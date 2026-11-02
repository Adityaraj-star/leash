// Package api is the operator-facing HTTP API: what the dashboard (and curl)
// use to watch the control plane and to make the human decisions Leash keeps
// for people (enroll a key, register or revoke a mandate, approve a step-up).
//
// It is deliberately NOT the agent's interface. The agent talks to Leash over
// MCP; nothing here can be reached with an agent's credentials. Every /api
// route needs the operator token.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Adityaraj-star/leash/internal/control"
	"github.com/Adityaraj-star/leash/internal/ledger"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

const maxBody = 1 << 20

// Server serves the operator API.
type Server struct {
	Plane *control.Plane
	// Token is the operator bearer token. It must not be empty.
	Token string
	// Static, if set, serves the dashboard at "/".
	Static http.Handler
	// Extra mounts other handlers (for example the agent's MCP endpoint) that
	// do their own authentication. They are not covered by the operator token.
	Extra map[string]http.Handler
	Logf  func(format string, args ...any)
	// Heartbeat is the SSE keep-alive interval (default 15s).
	Heartbeat time.Duration
	// EnrollSecret is what the API presents to the plane when the browser enrolls
	// its key. It defaults to Token, which the plane's Config.EnrollSecret should
	// match in a strict deployment.
	EnrollSecret string
	// Now is the clock (tests); default time.Now.
	Now func() time.Time

	chainMu sync.Mutex
	chain   chainState

	// failures counts wrong merchant secrets (see merchantDelivery).
	failMu   sync.Mutex
	failures map[string][]time.Time
}

// Wrong merchant secrets are limited so the delivery endpoint cannot be used to
// guess one. The limit is per claimed merchant id (plus one bucket for ids that do
// not exist), so a flood of guesses delays that merchant's confirmations rather
// than letting anyone try more secrets.
const (
	maxDeliveryFailures = 10
	deliveryFailWindow  = time.Minute
)

func (s *Server) deliveryBlocked(key string) bool {
	now := s.now()
	s.failMu.Lock()
	defer s.failMu.Unlock()
	recent := s.failures[key][:0]
	for _, t := range s.failures[key] {
		if now.Sub(t) < deliveryFailWindow {
			recent = append(recent, t)
		}
	}
	if s.failures == nil {
		s.failures = map[string][]time.Time{}
	}
	s.failures[key] = recent
	return len(recent) >= maxDeliveryFailures
}

func (s *Server) deliveryFailed(key string) {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	if s.failures == nil {
		s.failures = map[string][]time.Time{}
	}
	s.failures[key] = append(s.failures[key], s.now())
}

// chainState is the last full verification of the ledger. Verifying re-reads
// and re-checks every entry, so /api/state serves this cached result instead of
// repeating the work on every ledger event; RunVerifier refreshes it on a timer
// and the verify endpoint forces a fresh one.
type chainState struct {
	res ledger.Result
	at  time.Time
	ok  bool
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// VerifyChain verifies the whole ledger now and caches the result.
func (s *Server) VerifyChain() (ledger.Result, time.Time) {
	res := s.Plane.Ledger().Verify(nil)
	at := s.now()
	s.chainMu.Lock()
	s.chain = chainState{res: res, at: at, ok: true}
	s.chainMu.Unlock()
	return res, at
}

func (s *Server) cachedChain() (ledger.Result, time.Time) {
	s.chainMu.Lock()
	c := s.chain
	s.chainMu.Unlock()
	if c.ok {
		return c.res, c.at
	}
	return s.VerifyChain()
}

// RunVerifier re-verifies the ledger every interval until ctx ends and logs
// loudly if the chain ever stops verifying.
func (s *Server) RunVerifier(ctx context.Context, every time.Duration, logf func(string, ...any)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if res, _ := s.VerifyChain(); !res.OK {
				logf("LEDGER DOES NOT VERIFY at entry %d: %s", res.BrokenAt, res.Reason)
			}
		}
	}
}

// Handler returns the routes. It panics if Token is empty: an operator API with
// no authentication must never start.
func (s *Server) Handler() http.Handler {
	if s.Token == "" {
		panic("api: an operator token is required")
	}
	if s.Logf == nil {
		s.Logf = func(string, ...any) {}
	}
	if s.Heartbeat <= 0 {
		s.Heartbeat = 15 * time.Second
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	api := http.NewServeMux()
	api.HandleFunc("GET /api/state", s.state)
	api.HandleFunc("POST /api/enroll", s.enroll)
	api.HandleFunc("POST /api/mandates", s.registerMandate)
	api.HandleFunc("POST /api/mandates/{id}/revoke", s.revoke)
	api.HandleFunc("GET /api/requests", s.requests)
	api.HandleFunc("GET /api/requests/{id}", s.request)
	api.HandleFunc("GET /api/requests/{id}/approval", s.approvalMessage)
	api.HandleFunc("POST /api/requests/{id}/approve", s.approve)
	api.HandleFunc("POST /api/requests/{id}/reject", s.reject)
	api.HandleFunc("GET /api/ledger", s.ledgerEntries)
	api.HandleFunc("GET /api/ledger/verify", s.verify)
	api.HandleFunc("GET /api/evidence/{id}", s.evidence)
	api.HandleFunc("GET /api/events", s.events)
	mux.Handle("/api/", s.auth(api))
	// The merchant's own door: authenticated by the merchant's delivery secret, not
	// by the operator token, and it can do exactly one thing.
	mux.HandleFunc("POST /merchant/delivery", s.merchantDelivery)
	for path, h := range s.Extra {
		if strings.HasPrefix(path, "/api/") {
			panic("api: extra handlers must not live under /api/")
		}
		mux.Handle(path, h)
	}

	if s.Static != nil {
		mux.Handle("/", s.Static)
	}
	return secure(mux)
}

// secure sets headers that make a browser treat the dashboard conservatively.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == r.Header.Get("Authorization") || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="leash"`)
			writeErr(w, http.StatusUnauthorized, "missing or wrong operator token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ------------------------------------------------------------------ helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// fail maps domain errors to HTTP statuses. Messages from the domain are
// written for people, so they are passed through.
func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, settlement.ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, settlement.ErrBadState), errors.Is(err, control.ErrMandateConflict),
		errors.Is(err, control.ErrKeyMismatch), errors.Is(err, settlement.ErrAlreadyPaidOut):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, control.ErrNoKey):
		writeErr(w, http.StatusPreconditionFailed, err.Error())
	case errors.Is(err, control.ErrUnauthorized):
		writeErr(w, http.StatusForbidden, "not authorized")
	default:
		var se *settlement.StateError
		if errors.As(err, &se) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		s.Logf("api: %v", err)
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func b64(w http.ResponseWriter, field, s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		writeErr(w, http.StatusBadRequest, field+" must be standard base64")
		return nil, false
	}
	return b, true
}

// ------------------------------------------------------------------ views

// MandateDTO is a mandate as the dashboard shows it.
type MandateDTO struct {
	ID               string   `json:"id"`
	Intent           string   `json:"intent"`
	MaxTotal         string   `json:"max_total"`
	PerTxCap         string   `json:"per_tx_cap"`
	StepUpOver       string   `json:"step_up_over,omitempty"`
	Currency         string   `json:"currency"`
	AllowedMerchants []string `json:"allowed_merchants"`
	Categories       []string `json:"categories"`
	SingleUse        bool     `json:"single_use"`
	DeliverBy        string   `json:"deliver_by,omitempty"`
	ExpiresAt        string   `json:"expires_at"`
	Revoked          bool     `json:"revoked"`
	SpentMinor       int64    `json:"spent_minor"`
	SpentDisplay     string   `json:"spent"`
}

func mandateDTOs(p *control.Plane) []MandateDTO {
	views := p.Mandates()
	out := make([]MandateDTO, 0, len(views))
	for _, v := range views {
		m := v.Mandate
		spent := m.MaxTotal
		spent.Minor = v.Usage.SpentMinor
		d := MandateDTO{
			ID: m.ID, Intent: m.Intent, MaxTotal: m.MaxTotal.String(), PerTxCap: m.PerTxCap.String(),
			Currency: m.MaxTotal.Currency, AllowedMerchants: nonNil(m.AllowedMerchants), Categories: nonNil(m.Categories),
			SingleUse: v.Mandate.SingleUse, ExpiresAt: m.ExpiresAt.UTC().Format(time.RFC3339),
			Revoked: v.Revoked, SpentMinor: v.Usage.SpentMinor, SpentDisplay: spent.String(),
		}
		if m.StepUpOver.Minor > 0 {
			d.StepUpOver = m.StepUpOver.String()
		}
		if !m.DeliverBy.IsZero() {
			d.DeliverBy = m.DeliverBy.UTC().Format(time.RFC3339)
		}
		out = append(out, d)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ------------------------------------------------------------------ handlers

func (s *Server) state(w http.ResponseWriter, _ *http.Request) {
	reqs := s.Plane.Requests()
	counts := map[string]int{}
	for _, r := range reqs {
		counts[string(r.State)]++
	}
	pending := 0
	for _, r := range reqs {
		if r.State == settlement.StepUpPending {
			pending++
		}
	}
	vr, checkedAt := s.cachedChain()
	tainted := ""
	if t := s.Plane.TaintedUntil(); !t.IsZero() {
		tainted = t.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"strict":           s.Plane.Strict(),
		"tainted_until":    tainted,
		"chain_checked_at": checkedAt.UTC().Format(time.RFC3339),
		"key_id":           s.Plane.KeyID(),
		"mandates":         mandateDTOs(s.Plane),
		"counts":           counts,
		"step_ups":         pending,
		"requests":         len(reqs),
		"chain":            vr,
		"server_time":      time.Now().UTC().Format(time.RFC3339),
		"ledger_pub":       base64.StdEncoding.EncodeToString(s.Plane.Ledger().PublicKey()),
		"ledger_title":     "hash-chained, signed",
	})
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PublicKey string `json:"public_key"` // base64 of the 65-byte uncompressed P-256 point
	}
	if !decode(w, r, &in) {
		return
	}
	pub, ok := b64(w, "public_key", in.PublicKey)
	if !ok {
		return
	}
	secret := s.EnrollSecret
	if secret == "" {
		secret = s.Token
	}
	id, err := s.Plane.EnrollWithSecret(pub, secret)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key_id": id})
}

func (s *Server) registerMandate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mandate   string `json:"mandate"`   // the exact signed text
		Signature string `json:"signature"` // base64 raw r||s (64 bytes)
	}
	if !decode(w, r, &in) {
		return
	}
	sig, ok := b64(w, "signature", in.Signature)
	if !ok {
		return
	}
	m, err := s.Plane.RegisterMandate([]byte(in.Mandate), sig)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"mandate_id": m.ID})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	voided, err := s.Plane.Revoke(r.Context(), r.PathValue("id"), "operator")
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": r.PathValue("id"), "holds_released": nonNil(voided)})
}

func (s *Server) requests(w http.ResponseWriter, _ *http.Request) {
	reqs := s.Plane.Requests()
	// newest first
	for i, j := 0, len(reqs)-1; i < j; i, j = i+1, j-1 {
		reqs[i], reqs[j] = reqs[j], reqs[i]
	}
	writeJSON(w, http.StatusOK, reqs)
}

func (s *Server) request(w http.ResponseWriter, r *http.Request) {
	req, err := s.Plane.Request(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

// approve approves a step-up request. A strict server needs the user's own
// signature over the approval message (see approvalMessage); an unsigned approval
// is only accepted when the plane is not strict (the offline demo).
func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Signature string `json:"signature"` // base64 raw r||s over the approval message
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read the body")
		return
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
	}
	id := r.PathValue("id")
	var out control.Outcome
	if in.Signature != "" {
		sig, ok := b64(w, "signature", in.Signature)
		if !ok {
			return
		}
		out, err = s.Plane.ApproveStepUpSigned(r.Context(), id, sig)
	} else {
		out, err = s.Plane.ApproveStepUp(r.Context(), id, "operator")
		if errors.Is(err, control.ErrUnauthorized) && s.Plane.Strict() {
			writeErr(w, http.StatusForbidden, "this server needs the approval signed with your key")
			return
		}
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// merchantDelivery is how a merchant tells Leash a purchase was (or was not)
// delivered. Authentication is the merchant's delivery secret as a bearer token.
//
//	POST /merchant/delivery
//	Authorization: Bearer <delivery_secret>
//	{"merchant_id":"legitgifts","request_id":"req_...","delivered":true,"reference":"TRK-1","note":"..."}
//
// A positive confirmation captures the held funds and pays the merchant; a
// negative one releases the hold. Every authentication failure gets the same
// answer, so the endpoint does not reveal which part was wrong.
func (s *Server) merchantDelivery(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MerchantID string `json:"merchant_id"`
		RequestID  string `json:"request_id"`
		Delivered  *bool  `json:"delivered"`
		Reference  string `json:"reference"`
		Note       string `json:"note"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.MerchantID == "" || in.RequestID == "" || in.Delivered == nil {
		writeErr(w, http.StatusBadRequest, "merchant_id, request_id and delivered are required")
		return
	}
	key := in.MerchantID
	if len(key) > 64 {
		key = key[:64]
	}
	if s.deliveryBlocked(key) {
		w.Header().Set("Retry-After", strconv.Itoa(int(deliveryFailWindow.Seconds())))
		writeErr(w, http.StatusTooManyRequests, "too many wrong secrets; try again in a minute")
		return
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	out, err := s.Plane.AttestDelivery(r.Context(), in.MerchantID, secret, in.RequestID, settlement.Delivery{
		Delivered: *in.Delivered, Reference: in.Reference, Note: in.Note,
	})
	switch {
	case errors.Is(err, control.ErrUnauthorized):
		s.deliveryFailed(key)
		writeErr(w, http.StatusForbidden, "not authorized")
	case err != nil && out.RequestID != "":
		// The delivery was recorded but a later step failed (for example the payout).
		// The funds are safe and the maintenance pass retries; tell the merchant.
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "outcome": out})
	case err != nil:
		s.fail(w, err)
	default:
		writeJSON(w, http.StatusOK, out)
	}
}

// approvalMessage returns the exact text the user's key signs to approve a
// request. The dashboard shows the amount and merchant from it, then signs it.
func (s *Server) approvalMessage(w http.ResponseWriter, r *http.Request) {
	req, err := s.Plane.Request(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": string(control.ApprovalMessage(req.ID, req.MerchantID, req.Amount)),
	})
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	out, err := s.Plane.RejectStepUp(r.PathValue("id"), "operator")
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ledgerEntries returns entries with seq > after (default 0), at most limit.
func (s *Server) ledgerEntries(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	all, err := s.Plane.Ledger().Entries()
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]ledger.Entry, 0, 64)
	for _, e := range all {
		if e.Seq > after {
			out = append(out, e)
			if len(out) >= limit {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) verify(w http.ResponseWriter, _ *http.Request) {
	res, at := s.VerifyChain() // always fresh, and it refreshes the cached result too
	writeJSON(w, http.StatusOK, map[string]any{
		"result": res, "checkpoint": s.Plane.Ledger().Checkpoint(), "checked_at": at.UTC().Format(time.RFC3339),
	})
}

func (s *Server) evidence(w http.ResponseWriter, r *http.Request) {
	ev, ok := s.Plane.Evidence(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such evidence")
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// events streams new ledger entries as server-sent events. The client loads
// history from /api/ledger and de-duplicates by seq, so a reconnect is safe.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming is not supported")
		return
	}
	ch, cancel := s.Plane.Subscribe()
	defer cancel()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	tick := time.NewTicker(s.Heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, open := <-ch:
			if !open {
				return
			}
			b, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "id: %d\nevent: ledger\ndata: %s\n\n", e.Seq, b)
			fl.Flush()
		case <-tick.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			fl.Flush()
		}
	}
}

// RunSweeper runs the maintenance pass (expiry and retries) now and then every
// interval until ctx ends.
func RunSweeper(ctx context.Context, p *control.Plane, every time.Duration, logf func(string, ...any)) {
	sweep := func() {
		if ids, err := p.Sweep(ctx); err != nil {
			logf("sweep: %v", err)
		} else if len(ids) > 0 {
			logf("sweep: moved %v", ids)
		}
	}
	sweep() // pick up anything left half-done by a crash, right away
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
