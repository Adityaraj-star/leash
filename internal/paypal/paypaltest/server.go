// Package paypaltest is an in-memory fake of the PayPal REST endpoints Leash
// uses (OAuth, Orders v2 AUTHORIZE, Payments v2 capture/void/refund, Payouts,
// webhook verification).
//
// It exists so that settlement, the control plane and the whole demo can run
// and be tested without network access to the PayPal sandbox, and so a
// reviewer can run the repo with zero credentials. It is NOT a PayPal
// emulator: it models only the behaviors Leash depends on, and the real
// sandbox remains the source of truth (see docs/spikes.md and cmd/spike).
//
// The fake is driven through the real internal/paypal client over HTTP, so the
// client's request shapes are exercised too.
package paypaltest

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adityaraj-star/leash/internal/money"
)

// Default credentials accepted by the fake.
const (
	ClientID     = "fake-client-id"
	ClientSecret = "fake-client-secret"
)

type auth struct {
	ID         string
	OrderID    string
	Amount     money.Amount
	Captured   int64
	Voided     bool
	Expires    time.Time
	Created    time.Time
	CaptureIDs []string
}

type order struct {
	ID       string
	Intent   string
	Amount   money.Amount
	Approved bool
	AuthID   string
	Desc     string
	CustomID string
}

type capture struct {
	ID       string
	AuthID   string
	Amount   money.Amount
	Refunded int64
	Status   string // COMPLETED unless the server is told otherwise
}

// Payout records one paid-out item.
type Payout struct {
	BatchID  string
	Receiver string
	Amount   money.Amount
	Note     string
}

type cached struct {
	status int
	body   []byte
}

// Server is the fake. The zero value is not usable; call New.
type Server struct {
	mu sync.Mutex

	now func() time.Time
	seq int

	orders   map[string]*order
	auths    map[string]*auth
	captures map[string]*capture
	payouts  []Payout
	batches  map[string]bool // sender_batch_id seen
	replay   map[string]cached

	// Calls is a log of "METHOD path" for every authenticated API call.
	calls []string

	// FailNext makes the next N authenticated API calls return HTTP 503.
	FailNext int
	// HoldDays is how long an authorization stays valid (PayPal's honor period is 3 days).
	HoldDays int
	// WebhookOK is the result returned by webhook signature verification.
	WebhookOK bool
	// PendingCaptures makes new captures report PENDING until SetCaptureStatus changes them.
	PendingCaptures bool

	srv *httptest.Server
}

// New creates a fake.
func New() *Server {
	return &Server{
		now:       time.Now,
		orders:    map[string]*order{},
		auths:     map[string]*auth{},
		captures:  map[string]*capture{},
		batches:   map[string]bool{},
		replay:    map[string]cached{},
		HoldDays:  3,
		WebhookOK: true,
	}
}

// SetClock overrides time (tests).
func (s *Server) SetClock(now func() time.Time) { s.mu.Lock(); s.now = now; s.mu.Unlock() }

// Start serves the fake on a loopback port and returns its base URL.
func (s *Server) Start() string {
	s.srv = httptest.NewServer(s.Handler())
	return s.srv.URL
}

// Close stops a server started with Start.
func (s *Server) Close() {
	if s.srv != nil {
		s.srv.Close()
	}
}

// Handler returns the HTTP handler (mount it anywhere).
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serve) }

// ApproveOrder simulates the buyer tapping approve in PayPal's UI.
func (s *Server) ApproveOrder(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[id]
	if !ok {
		return fmt.Errorf("no such order %q", id)
	}
	o.Approved = true
	return nil
}

// Stats is a read-only money summary, used by the demo to "show the money".
type Stats struct {
	HeldMinor     int64            `json:"held_minor"`     // authorized, not yet captured or voided
	CapturedMinor int64            `json:"captured_minor"` // captured from the buyer
	RefundedMinor int64            `json:"refunded_minor"`
	PaidOut       map[string]int64 `json:"paid_out_minor"` // receiver email -> minor units
	Payouts       []Payout         `json:"payouts"`
	Calls         int              `json:"calls"`
}

// Stats returns a snapshot.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{PaidOut: map[string]int64{}, Calls: len(s.calls)}
	for _, a := range s.auths {
		if !a.Voided {
			st.HeldMinor += a.Amount.Minor - a.Captured
		}
		st.CapturedMinor += a.Captured
	}
	for _, c := range s.captures {
		st.RefundedMinor += c.Refunded
	}
	for _, p := range s.payouts {
		st.PaidOut[p.Receiver] += p.Amount.Minor
	}
	st.Payouts = append(st.Payouts, s.payouts...)
	return st
}

// Calls returns the log of API calls so far.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// Reset clears all state (used by the public demo's reset endpoint).
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orders = map[string]*order{}
	s.auths = map[string]*auth{}
	s.captures = map[string]*capture{}
	s.payouts = nil
	s.batches = map[string]bool{}
	s.replay = map[string]cached{}
	s.calls = nil
	s.seq = 0
}

func (s *Server) nextID(prefix string) string {
	s.seq++
	return fmt.Sprintf("%s-%05d", prefix, s.seq)
}

func writeJSON(w http.ResponseWriter, status int, v any) []byte {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status != http.StatusNoContent {
		w.Write(b)
	}
	return b
}

func apiErr(w http.ResponseWriter, status int, name, msg string) {
	writeJSON(w, status, map[string]any{"name": name, "message": msg, "debug_id": "fake-debug"})
}

func moneyJSON(a money.Amount) map[string]string {
	return map[string]string{"currency_code": a.Currency, "value": a.String()}
}

func parseMoney(v any) (money.Amount, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return money.Amount{}, false
	}
	val, _ := m["value"].(string)
	cur, _ := m["currency_code"].(string)
	if cur == "" {
		cur, _ = m["currency"].(string)
	}
	a, err := money.Parse(val, cur)
	return a, err == nil
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	// OAuth is unauthenticated apart from Basic credentials.
	if r.Method == http.MethodPost && r.URL.Path == "/v1/oauth2/token" {
		id, sec, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(id), []byte(ClientID)) != 1 ||
			subtle.ConstantTimeCompare([]byte(sec), []byte(ClientSecret)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": "Client Authentication failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "fake-token", "token_type": "Bearer", "expires_in": 32400})
		return
	}
	if r.Header.Get("Authorization") != "Bearer fake-token" {
		apiErr(w, http.StatusUnauthorized, "AUTHENTICATION_FAILURE", "Authentication failed due to invalid authentication credentials.")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, r.Method+" "+r.URL.Path)
	if s.FailNext > 0 {
		s.FailNext--
		apiErr(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "injected failure")
		return
	}

	// Idempotency: same PayPal-Request-Id on the same endpoint replays the response.
	rid := r.Header.Get("PayPal-Request-Id")
	key := ""
	if r.Method == http.MethodPost && rid != "" {
		key = r.URL.Path + "|" + rid
		if c, ok := s.replay[key]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(c.status)
			w.Write(c.body)
			return
		}
	}
	rec := &recorder{ResponseWriter: w}
	s.route(rec, r)
	if key != "" && rec.status >= 200 && rec.status < 300 {
		s.replay[key] = cached{status: rec.status, body: rec.body}
	}
}

type recorder struct {
	http.ResponseWriter
	status int
	body   []byte
}

func (r *recorder) WriteHeader(c int) { r.status = c; r.ResponseWriter.WriteHeader(c) }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.body = append(r.body, b...)
	return r.ResponseWriter.Write(b)
}

func decode(r *http.Request) map[string]any {
	var m map[string]any
	json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(&m)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == "/v2/checkout/orders":
		s.createOrder(w, r)
	case strings.HasPrefix(p, "/v2/checkout/orders/"):
		rest := strings.TrimPrefix(p, "/v2/checkout/orders/")
		id, action, _ := strings.Cut(rest, "/")
		switch {
		case r.Method == http.MethodGet && action == "":
			s.getOrder(w, id)
		case r.Method == http.MethodPost && action == "authorize":
			s.authorizeOrder(w, id)
		default:
			apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "unknown order endpoint")
		}
	case strings.HasPrefix(p, "/v2/payments/authorizations/"):
		rest := strings.TrimPrefix(p, "/v2/payments/authorizations/")
		id, action, _ := strings.Cut(rest, "/")
		switch {
		case r.Method == http.MethodGet && action == "":
			s.getAuth(w, id)
		case r.Method == http.MethodPost && action == "capture":
			s.capture(w, r, id)
		case r.Method == http.MethodPost && action == "void":
			s.void(w, id)
		default:
			apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "unknown authorization endpoint")
		}
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/v2/payments/captures/") && !strings.Contains(strings.TrimPrefix(p, "/v2/payments/captures/"), "/"):
		s.getCapture(w, strings.TrimPrefix(p, "/v2/payments/captures/"))
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/v2/payments/captures/") && strings.HasSuffix(p, "/refund"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/v2/payments/captures/"), "/refund")
		s.refund(w, r, id)
	case r.Method == http.MethodPost && p == "/v1/payments/payouts":
		s.createPayout(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/v1/payments/payouts/"):
		s.getPayout(w, strings.TrimPrefix(p, "/v1/payments/payouts/"))
	case r.Method == http.MethodPost && p == "/v1/notifications/verify-webhook-signature":
		st := "FAILURE"
		if s.WebhookOK {
			st = "SUCCESS"
		}
		writeJSON(w, http.StatusOK, map[string]string{"verification_status": st})
	default:
		apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "unknown endpoint "+p)
	}
}

func (s *Server) orderJSON(o *order) map[string]any {
	out := map[string]any{"id": o.ID, "intent": o.Intent}
	switch {
	case o.AuthID != "":
		out["status"] = "COMPLETED"
	case o.Approved:
		out["status"] = "APPROVED"
	default:
		out["status"] = "PAYER_ACTION_REQUIRED"
		out["links"] = []map[string]string{{"rel": "payer-action", "method": "GET", "href": "https://www.sandbox.paypal.com/checkoutnow?token=" + o.ID}}
	}
	pu := map[string]any{"reference_id": "default", "amount": moneyJSON(o.Amount)}
	if o.AuthID != "" {
		pu["payments"] = map[string]any{"authorizations": []any{s.authJSON(s.auths[o.AuthID])}}
	}
	out["purchase_units"] = []any{pu}
	return out
}

func (s *Server) authJSON(a *auth) map[string]any {
	status := "CREATED"
	switch {
	case a.Voided:
		status = "VOIDED"
	case a.Captured >= a.Amount.Minor:
		status = "CAPTURED"
	case a.Captured > 0:
		status = "PARTIALLY_CAPTURED"
	}
	return map[string]any{
		"id": a.ID, "status": status, "amount": moneyJSON(a.Amount),
		"create_time":     a.Created.UTC().Format(time.RFC3339),
		"expiration_time": a.Expires.UTC().Format(time.RFC3339),
	}
}

func (s *Server) createOrder(w http.ResponseWriter, r *http.Request) {
	body := decode(r)
	intent, _ := body["intent"].(string)
	if intent != "AUTHORIZE" && intent != "CAPTURE" {
		apiErr(w, http.StatusUnprocessableEntity, "INVALID_REQUEST", "intent must be AUTHORIZE or CAPTURE")
		return
	}
	pus, _ := body["purchase_units"].([]any)
	if len(pus) != 1 {
		apiErr(w, http.StatusUnprocessableEntity, "INVALID_REQUEST", "exactly one purchase unit is supported")
		return
	}
	pu, _ := pus[0].(map[string]any)
	amt, ok := parseMoney(pu["amount"])
	if !ok || amt.Minor <= 0 {
		apiErr(w, http.StatusUnprocessableEntity, "INVALID_REQUEST", "bad amount")
		return
	}
	o := &order{ID: s.nextID("ORDER"), Intent: intent, Amount: amt}
	o.Desc, _ = pu["description"].(string)
	o.CustomID, _ = pu["custom_id"].(string)
	// Only a vaulted PayPal method (vault_id) means no redirect is needed. A
	// payment_source that carries just experience_context (return and cancel URLs,
	// shipping preference) still needs the buyer to approve, exactly as in PayPal.
	if ps, ok := body["payment_source"].(map[string]any); ok {
		if pp, ok := ps["paypal"].(map[string]any); ok {
			if v, _ := pp["vault_id"].(string); v != "" {
				o.Approved = true
			}
		}
	}
	s.orders[o.ID] = o
	writeJSON(w, http.StatusCreated, s.orderJSON(o))
}

func (s *Server) getOrder(w http.ResponseWriter, id string) {
	o, ok := s.orders[id]
	if !ok {
		apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "order not found")
		return
	}
	writeJSON(w, http.StatusOK, s.orderJSON(o))
}

func (s *Server) authorizeOrder(w http.ResponseWriter, id string) {
	o, ok := s.orders[id]
	if !ok {
		apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "order not found")
		return
	}
	if o.Intent != "AUTHORIZE" {
		apiErr(w, http.StatusUnprocessableEntity, "ORDER_NOT_AUTHORIZABLE", "order intent is not AUTHORIZE")
		return
	}
	if !o.Approved {
		apiErr(w, http.StatusUnprocessableEntity, "ORDER_NOT_APPROVED", "Payer has not approved the order")
		return
	}
	if o.AuthID != "" {
		apiErr(w, http.StatusUnprocessableEntity, "ORDER_ALREADY_AUTHORIZED", "order already authorized")
		return
	}
	now := s.now()
	a := &auth{ID: s.nextID("AUTH"), OrderID: o.ID, Amount: o.Amount, Created: now, Expires: now.Add(time.Duration(s.HoldDays) * 24 * time.Hour)}
	s.auths[a.ID] = a
	o.AuthID = a.ID
	writeJSON(w, http.StatusCreated, s.orderJSON(o))
}

func (s *Server) getAuth(w http.ResponseWriter, id string) {
	a, ok := s.auths[id]
	if !ok {
		apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "authorization not found")
		return
	}
	writeJSON(w, http.StatusOK, s.authJSON(a))
}

func (s *Server) capture(w http.ResponseWriter, r *http.Request, id string) {
	a, ok := s.auths[id]
	if !ok {
		apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "authorization not found")
		return
	}
	body := decode(r)
	if a.Voided {
		apiErr(w, http.StatusUnprocessableEntity, "AUTHORIZATION_VOIDED", "Authorization has been voided")
		return
	}
	if !s.now().Before(a.Expires) {
		apiErr(w, http.StatusUnprocessableEntity, "AUTHORIZATION_EXPIRED", "Authorization has expired")
		return
	}
	remaining := a.Amount.Minor - a.Captured
	amt := money.Amount{Minor: remaining, Currency: a.Amount.Currency}
	if v, present := body["amount"]; present {
		parsed, ok := parseMoney(v)
		if !ok || parsed.Currency != a.Amount.Currency {
			apiErr(w, http.StatusUnprocessableEntity, "INVALID_REQUEST", "bad capture amount")
			return
		}
		amt = parsed
	}
	if amt.Minor <= 0 || amt.Minor > remaining {
		apiErr(w, http.StatusUnprocessableEntity, "CAPTURE_AMOUNT_EXCEEDS_AUTHORIZATION", "capture exceeds the remaining authorization")
		return
	}
	a.Captured += amt.Minor
	final, _ := body["final_capture"].(bool)
	if final && a.Captured < a.Amount.Minor {
		// Final capture releases the remainder of the hold.
		a.Amount.Minor = a.Captured
	}
	c := &capture{ID: s.nextID("CAP"), AuthID: a.ID, Amount: amt, Status: "COMPLETED"}
	if s.PendingCaptures {
		c.Status = "PENDING"
	}
	s.captures[c.ID] = c
	a.CaptureIDs = append(a.CaptureIDs, c.ID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": c.ID, "status": c.Status, "amount": moneyJSON(amt), "final_capture": final || a.Captured >= a.Amount.Minor,
		"create_time": s.now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) getCapture(w http.ResponseWriter, id string) {
	c, ok := s.captures[id]
	if !ok {
		apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "capture not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": c.ID, "status": c.Status, "amount": moneyJSON(c.Amount), "final_capture": true,
	})
}

// SetCaptureStatus changes what PayPal reports for a capture (tests): for example
// PENDING -> COMPLETED, or DECLINED.
func (s *Server) SetCaptureStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.captures[id]
	if !ok {
		return fmt.Errorf("no such capture %q", id)
	}
	c.Status = status
	return nil
}

func (s *Server) void(w http.ResponseWriter, id string) {
	a, ok := s.auths[id]
	if !ok {
		apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "authorization not found")
		return
	}
	if a.Captured > 0 {
		apiErr(w, http.StatusUnprocessableEntity, "PREVIOUSLY_CAPTURED", "Authorization has already been captured")
		return
	}
	a.Voided = true
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) refund(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := s.captures[id]
	if !ok {
		apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "capture not found")
		return
	}
	body := decode(r)
	amt := money.Amount{Minor: c.Amount.Minor - c.Refunded, Currency: c.Amount.Currency}
	if v, present := body["amount"]; present {
		parsed, ok := parseMoney(v)
		if !ok || parsed.Currency != c.Amount.Currency {
			apiErr(w, http.StatusUnprocessableEntity, "INVALID_REQUEST", "bad refund amount")
			return
		}
		amt = parsed
	}
	if amt.Minor <= 0 || amt.Minor > c.Amount.Minor-c.Refunded {
		apiErr(w, http.StatusUnprocessableEntity, "REFUND_AMOUNT_EXCEEDED", "refund exceeds the captured amount")
		return
	}
	c.Refunded += amt.Minor
	writeJSON(w, http.StatusCreated, map[string]any{"id": s.nextID("REF"), "status": "COMPLETED", "amount": moneyJSON(amt)})
}

func (s *Server) createPayout(w http.ResponseWriter, r *http.Request) {
	body := decode(r)
	hdr, _ := body["sender_batch_header"].(map[string]any)
	sbid, _ := hdr["sender_batch_id"].(string)
	if sbid == "" {
		apiErr(w, http.StatusUnprocessableEntity, "INVALID_REQUEST", "sender_batch_id is required")
		return
	}
	if s.batches[sbid] {
		apiErr(w, http.StatusUnprocessableEntity, "USER_BUSINESS_ERROR", "Batch with given sender_batch_id already exists")
		return
	}
	items, _ := body["items"].([]any)
	if len(items) == 0 {
		apiErr(w, http.StatusUnprocessableEntity, "INVALID_REQUEST", "at least one item is required")
		return
	}
	batchID := s.nextID("BATCH")
	var outItems []any
	var recs []Payout
	for i, it := range items {
		m, _ := it.(map[string]any)
		amt, ok := parseMoney(m["amount"])
		recv, _ := m["receiver"].(string)
		if !ok || amt.Minor <= 0 || recv == "" {
			apiErr(w, http.StatusUnprocessableEntity, "INVALID_REQUEST", "bad payout item")
			return
		}
		note, _ := m["note"].(string)
		recs = append(recs, Payout{BatchID: batchID, Receiver: recv, Amount: amt, Note: note})
		outItems = append(outItems, map[string]any{
			"payout_item_id": fmt.Sprintf("%s-ITEM-%d", batchID, i+1), "transaction_id": fmt.Sprintf("TXN-%s-%d", batchID, i+1),
			"transaction_status": "SUCCESS",
			"payout_item":        map[string]any{"receiver": recv, "amount": map[string]string{"value": amt.String(), "currency": amt.Currency}},
		})
	}
	s.batches[sbid] = true
	s.payouts = append(s.payouts, recs...)
	writeJSON(w, http.StatusCreated, map[string]any{
		"batch_header": map[string]string{"payout_batch_id": batchID, "batch_status": "SUCCESS"}, "items": outItems,
	})
}

func (s *Server) getPayout(w http.ResponseWriter, id string) {
	var items []any
	found := false
	for _, p := range s.payouts {
		if p.BatchID == id {
			found = true
			items = append(items, map[string]any{
				"transaction_status": "SUCCESS",
				"payout_item":        map[string]any{"receiver": p.Receiver, "amount": map[string]string{"value": p.Amount.String(), "currency": p.Amount.Currency}},
			})
		}
	}
	if !found {
		apiErr(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "batch not found")
		return
	}
	sort.SliceStable(items, func(i, j int) bool { return false })
	writeJSON(w, http.StatusOK, map[string]any{"batch_header": map[string]string{"payout_batch_id": id, "batch_status": "SUCCESS"}, "items": items})
}
