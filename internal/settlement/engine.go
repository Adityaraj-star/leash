package settlement

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adityaraj-star/leash/internal/ledger"
	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/policy"
)

// Gateway is the slice of the PayPal client settlement needs. *paypal.Client
// satisfies it; tests and the offline demo use it over internal/paypal/paypaltest.
type Gateway interface {
	CreateOrder(ctx context.Context, p paypal.CreateOrderParams) (*paypal.Order, error)
	GetOrder(ctx context.Context, orderID string) (*paypal.Order, error)
	AuthorizeOrder(ctx context.Context, orderID, requestID string) (*paypal.Order, error)
	Capture(ctx context.Context, authID string, p paypal.CaptureParams) (*paypal.Capture, error)
	GetCapture(ctx context.Context, captureID string) (*paypal.Capture, error)
	Void(ctx context.Context, authID, requestID string) error
	RefundCapture(ctx context.Context, captureID string, p paypal.RefundParams) (*paypal.Refund, error)
	CreatePayout(ctx context.Context, p paypal.PayoutParams) (*paypal.PayoutBatch, error)
	GetPayout(ctx context.Context, batchID string) (*paypal.PayoutBatch, error)
}

var _ Gateway = (*paypal.Client)(nil)

// Recorder is the evidence log. *ledger.Ledger satisfies it.
type Recorder interface {
	Append(typ string, payload any) (ledger.Entry, error)
}

var (
	ErrNotFound              = errors.New("settlement: request not found")
	ErrBadState              = errors.New("settlement: operation not allowed in the current state")
	ErrDuplicateKey          = errors.New("settlement: idempotency key already used for this mandate")
	ErrBuyerApprovalRequired = errors.New("settlement: the buyer must approve the payment in PayPal first")
	ErrAlreadyPaidOut        = errors.New("settlement: funds were already paid out to the merchant; open a dispute instead")
)

// ErrOutcomeUnknown marks a PayPal call that may or may not have happened (a
// timeout, a dropped connection, a 5xx). The request keeps its state; calling
// the operation again, or Reconcile, is safe because every call reuses its
// PayPal-Request-Id and reads PayPal's own state first.
var ErrOutcomeUnknown = errors.New("settlement: PayPal outcome unknown, will be reconciled")

// ErrGuardRejected means the Guard refused to place a new hold (for example the
// mandate was revoked or expired while the request waited). The request was
// voided and nothing was held.
var ErrGuardRejected = errors.New("settlement: the request is no longer allowed to proceed")

// OutcomeUnknownError wraps the underlying error for an unknown outcome.
type OutcomeUnknownError struct {
	Op  string
	Err error
}

func (e *OutcomeUnknownError) Error() string {
	return fmt.Sprintf("settlement: %s: outcome unknown (%v)", e.Op, e.Err)
}
func (e *OutcomeUnknownError) Unwrap() []error { return []error{ErrOutcomeUnknown, e.Err} }

// definitive reports whether err PROVES PayPal did not perform the operation:
// PayPal answered with a client error. Network errors, timeouts, cancelled
// contexts and 5xx prove nothing. 408, 409 and 429 are treated as unknown too.
func definitive(err error) bool {
	var ae *paypal.APIError
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.Status {
	case http.StatusRequestTimeout, http.StatusConflict, http.StatusTooManyRequests:
		return false
	}
	return ae.Status >= 400 && ae.Status < 500
}

// StateError says an operation was attempted in a state that does not allow it.
type StateError struct {
	ID    string
	Op    string
	State State
}

func (e *StateError) Error() string {
	return fmt.Sprintf("settlement: cannot %s request %s in state %s", e.Op, e.ID, e.State)
}
func (e *StateError) Unwrap() error { return ErrBadState }

// Config configures an Engine.
type Config struct {
	Gateway  Gateway
	Recorder Recorder
	Store    Store // default MemStore
	Now      func() time.Time
	Logf     func(format string, args ...any)

	// PaymentSource is the buyer's vaulted payment method, passed to PayPal when
	// creating the order (what spike S2 must establish). Nil means the buyer must
	// approve in PayPal's UI (the documented fallback).
	PaymentSource map[string]any
	// StepUpTTL is how long a human has to approve a STEP_UP request.
	StepUpTTL time.Duration
	// HoldSafety voids an authorization this long before PayPal would expire it.
	HoldSafety time.Duration

	// ReturnURL and CancelURL are where PayPal sends the buyer after approving or
	// cancelling in the fallback flow (no vaulted payment method). The orders are
	// also created with no shipping step (Leash buys digital goods). Defaults are
	// placeholders; point them at Leash's own pages.
	ReturnURL, CancelURL string
	// ApprovalTTL is how long an APPROVED request may wait for its hold (for
	// example for the buyer to approve in PayPal) before Sweep expires it.
	ApprovalTTL time.Duration
	// InspectionPeriod keeps a delivered purchase on hold this long before it is
	// captured and paid out, so the buyer can still report a problem. Zero
	// captures immediately. Capture happens early if the hold is about to lapse.
	InspectionPeriod time.Duration
	// Guard, when set, is asked before a NEW hold is placed. Returning false voids
	// the request with the given reason (for example: the mandate was revoked or
	// has expired). It must be fast and must not call back into the Engine.
	Guard func(r *Request) (ok bool, reason string)
}

// Engine runs settlement. It is safe for concurrent use.
type Engine struct {
	cfg Config

	mu   sync.Mutex // guards reqs and every field of every *Request
	reqs map[string]*Request

	opMu sync.Mutex // guards ops
	ops  map[string]*sync.Mutex
}

// New builds an Engine and reloads persisted requests.
func New(cfg Config) (*Engine, error) {
	if cfg.Gateway == nil || cfg.Recorder == nil {
		return nil, errors.New("settlement: gateway and recorder are required")
	}
	if cfg.Store == nil {
		cfg.Store = MemStore{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.StepUpTTL <= 0 {
		cfg.StepUpTTL = 15 * time.Minute
	}
	if cfg.HoldSafety <= 0 {
		cfg.HoldSafety = 2 * time.Hour
	}
	if cfg.ApprovalTTL <= 0 {
		cfg.ApprovalTTL = 3 * time.Hour
	}
	if cfg.ReturnURL == "" {
		cfg.ReturnURL = "https://example.com/return"
	}
	if cfg.CancelURL == "" {
		cfg.CancelURL = "https://example.com/cancel"
	}
	e := &Engine{cfg: cfg, reqs: map[string]*Request{}, ops: map[string]*sync.Mutex{}}
	loaded, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	for _, r := range loaded {
		e.reqs[r.ID] = r
	}
	return e, nil
}

func (e *Engine) now() time.Time { return e.cfg.Now().UTC() }

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // no entropy: refuse to continue rather than issue guessable IDs
	}
	return "req_" + hex.EncodeToString(b[:])
}

// op serializes operations on one request (including their network calls).
func (e *Engine) op(id string) func() {
	e.opMu.Lock()
	m, ok := e.ops[id]
	if !ok {
		m = &sync.Mutex{}
		e.ops[id] = m
	}
	e.opMu.Unlock()
	m.Lock()
	return m.Unlock
}

func (e *Engine) lookup(id string) (*Request, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.reqs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

// snapshot returns a copy of r that is safe to hand to callers.
func (e *Engine) snapshot(r *Request) *Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	return r.clone()
}

func (e *Engine) state(r *Request) State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return r.State
}

func (e *Engine) mutate(r *Request, fn func()) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	fn()
	r.UpdatedAt = e.now()
	return e.cfg.Store.Save(r)
}

// record appends to the evidence ledger.
func (e *Engine) record(typ string, payload any) error {
	if _, err := e.cfg.Recorder.Append(typ, payload); err != nil {
		return fmt.Errorf("evidence ledger unavailable, refusing to proceed: %w", err)
	}
	return nil
}

// move performs a state transition and records it. When force is true the
// transition is applied even if the ledger is down (used only after money has
// already moved, where refusing to update state would be worse).
func (e *Engine) move(r *Request, to State, reason string, extra map[string]any, force bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	from := r.State
	if !CanTransition(from, to) {
		return &StateError{ID: r.ID, Op: "move to " + string(to), State: from}
	}
	payload := map[string]any{"request_id": r.ID, "mandate_id": r.MandateID, "from": from, "to": to, "reason": reason}
	for k, v := range extra {
		payload[k] = v
	}
	if err := e.record("settlement.transition", payload); err != nil {
		if !force {
			return err
		}
		e.cfg.Logf("settlement: %v (applying %s -> %s for %s anyway: money already moved)", err, from, to, r.ID)
	}
	now := e.now()
	r.State, r.Reason, r.UpdatedAt = to, reason, now
	r.History = append(r.History, Transition{From: from, To: to, At: now, Reason: reason})
	return e.cfg.Store.Save(r)
}

// unknown records that a PayPal call may have succeeded and returns the error
// the caller should surface. The request's state is left unchanged.
func (e *Engine) unknown(r *Request, op string, err error) error {
	_ = e.record("settlement.unknown", map[string]any{"request_id": r.ID, "op": op, "error": err.Error(),
		"note": "PayPal may have performed this call; state unchanged; it will be reconciled"})
	e.cfg.Logf("settlement: %s for %s: outcome unknown (%v); leaving the request for Reconcile", op, r.ID, err)
	return &OutcomeUnknownError{Op: op, Err: err}
}

// intent writes the write-ahead record before any call that moves money.
func (e *Engine) intent(r *Request, op string, details map[string]any) error {
	payload := map[string]any{"request_id": r.ID, "mandate_id": r.MandateID, "op": op, "paypal_request_id": payPalID(r, op)}
	for k, v := range details {
		payload[k] = v
	}
	return e.record("settlement.intent", payload)
}

// ---------------------------------------------------------------- opening

// OpenInput is what the control plane knows when a payment is requested.
type OpenInput struct {
	MandateID        string
	MerchantID       string
	MerchantEmail    string
	Amount           money.Amount
	Items            []string
	IdempotencyKey   string
	PromisedDelivery time.Time
	DeliverBy        time.Time
}

// Open creates a request in REQUESTED. A second request with the same
// idempotency key for the same mandate returns ErrDuplicateKey together with
// the original request, so the caller can answer with the earlier decision.
func (e *Engine) Open(in OpenInput) (*Request, error) {
	if in.MandateID == "" || in.IdempotencyKey == "" || in.Amount.Minor <= 0 {
		return nil, errors.New("settlement: mandate, idempotency key and a positive amount are required")
	}
	now := e.now()
	r := &Request{
		ID: newID(), MandateID: in.MandateID, MerchantID: in.MerchantID, MerchantEmail: in.MerchantEmail,
		Amount: in.Amount, Items: append([]string(nil), in.Items...), IdempotencyKey: in.IdempotencyKey,
		PromisedDelivery: in.PromisedDelivery, DeliverBy: in.DeliverBy,
		State: Requested, Reason: "Payment requested.", CreatedAt: now, UpdatedAt: now,
	}
	// Check-and-insert is atomic so two concurrent requests with the same key
	// cannot both be created.
	e.mu.Lock()
	for _, prev := range e.reqs {
		if prev.MandateID == in.MandateID && prev.IdempotencyKey == in.IdempotencyKey {
			c := prev.clone()
			e.mu.Unlock()
			return c, ErrDuplicateKey
		}
	}
	e.reqs[r.ID] = r
	e.mu.Unlock()

	if err := e.record("settlement.requested", map[string]any{
		"request_id": r.ID, "mandate_id": r.MandateID, "merchant_id": r.MerchantID,
		"amount": r.Amount.String(), "currency": r.Amount.Currency, "items": r.Items, "idempotency_key": r.IdempotencyKey,
	}); err != nil {
		e.mu.Lock()
		delete(e.reqs, r.ID) // no evidence, no request
		e.mu.Unlock()
		return nil, err
	}
	e.mu.Lock()
	err := e.cfg.Store.Save(r)
	c := r.clone()
	e.mu.Unlock()
	return c, err
}

// Decide applies the policy decision (and the AI judge's note) to a REQUESTED
// request: DENIED, STEP_UP_PENDING or APPROVED. Anything other than a clear
// ALLOW or STEP_UP is treated as DENY (fail closed).
func (e *Engine) Decide(id string, d policy.Decision, judge string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	if s := e.state(r); s != Requested {
		return nil, &StateError{ID: id, Op: "decide", State: s}
	}
	if err := e.mutate(r, func() { r.Decision, r.Judge = d, judge }); err != nil {
		return nil, err
	}
	reason := d.Summary()
	if judge != "" && d.Result != policy.Allow {
		reason += " " + judge
	}
	if err := e.move(r, Evaluated, "Policy evaluated: "+string(d.Result)+".", map[string]any{"decision": d, "judge": judge}, false); err != nil {
		return nil, err
	}
	var to State
	switch d.Result {
	case policy.Allow:
		to = Approved
		reason = "Approved: within the signed mandate."
	case policy.StepUp:
		to = StepUpPending
	default:
		to = Denied
	}
	if err := e.move(r, to, reason, nil, false); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// Approve records a human's approval of a STEP_UP request. DENY decisions can
// never be approved by a human; they are final.
func (e *Engine) Approve(id, by string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	res, st := r.Decision.Result, r.State
	e.mu.Unlock()
	if st != StepUpPending || res != policy.StepUp {
		return nil, &StateError{ID: id, Op: "approve", State: st}
	}
	if err := e.move(r, Approved, "You approved this payment.", map[string]any{"approved_by": by}, false); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// Reject records a human's refusal of a STEP_UP request.
func (e *Engine) Reject(id, by string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	if err := e.move(r, Denied, "You declined this payment.", map[string]any{"rejected_by": by}, false); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// Cancel denies a request that is still waiting for a human, for a system
// reason (for example the user revoked the mandate while it waited). Unlike
// Reject it does not claim the human declined.
func (e *Engine) Cancel(id, reason string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	if s := e.state(r); s != StepUpPending {
		return nil, &StateError{ID: id, Op: "cancel", State: s}
	}
	if err := e.move(r, Denied, reason, map[string]any{"cancelled_by": "leash"}, false); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// ---------------------------------------------------------------- money steps

func (e *Engine) deny(r *Request, reason string) {
	if err := e.move(r, Denied, reason, nil, true); err != nil {
		e.cfg.Logf("settlement: could not record denial for %s: %v", r.ID, err)
	}
}

// Authorize places the hold. If PayPal needs the human buyer to approve first
// (no vaulted method), it returns ErrBuyerApprovalRequired and the request
// keeps its APPROVED state and BuyerApprovalURL; call Authorize again after the
// buyer has approved.
//
// Failure handling separates what PayPal PROVED from what is merely unknown. A
// client error (4xx) proves nothing was held, so the request is DENIED. A
// timeout, dropped connection or 5xx proves nothing: the hold may exist. Then the
// request stays APPROVED, PayPal's own state is read before anything else, and
// the caller gets an OutcomeUnknownError; calling again is safe because every
// call reuses its PayPal-Request-Id. This is what prevents an orphan hold (funds
// held at PayPal while Leash believes nothing happened).
func (e *Engine) Authorize(ctx context.Context, id string) (*Request, error) {
	defer e.op(id)()
	return e.authorize(ctx, id)
}

func (e *Engine) authorize(ctx context.Context, id string) (*Request, error) {
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	if s := e.state(r); s != Approved {
		return nil, &StateError{ID: id, Op: "authorize", State: s}
	}
	e.mu.Lock()
	orderID, amount, merchant, holdID := r.OrderID, r.Amount, r.MerchantID, r.AuthorizationID
	e.mu.Unlock()

	if holdID == "" && e.cfg.Guard != nil {
		if ok, reason := e.cfg.Guard(e.snapshot(r)); !ok {
			if _, verr := e.void(ctx, r, Voided, reason); verr != nil {
				return nil, verr
			}
			return e.snapshot(r), ErrGuardRejected
		}
	}

	var order *paypal.Order
	if orderID == "" {
		if err := e.intent(r, "order", map[string]any{"amount": amount.String(), "currency": amount.Currency}); err != nil {
			return nil, err
		}
		params := paypal.CreateOrderParams{
			Intent: "AUTHORIZE", Amount: amount, ReferenceID: r.ID,
			Description: "Leash escrow for " + merchant, CustomID: r.ID,
			PaymentSource: e.cfg.PaymentSource, RequestID: payPalID(r, "order"),
		}
		if e.cfg.PaymentSource == nil {
			// Fallback flow: the buyer approves in PayPal. Without a return URL the
			// approval page has nowhere to go, and without NO_SHIPPING it asks for an address.
			params.NoShipping, params.ReturnURL, params.CancelURL = true, e.cfg.ReturnURL, e.cfg.CancelURL
		}
		order, err = e.cfg.Gateway.CreateOrder(ctx, params)
		if err != nil {
			if definitive(err) {
				e.deny(r, "PayPal could not set up the payment, so nothing was held or charged.")
				return nil, fmt.Errorf("create order: %w", err)
			}
			return nil, e.unknown(r, "create order", err)
		}
		if err := e.mutate(r, func() { r.OrderID = order.ID }); err != nil {
			return nil, err
		}
	} else {
		order, err = e.cfg.Gateway.GetOrder(ctx, orderID)
		if err != nil {
			return nil, fmt.Errorf("get order: %w", err) // transient: stay APPROVED and let the caller retry
		}
	}

	auth := order.Authorization()
	if auth == nil {
		if order.Status != "APPROVED" {
			url := order.ApproveURL()
			_ = e.mutate(r, func() { r.BuyerApprovalURL = url })
			return e.snapshot(r), ErrBuyerApprovalRequired
		}
		if err := e.intent(r, "authorize", map[string]any{"order_id": order.ID}); err != nil {
			return nil, err
		}
		authed, aerr := e.cfg.Gateway.AuthorizeOrder(ctx, order.ID, payPalID(r, "authorize"))
		switch {
		case aerr == nil:
			order = authed
			if auth = order.Authorization(); auth == nil {
				e.deny(r, "PayPal did not return an authorization, so nothing was held.")
				return nil, errors.New("settlement: authorize response had no authorization")
			}
		default:
			// Read PayPal's own state before deciding anything: the hold may exist
			// even though the answer never reached us (or PayPal says it already exists).
			if cur, gerr := e.cfg.Gateway.GetOrder(ctx, order.ID); gerr == nil && cur.Authorization() != nil {
				order, auth = cur, cur.Authorization()
				e.cfg.Logf("settlement: authorize for %s reported %v but PayPal already holds %s; adopting it", r.ID, aerr, auth.ID)
			} else if definitive(aerr) {
				e.deny(r, "PayPal declined to hold the funds, so nothing was held or charged.")
				return nil, fmt.Errorf("authorize order: %w", aerr)
			} else {
				return nil, e.unknown(r, "authorize order", aerr)
			}
		}
	}

	held, perr := auth.Amount.ToAmount()
	if perr != nil || held != amount {
		// The hold does not match what was approved. Release it and refuse.
		if verr := e.cfg.Gateway.Void(ctx, auth.ID, payPalID(r, "void-mismatch")); verr != nil {
			e.cfg.Logf("settlement: could not void mismatched authorization %s: %v", auth.ID, verr)
		}
		e.deny(r, "The amount PayPal held did not match the approved amount, so the hold was released.")
		return nil, fmt.Errorf("settlement: authorization amount mismatch (held %v, approved %s)", auth.Amount, amount.Display())
	}
	var exp time.Time
	if t, perr := time.Parse(time.RFC3339, auth.ExpirationTime); perr == nil {
		exp = t.UTC()
	}
	if err := e.mutate(r, func() { r.AuthorizationID, r.HoldExpiresAt, r.BuyerApprovalURL = auth.ID, exp, "" }); err != nil {
		return nil, err
	}
	if err := e.move(r, Authorized, "Funds are held in escrow. You have not been charged yet.",
		map[string]any{"order_id": order.ID, "authorization_id": auth.ID, "hold_expires_at": exp}, true); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// Delivery is the merchant-side delivery result.
type Delivery struct {
	Delivered bool
	Reference string // tracking number, receipt id, ...
	Source    string // who attested (for the evidence trail)
	Note      string
}

// ConfirmDelivery records verified delivery (AUTHORIZED -> DELIVERED). If the
// delivery failed it releases the hold instead (AUTHORIZED -> VOIDED).
func (e *Engine) ConfirmDelivery(ctx context.Context, id string, d Delivery) (*Request, error) {
	if !d.Delivered {
		note := d.Note
		if note == "" {
			note = "the merchant reported a failed delivery"
		}
		return e.Void(ctx, id, "Delivery failed ("+note+"). The hold was released and you were not charged.")
	}
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	after := e.now().Add(e.cfg.InspectionPeriod)
	if e.state(r) == Authorized {
		if err := e.mutate(r, func() { r.CaptureAfter = after }); err != nil {
			return nil, err
		}
	}
	reason := "Delivery confirmed."
	if e.cfg.InspectionPeriod > 0 {
		reason = "Delivery confirmed. The hold stays in place until " + after.Format(time.RFC3339) + " so you can report a problem."
	}
	if err := e.move(r, Delivered, reason, map[string]any{"reference": d.Reference, "source": d.Source, "note": d.Note, "capture_after": after}, false); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// SettleIfDue captures and pays out a DELIVERED request once its inspection
// window has passed. It also settles early when the hold is about to lapse,
// because a lapsed hold would mean the merchant is never paid. Before that it
// does nothing and returns the request unchanged.
func (e *Engine) SettleIfDue(ctx context.Context, id string) (*Request, error) {
	defer e.op(id)()
	return e.settleIfDue(ctx, id)
}

func (e *Engine) settleIfDue(ctx context.Context, id string) (*Request, error) {
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	st, after, holdExp := r.State, r.CaptureAfter, r.HoldExpiresAt
	e.mu.Unlock()
	if st != Delivered {
		return nil, &StateError{ID: id, Op: "settle", State: st}
	}
	now := e.now()
	lapsing := !holdExp.IsZero() && !now.Before(holdExp.Add(-e.cfg.HoldSafety))
	if now.Before(after) && !lapsing {
		return e.snapshot(r), nil
	}
	return e.settle(ctx, id)
}

// Capture takes the held funds from the buyer (DELIVERED -> CAPTURED).
func (e *Engine) Capture(ctx context.Context, id string) (*Request, error) {
	defer e.op(id)()
	return e.capture(ctx, id)
}

func (e *Engine) capture(ctx context.Context, id string) (*Request, error) {
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	st, authID, amount := r.State, r.AuthorizationID, r.Amount
	e.mu.Unlock()
	if st != Delivered {
		return nil, &StateError{ID: id, Op: "capture", State: st}
	}
	if err := e.intent(r, "capture", map[string]any{"authorization_id": authID, "amount": amount.String()}); err != nil {
		return nil, err
	}
	e.mu.Lock()
	attempt := r.CaptureAttempts
	e.mu.Unlock()
	cp, err := e.cfg.Gateway.Capture(ctx, authID, paypal.CaptureParams{Amount: &amount, FinalCapture: true, RequestID: payPalID(r, attemptOp("capture", attempt))})
	if err != nil {
		_ = e.record("settlement.failure", map[string]any{"request_id": r.ID, "op": "capture", "error": err.Error()})
		var ae *paypal.APIError
		if errors.As(err, &ae) && (ae.Name == "AUTHORIZATION_EXPIRED" || ae.Name == "AUTHORIZATION_VOIDED") {
			// The hold is gone: nothing was taken from the buyer and the merchant
			// cannot be paid. Leaving the request DELIVERED would retry forever.
			if merr := e.move(r, Voided, "The hold was no longer valid when the payment was captured, so you were not charged.",
				map[string]any{"capture_error": ae.Name}, true); merr != nil {
				return nil, merr
			}
			return e.snapshot(r), fmt.Errorf("capture: %w", err)
		}
		return nil, fmt.Errorf("capture: %w", err) // stays DELIVERED; safe to retry (same PayPal-Request-Id)
	}
	got, perr := cp.Amount.ToAmount()
	if perr != nil || got != amount {
		_ = e.record("settlement.failure", map[string]any{"request_id": r.ID, "op": "capture", "error": fmt.Sprintf("unexpected capture result status=%s amount=%v", cp.Status, cp.Amount)})
		return nil, fmt.Errorf("settlement: unexpected capture result (status %q, amount %v)", cp.Status, cp.Amount)
	}
	if err := e.mutate(r, func() { r.CaptureID = cp.ID }); err != nil {
		e.cfg.Logf("settlement: persist capture id for %s: %v", r.ID, err)
	}
	switch strings.ToUpper(cp.Status) {
	case "COMPLETED":
		if err := e.move(r, Captured, "Delivery verified; funds captured from your PayPal.", map[string]any{"capture_id": cp.ID}, true); err != nil {
			return nil, err
		}
	case "PENDING":
		// PayPal accepted the capture but is still processing it. The merchant must
		// not be paid yet; CaptureCompleted (webhook) or Reconcile continues from here.
		if err := e.move(r, CapturePending, "Delivery verified. PayPal accepted the capture and is still processing it.", map[string]any{"capture_id": cp.ID}, true); err != nil {
			return nil, err
		}
	default:
		_ = e.record("settlement.failure", map[string]any{"request_id": r.ID, "op": "capture", "error": "unexpected capture status " + cp.Status})
		return nil, fmt.Errorf("settlement: unexpected capture status %q", cp.Status)
	}
	return e.snapshot(r), nil
}

// Payout pays the merchant (CAPTURED -> PAID_OUT).
func (e *Engine) Payout(ctx context.Context, id string) (*Request, error) {
	defer e.op(id)()
	return e.payout(ctx, id)
}

func (e *Engine) payout(ctx context.Context, id string) (*Request, error) {
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	st, amount, email, merchant := r.State, r.Amount, r.MerchantEmail, r.MerchantID
	e.mu.Unlock()
	if st != Captured {
		return nil, &StateError{ID: id, Op: "pay out", State: st}
	}
	if email == "" {
		return nil, errors.New("settlement: merchant has no payout address")
	}
	e.mu.Lock()
	attempt := r.PayoutAttempts
	e.mu.Unlock()
	opName := attemptOp("payout", attempt)
	batchID := "leash-" + r.ID
	if attempt > 0 {
		batchID = fmt.Sprintf("leash-%s-%d", r.ID, attempt) // PayPal rejects a reused sender_batch_id
	}
	if err := e.intent(r, opName, map[string]any{"receiver": email, "amount": amount.String()}); err != nil {
		return nil, err
	}
	batch, err := e.cfg.Gateway.CreatePayout(ctx, paypal.PayoutParams{
		SenderBatchID: batchID, EmailSubject: "Payment for your order (released by Leash escrow)",
		Items:     []paypal.PayoutItem{{Receiver: email, Amount: amount, Note: "Order " + r.ID, SenderItemID: r.ID}},
		RequestID: payPalID(r, opName),
	})
	if err != nil {
		_ = e.record("settlement.failure", map[string]any{"request_id": r.ID, "op": "payout", "error": err.Error()})
		return nil, fmt.Errorf("payout: %w", err) // stays CAPTURED; safe to retry
	}
	pbID := batch.BatchHeader.PayoutBatchID
	if err := e.mutate(r, func() { r.PayoutBatchID = pbID }); err != nil {
		e.cfg.Logf("settlement: persist payout id for %s: %v", r.ID, err)
	}
	final, ok, detail := payoutOutcome(batch)
	switch {
	case final && ok:
		if err := e.move(r, PaidOut, "Payout to "+merchant+" confirmed by PayPal.", map[string]any{"payout_batch_id": pbID, "receiver": email, "batch_status": batch.BatchHeader.BatchStatus}, true); err != nil {
			return nil, err
		}
	case final:
		_ = e.mutate(r, func() { r.PayoutAttempts++ })
		_ = e.record("settlement.failure", map[string]any{"request_id": r.ID, "op": "payout", "error": detail})
		return nil, fmt.Errorf("settlement: payout failed (%s); the funds are safe in escrow and the payout will be retried", detail)
	default:
		if err := e.move(r, PayoutPending, "Payout to "+merchant+" submitted; waiting for PayPal to confirm it.", map[string]any{"payout_batch_id": pbID, "receiver": email, "batch_status": batch.BatchHeader.BatchStatus}, true); err != nil {
			return nil, err
		}
	}
	return e.snapshot(r), nil
}

// payoutOutcome reads a payout batch. final says PayPal has reached a verdict;
// ok says the money arrived. Anything not clearly SUCCESS is not paid.
func payoutOutcome(b *paypal.PayoutBatch) (final, ok bool, detail string) {
	if len(b.Items) == 0 {
		status := strings.ToUpper(b.BatchHeader.BatchStatus)
		switch status {
		case "SUCCESS":
			return true, true, "batch SUCCESS"
		case "DENIED", "CANCELED":
			return true, false, "batch " + status
		default:
			return false, false, "batch " + status
		}
	}
	pending := false
	for _, it := range b.Items {
		switch st := strings.ToUpper(it.TransactionStatus); st {
		case "SUCCESS":
		case "FAILED", "BLOCKED", "DENIED", "RETURNED", "REFUNDED", "REVERSED":
			return true, false, "item " + st
		default: // PENDING, ONHOLD, UNCLAIMED, or unknown: not confirmed
			pending = true
		}
	}
	if pending {
		return false, false, "items not yet confirmed"
	}
	return true, true, "all items SUCCESS"
}

// pollPayout asks PayPal how a submitted payout ended and moves the request
// accordingly. The caller holds the request's operation lock.
func (e *Engine) pollPayout(ctx context.Context, r *Request) error {
	e.mu.Lock()
	st, batchID, merchant := r.State, r.PayoutBatchID, r.MerchantID
	e.mu.Unlock()
	if st != PayoutPending {
		return &StateError{ID: r.ID, Op: "check payout", State: st}
	}
	batch, err := e.cfg.Gateway.GetPayout(ctx, batchID)
	if err != nil {
		return fmt.Errorf("get payout: %w", err)
	}
	final, ok, detail := payoutOutcome(batch)
	switch {
	case !final:
		return nil
	case ok:
		return e.move(r, PaidOut, "Payout to "+merchant+" confirmed by PayPal.", map[string]any{"payout_batch_id": batchID}, true)
	default:
		_ = e.mutate(r, func() { r.PayoutAttempts++ })
		return e.move(r, Captured, "The payout did not complete ("+detail+"). The funds are safe in escrow and the payout will be retried.",
			map[string]any{"payout_batch_id": batchID, "detail": detail}, true)
	}
}

// pollCapture asks PayPal how a pending capture ended. The caller holds the
// request's operation lock. COMPLETED moves on to CAPTURED; DECLINED or FAILED
// returns to DELIVERED so the capture can be retried; PENDING changes nothing.
func (e *Engine) pollCapture(ctx context.Context, r *Request) error {
	e.mu.Lock()
	st, capID := r.State, r.CaptureID
	e.mu.Unlock()
	if st != CapturePending {
		return &StateError{ID: r.ID, Op: "check capture", State: st}
	}
	cp, err := e.cfg.Gateway.GetCapture(ctx, capID)
	if err != nil {
		return fmt.Errorf("get capture: %w", err)
	}
	switch status := strings.ToUpper(cp.Status); status {
	case "COMPLETED":
		return e.move(r, Captured, "PayPal confirmed the capture; funds captured from your PayPal.", map[string]any{"capture_id": capID}, true)
	case "DECLINED", "FAILED":
		_ = e.mutate(r, func() { r.CaptureID = ""; r.CaptureAttempts++ })
		return e.move(r, Delivered, "PayPal declined the capture ("+status+"). It will be retried.", map[string]any{"capture_id": capID, "detail": status}, true)
	default:
		return nil
	}
}

// CaptureUpdate re-checks a CAPTURE_PENDING request with PayPal and, once the
// capture has completed, pays the merchant. Reconcile calls it; it can also be
// called by hand.
func (e *Engine) CaptureUpdate(ctx context.Context, id string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	if err := e.pollCapture(ctx, r); err != nil {
		return nil, err
	}
	if e.state(r) == Captured {
		return e.payout(ctx, id)
	}
	return e.snapshot(r), nil
}

// PayoutUpdate re-checks a PAYOUT_PENDING request with PayPal. Call it when a
// PAYMENT.PAYOUTS-ITEM.* webhook arrives; Reconcile also calls it.
func (e *Engine) PayoutUpdate(ctx context.Context, id string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	if err := e.pollPayout(ctx, r); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// CaptureCompleted records PayPal's confirmation (webhook PAYMENT.CAPTURE.COMPLETED)
// that a pending capture finished. Call Payout (or Reconcile) next.
func (e *Engine) CaptureCompleted(id, captureID string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	st, have := r.State, r.CaptureID
	e.mu.Unlock()
	if st != CapturePending {
		return nil, &StateError{ID: id, Op: "complete capture", State: st}
	}
	if captureID != "" && have != "" && captureID != have {
		return nil, fmt.Errorf("settlement: capture %s does not belong to request %s", captureID, id)
	}
	if err := e.move(r, Captured, "PayPal confirmed the capture; funds captured from your PayPal.", map[string]any{"capture_id": have}, true); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// CaptureDenied records that PayPal refused a pending capture (webhook
// PAYMENT.CAPTURE.DENIED). The request returns to DELIVERED so the capture can be
// retried with a fresh PayPal-Request-Id.
func (e *Engine) CaptureDenied(id, captureID, reason string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	st, have := r.State, r.CaptureID
	e.mu.Unlock()
	if st != CapturePending {
		return nil, &StateError{ID: id, Op: "deny capture", State: st}
	}
	if captureID != "" && have != "" && captureID != have {
		return nil, fmt.Errorf("settlement: capture %s does not belong to request %s", captureID, id)
	}
	_ = e.mutate(r, func() { r.CaptureID = ""; r.CaptureAttempts++ })
	if err := e.move(r, Delivered, "PayPal declined the capture ("+reason+"). It will be retried.", map[string]any{"capture_id": have, "detail": reason}, true); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// Settle captures and then pays out. If the payout fails the request stays
// CAPTURED (funds are safe in the escrow account) and the error is returned.
func (e *Engine) Settle(ctx context.Context, id string) (*Request, error) {
	defer e.op(id)()
	return e.settle(ctx, id)
}

func (e *Engine) settle(ctx context.Context, id string) (*Request, error) {
	r, err := e.capture(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.State != Captured {
		// CAPTURE_PENDING: PayPal is still processing. The merchant is paid only
		// after PayPal confirms (CaptureCompleted, then Payout, or Reconcile).
		return r, nil
	}
	return e.payout(ctx, id)
}

// Void releases the hold (APPROVED/AUTHORIZED/DELIVERED -> VOIDED). The buyer
// is never charged.
func (e *Engine) Void(ctx context.Context, id, reason string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	return e.void(ctx, r, Voided, reason)
}

func (e *Engine) void(ctx context.Context, r *Request, to State, reason string) (*Request, error) {
	e.mu.Lock()
	st, authID := r.State, r.AuthorizationID
	e.mu.Unlock()
	if !CanTransition(st, to) {
		return nil, &StateError{ID: r.ID, Op: "void", State: st}
	}
	if authID != "" {
		if err := e.intent(r, "void", map[string]any{"authorization_id": authID}); err != nil {
			return nil, err
		}
		if err := e.cfg.Gateway.Void(ctx, authID, payPalID(r, "void")); err != nil {
			var apiErr *paypal.APIError
			// An authorization that already expired cannot be voided; the hold is gone either way.
			if !(to == Expired && errors.As(err, &apiErr) && apiErr.Status == 422) {
				_ = e.record("settlement.failure", map[string]any{"request_id": r.ID, "op": "void", "error": err.Error()})
				return nil, fmt.Errorf("void: %w", err)
			}
		}
	}
	if err := e.move(r, to, reason, nil, true); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// Refund returns captured funds to the buyer (CAPTURED -> REFUNDED). After
// payout the money is with the merchant; that case must go through Dispute.
func (e *Engine) Refund(ctx context.Context, id, reason string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	st, capID := r.State, r.CaptureID
	e.mu.Unlock()
	if st == PaidOut {
		return nil, ErrAlreadyPaidOut
	}
	if st != Captured {
		return nil, &StateError{ID: id, Op: "refund", State: st}
	}
	if err := e.intent(r, "refund", map[string]any{"capture_id": capID}); err != nil {
		return nil, err
	}
	ref, err := e.cfg.Gateway.RefundCapture(ctx, capID, paypal.RefundParams{NoteToPayer: reason, RequestID: payPalID(r, "refund")})
	if err != nil {
		_ = e.record("settlement.failure", map[string]any{"request_id": r.ID, "op": "refund", "error": err.Error()})
		return nil, fmt.Errorf("refund: %w", err)
	}
	if err := e.mutate(r, func() { r.RefundID = ref.ID }); err != nil {
		e.cfg.Logf("settlement: persist refund id for %s: %v", r.ID, err)
	}
	if err := e.move(r, Refunded, "Refunded: "+reason, map[string]any{"refund_id": ref.ID}, true); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// Dispute marks a captured or paid-out request as disputed (evidence only; the
// dispute itself is opened by the buyer in PayPal's resolution center).
func (e *Engine) Dispute(id, reason string) (*Request, error) {
	defer e.op(id)()
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	if err := e.move(r, Disputed, "Disputed: "+reason, nil, false); err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// Sweep applies time-based exits: stale step-up requests expire, and holds that
// are about to lapse (or whose delivery deadline passed) are voided so the buyer
// is never charged for something that was not delivered. It returns the IDs it
// changed.
func (e *Engine) Sweep(ctx context.Context) ([]string, error) {
	now := e.now()
	e.mu.Lock()
	ids := make([]string, 0, len(e.reqs))
	for id := range e.reqs {
		ids = append(ids, id)
	}
	e.mu.Unlock()
	sort.Strings(ids)

	var changed []string
	var firstErr error
	for _, id := range ids {
		func() {
			defer e.op(id)()
			r, err := e.lookup(id)
			if err != nil {
				return
			}
			e.mu.Lock()
			st, created := r.State, r.UpdatedAt
			holdExp, deliverBy := r.HoldExpiresAt, r.DeliverBy
			approvedAt, orderID, authID := enteredAt(r, Approved), r.OrderID, r.AuthorizationID
			e.mu.Unlock()
			switch st {
			case Approved:
				if now.Sub(approvedAt) < e.cfg.ApprovalTTL {
					break
				}
				if authID == "" && orderID != "" {
					// An earlier unknown outcome may have left a hold: look before expiring.
					cur, gerr := e.cfg.Gateway.GetOrder(ctx, orderID)
					if gerr != nil {
						if firstErr == nil {
							firstErr = gerr
						}
						break
					}
					if a := cur.Authorization(); a != nil {
						_ = e.mutate(r, func() { r.AuthorizationID = a.ID })
					}
				}
				if _, err := e.void(ctx, r, Expired, "The payment was approved but the hold was not completed in time, so it expired and you were not charged."); err == nil {
					changed = append(changed, id)
				} else if firstErr == nil {
					firstErr = err
				}
			case StepUpPending:
				if now.Sub(created) >= e.cfg.StepUpTTL {
					if err := e.move(r, Expired, "Nobody approved this payment in time, so it expired.", nil, false); err == nil {
						changed = append(changed, id)
					} else if firstErr == nil {
						firstErr = err
					}
				}
			case Authorized:
				late := !deliverBy.IsZero() && now.After(deliverBy)
				lapsing := !holdExp.IsZero() && !now.Before(holdExp.Add(-e.cfg.HoldSafety))
				if late || lapsing {
					why := "The merchant did not deliver by your deadline, so the hold was released and you were not charged."
					if !late {
						why = "The hold was about to lapse before delivery was confirmed, so it was released and you were not charged."
					}
					if _, err := e.void(ctx, r, Expired, why); err == nil {
						changed = append(changed, id)
					} else if firstErr == nil {
						firstErr = err
					}
				}
			}
		}()
	}
	return changed, firstErr
}

// Reconcile moves requests that are stuck between steps forward again. It is
// what turns "safe to retry" into "actually retried": run it at startup and on a
// timer (Plane.Sweep does both Sweep and Reconcile).
//
//	APPROVED         place the hold (an earlier call timed out or the process died)
//	DELIVERED        capture and pay out once the inspection window has passed
//	CAPTURE_PENDING  ask PayPal whether the capture finished, then pay out
//	CAPTURED         pay the merchant (an earlier payout failed)
//	PAYOUT_PENDING   ask PayPal whether the payout finished
//
// Every step re-reads PayPal's state and reuses its PayPal-Request-Id, so running
// it twice, or while another process is mid-call, cannot double-charge or
// double-pay. It returns the IDs whose state changed and the first error.
func (e *Engine) Reconcile(ctx context.Context) ([]string, error) {
	e.mu.Lock()
	ids := make([]string, 0, len(e.reqs))
	for id := range e.reqs {
		ids = append(ids, id)
	}
	e.mu.Unlock()
	sort.Strings(ids)

	var changed []string
	var firstErr error
	for _, id := range ids {
		func() {
			defer e.op(id)()
			r, err := e.lookup(id)
			if err != nil {
				return
			}
			before := e.state(r)
			switch before {
			case Approved:
				_, err = e.authorize(ctx, id)
			case Delivered:
				_, err = e.settleIfDue(ctx, id)
			case CapturePending:
				if err = e.pollCapture(ctx, r); err == nil && e.state(r) == Captured {
					_, err = e.payout(ctx, id)
				}
			case Captured:
				_, err = e.payout(ctx, id)
			case PayoutPending:
				err = e.pollPayout(ctx, r)
			default:
				return
			}
			if err != nil && firstErr == nil && !errors.Is(err, ErrBuyerApprovalRequired) {
				firstErr = fmt.Errorf("reconcile %s: %w", id, err)
			}
			if e.state(r) != before {
				changed = append(changed, id)
			}
		}()
	}
	return changed, firstErr
}

// ---------------------------------------------------------------- queries

// Get returns a copy of one request.
func (e *Engine) Get(id string) (*Request, error) {
	r, err := e.lookup(id)
	if err != nil {
		return nil, err
	}
	return e.snapshot(r), nil
}

// List returns copies of all requests, oldest first.
func (e *Engine) List() []*Request {
	e.mu.Lock()
	out := make([]*Request, 0, len(e.reqs))
	for _, r := range e.reqs {
		out = append(out, r.clone())
	}
	e.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// ByIdempotencyKey finds the earlier request for (mandate, key).
func (e *Engine) ByIdempotencyKey(mandateID, key string) (*Request, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.reqs {
		if r.MandateID == mandateID && r.IdempotencyKey == key {
			return r.clone(), true
		}
	}
	return nil, false
}

// Usage is what the policy engine needs to know about a mandate's history.
type Usage struct {
	SpentMinor int64
	Consumed   bool        // any request that still counts as spend
	Recent     []time.Time // creation times of every request (velocity counts attempts)
}

// MandateUsage summarizes a mandate's history, ignoring request excludeID
// (so a request being re-evaluated does not count against itself).
func (e *Engine) MandateUsage(mandateID, excludeID, currency string) Usage {
	e.mu.Lock()
	defer e.mu.Unlock()
	var u Usage
	for _, r := range e.reqs {
		if r.MandateID != mandateID || r.ID == excludeID {
			continue
		}
		u.Recent = append(u.Recent, r.CreatedAt)
		if r.State.CountsAsSpend() && r.Amount.Currency == currency {
			u.SpentMinor += r.Amount.Minor
			u.Consumed = true
		}
	}
	return u
}
