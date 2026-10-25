// Package settlement is Leash's escrow state machine.
//
//	REQUESTED -> EVALUATED -> (STEP_UP_PENDING) -> APPROVED -> AUTHORIZED (funds held)
//	    -> DELIVERED -> CAPTURED -> PAID_OUT
//	Exits: DENIED | EXPIRED | VOIDED | REFUNDED | DISPUTED
//
// Two in-flight states exist because PayPal's answer is not always final:
// CAPTURE_PENDING (capture accepted but still processing) and PAYOUT_PENDING
// (payout submitted but not yet confirmed). A request only becomes CAPTURED or
// PAID_OUT when PayPal says so, never earlier.
//
// Escrow model (sandbox): the buyer's payment is *authorized* (held, not taken).
// Only after verified delivery does Leash capture it and pay the merchant out.
// If delivery fails or the deadline passes, Leash voids the authorization and
// the buyer is never charged.
//
// Safety properties enforced here, independent of any caller:
//   - Transitions are table-driven; anything not listed is an error.
//   - Fail closed: if PayPal REFUSES (a client error) while placing the hold, the
//     request is DENIED. If the outcome is merely UNKNOWN (timeout, dropped
//     connection, 5xx) the request is not denied: PayPal's state is read and the
//     call is retried with the same PayPal-Request-Id, so no orphan hold is left.
//   - Write-ahead evidence: before any call that moves money, an intent record
//     is appended to the ledger; if that append fails, the call is not made.
//   - Every PayPal call carries a deterministic PayPal-Request-Id, so retries
//     and crash-recovery cannot double-charge or double-pay.
package settlement

import (
	"fmt"
	"time"

	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/policy"
)

// State is a settlement state.
type State string

const (
	Requested     State = "REQUESTED"
	Evaluated     State = "EVALUATED"
	StepUpPending State = "STEP_UP_PENDING"
	Approved      State = "APPROVED"
	Authorized    State = "AUTHORIZED"
	Delivered     State = "DELIVERED"
	Captured      State = "CAPTURED"
	PaidOut       State = "PAID_OUT"

	CapturePending State = "CAPTURE_PENDING" // PayPal accepted the capture but has not finished it
	PayoutPending  State = "PAYOUT_PENDING"  // payout submitted, not yet confirmed by PayPal

	Denied   State = "DENIED"
	Expired  State = "EXPIRED"
	Voided   State = "VOIDED"
	Refunded State = "REFUNDED"
	Disputed State = "DISPUTED"
)

var transitions = map[State][]State{
	Requested:     {Evaluated, Denied},
	Evaluated:     {StepUpPending, Approved, Denied},
	StepUpPending: {Approved, Denied, Expired},
	Approved:      {Authorized, Voided, Expired, Denied},
	Authorized:    {Delivered, Voided, Expired},
	Delivered:     {Captured, CapturePending, Voided},
	// A denied pending capture goes back to DELIVERED so it can be retried.
	CapturePending: {Captured, Delivered, Disputed},
	// A failed payout goes back to CAPTURED: the funds are safe in escrow and the
	// payout can be retried (or the buyer refunded).
	Captured:      {PaidOut, PayoutPending, Refunded, Disputed},
	PayoutPending: {PaidOut, Captured, Disputed},
	PaidOut:       {Disputed},
}

// CanTransition reports whether from -> to is a legal move.
func CanTransition(from, to State) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Terminal reports whether no further transition is possible.
func (s State) Terminal() bool { return len(transitions[s]) == 0 }

// CountsAsSpend reports whether a request in this state still counts against the
// mandate's budget (money is held, taken, or about to be).
func (s State) CountsAsSpend() bool {
	switch s {
	case Approved, StepUpPending, Authorized, Delivered, CapturePending, Captured, PayoutPending, PaidOut, Disputed:
		return true
	}
	return false
}

// Transition is one history entry on a request.
type Transition struct {
	From   State     `json:"from"`
	To     State     `json:"to"`
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

// Request is one payment request moving through settlement.
type Request struct {
	ID               string       `json:"id"`
	MandateID        string       `json:"mandate_id"`
	MerchantID       string       `json:"merchant_id"`
	MerchantEmail    string       `json:"merchant_email"`
	Amount           money.Amount `json:"amount"`
	Items            []string     `json:"items"`
	IdempotencyKey   string       `json:"idempotency_key"`
	PromisedDelivery time.Time    `json:"promised_delivery,omitempty"`
	DeliverBy        time.Time    `json:"deliver_by,omitempty"`

	State  State  `json:"state"`
	Reason string `json:"reason"` // plain-English reason for the current state

	// Decision is the policy engine's verdict, kept for the dashboard.
	Decision policy.Decision `json:"decision"`
	// Judge is the AI judge's summary, if one ran (may only tighten).
	Judge string `json:"judge,omitempty"`

	OrderID          string    `json:"order_id,omitempty"`
	AuthorizationID  string    `json:"authorization_id,omitempty"`
	CaptureID        string    `json:"capture_id,omitempty"`
	RefundID         string    `json:"refund_id,omitempty"`
	PayoutBatchID    string    `json:"payout_batch_id,omitempty"`
	BuyerApprovalURL string    `json:"buyer_approval_url,omitempty"` // set when PayPal needs the human buyer (spike S2 fallback)
	HoldExpiresAt    time.Time `json:"hold_expires_at,omitempty"`
	// CaptureAfter is when the inspection window after delivery ends; before
	// then the hold stays in place and the buyer (or their agent) can still report
	// a problem. Zero means capture immediately.
	CaptureAfter time.Time `json:"capture_after,omitempty"`
	// CaptureAttempts and PayoutAttempts count retries after a definitive
	// failure, so each retry uses a fresh PayPal-Request-Id (PayPal would replay
	// the old failed answer for a reused one) and a fresh payout batch id.
	CaptureAttempts int `json:"capture_attempts,omitempty"`
	PayoutAttempts  int `json:"payout_attempts,omitempty"`

	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	History   []Transition `json:"history"`
}

func (r *Request) clone() *Request {
	c := *r
	c.Items = append([]string(nil), r.Items...)
	c.History = append([]Transition(nil), r.History...)
	c.Decision.Findings = append([]policy.Finding(nil), r.Decision.Findings...)
	c.Decision.Passed = append([]string(nil), r.Decision.Passed...)
	return &c
}

// payPalID builds the deterministic PayPal-Request-Id for one operation.
func payPalID(r *Request, op string) string { return fmt.Sprintf("leash-%s-%s", r.ID, op) }

// attemptOp names an operation for its n-th attempt: the first attempt keeps the
// plain name, so ids stay stable for requests created before retries existed.
func attemptOp(op string, attempt int) string {
	if attempt <= 0 {
		return op
	}
	return fmt.Sprintf("%s-%d", op, attempt)
}

// enteredAt returns when the request most recently entered state s.
func enteredAt(r *Request, s State) time.Time {
	for i := len(r.History) - 1; i >= 0; i-- {
		if r.History[i].To == s {
			return r.History[i].At
		}
	}
	return r.CreatedAt
}
