// Package policy is Leash's deterministic rule engine.
//
// It is a pure function: Evaluate(Input) -> Decision. No I/O, no clocks, no
// randomness, no LLM. Everything it needs (time, spend so far, registry data,
// provenance verdicts) is passed in, which is what makes it testable with
// properties and fuzzing and defensible in front of judges.
//
// Principles:
//   - Fail closed: anything missing, malformed or unknown denies.
//   - Never panic and never overflow: only one subtraction exists (remaining
//     budget) and it is guarded.
//   - The result is the worst finding: DENY > STEP_UP > ALLOW. The AI judge,
//     which runs elsewhere, may only move a decision up that ladder.
//
// Rules (see docs/architecture.md):
//
//	R1 mandate valid (present, signature, not revoked, not expired, well-formed)
//	R2 amount and currency within per-tx cap and remaining budget
//	R3 merchant allowed (allowlist AND category when both are set), return policy
//	R4 single-use mandate not already consumed
//	R5 velocity
//	R6 step-up threshold (human must approve)
//	R7 provenance (values must not originate only in untrusted web content)
//	R8 idempotency (replay returns the earlier decision; key required)
//	R9 delivery deadline
package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/money"
)

// Result is a decision outcome.
type Result string

const (
	Allow  Result = "ALLOW"
	StepUp Result = "STEP_UP"
	Deny   Result = "DENY"
	// Replay means the idempotency key was already processed; the caller must
	// return the stored decision instead of acting again.
	Replay Result = "REPLAY"
)

func (r Result) rank() int {
	switch r {
	case Allow:
		return 0
	case StepUp:
		return 1
	default:
		return 2
	}
}

// Origin says where a value in a payment request came from.
type Origin string

const (
	// OriginTrusted: the value is in the signed mandate or the user's own
	// message, or was confirmed against a Leash-verified merchant quote.
	OriginTrusted Origin = "trusted"
	// OriginUntrustedOnly: the value appears only in untrusted web content.
	OriginUntrustedOnly Origin = "untrusted_only"
	// OriginUnknown: provenance could not be established.
	OriginUnknown Origin = "unknown"
)

// Severity of prompt-injection signals found in content the agent read.
type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
)

// Provenance is the verdict of the provenance checker (internal/provenance).
type Provenance struct {
	Evaluated      bool // false = no evidence was supplied: fail closed
	MerchantOrigin Origin
	AmountOrigin   Origin
	ItemsOrigin    Origin
	Injection      Severity
	Notes          []string
}

// Merchant is registry data about the payee.
type Merchant struct {
	ID              string
	Known           bool
	Categories      []string
	HasReturnPolicy bool
}

// Request is what the agent asked for.
type Request struct {
	Merchant         Merchant
	Amount           money.Amount
	PromisedDelivery time.Time // zero = unknown
	IdempotencyKey   string
	StepUpApproved   bool // a human tapped approve for exactly this request
}

// State is everything Leash knows about this mandate's history.
type State struct {
	SpentMinor         int64
	MandateConsumed    bool
	Revoked            bool
	RecentRequests     []time.Time
	IdempotencyKeySeen bool
}

// Config holds tunables.
type Config struct {
	VelocityMax    int
	VelocityWindow time.Duration
}

// DefaultConfig is used when Config is the zero value.
var DefaultConfig = Config{VelocityMax: 5, VelocityWindow: time.Minute}

// Input is the full, explicit input of one evaluation.
type Input struct {
	Now            time.Time
	Mandate        *mandate.Mandate
	SignatureValid bool
	Request        Request
	State          State
	Prov           Provenance
	Cfg            Config
}

// Finding is one rule outcome other than a clean pass.
type Finding struct {
	Rule   string `json:"rule"`
	Result Result `json:"result"`
	Reason string `json:"reason"`
}

// Decision is the engine's output.
type Decision struct {
	Result   Result    `json:"result"`
	Findings []Finding `json:"findings,omitempty"`
	Passed   []string  `json:"passed,omitempty"`
}

// Summary is a one-sentence, plain-English explanation.
func (d Decision) Summary() string {
	for _, want := range []Result{Deny, StepUp, Replay} {
		for _, f := range d.Findings {
			if f.Result == want {
				return f.Reason
			}
		}
	}
	return "Within the signed mandate."
}

// Reasons lists every non-passing reason, worst first.
func (d Decision) Reasons() []string {
	var out []string
	for _, want := range []Result{Deny, StepUp, Replay} {
		for _, f := range d.Findings {
			if f.Result == want {
				out = append(out, f.Reason)
			}
		}
	}
	return out
}

var allRules = []string{"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Evaluate applies all rules. See the package comment.
func Evaluate(in Input) Decision {
	// R8 first: a replay must return the earlier decision no matter what.
	if in.State.IdempotencyKeySeen {
		return Decision{Result: Replay, Findings: []Finding{{
			Rule: "R8", Result: Replay,
			Reason: "This request was already processed (same idempotency key); returning the earlier decision.",
		}}}
	}

	var d Decision
	failed := map[string]bool{}
	fail := func(rule string, r Result, format string, a ...any) {
		failed[rule] = true
		d.Findings = append(d.Findings, Finding{Rule: rule, Result: r, Reason: fmt.Sprintf(format, a...)})
	}
	finish := func() Decision {
		d.Result = Allow
		for _, f := range d.Findings {
			if f.Result.rank() > d.Result.rank() {
				d.Result = f.Result
			}
		}
		for _, r := range allRules {
			if !failed[r] {
				d.Passed = append(d.Passed, r)
			}
		}
		return d
	}
	earlyDeny := func(format string, a ...any) Decision {
		fail("R1", Deny, format, a...)
		d.Result = Deny
		return d // R1 failures invalidate everything else; nothing more is evaluated
	}

	// ---- R1: the mandate itself ----
	m := in.Mandate
	if m == nil {
		return earlyDeny("No mandate was provided, so nothing authorizes this payment.")
	}
	if !in.SignatureValid {
		return earlyDeny("The mandate's signature could not be verified, so it cannot authorize spending.")
	}
	if m.MaxTotal.Minor <= 0 || !money.ValidCurrency(m.MaxTotal.Currency) {
		return earlyDeny("The mandate is malformed (no valid maximum total).")
	}
	if in.State.Revoked {
		return earlyDeny("You revoked this mandate (kill switch), so no further payments are allowed.")
	}
	if !in.Now.Before(m.ExpiresAt) {
		return earlyDeny("The mandate expired at %s.", m.ExpiresAt.UTC().Format(time.RFC3339))
	}

	req := in.Request
	a := req.Amount
	cur := m.MaxTotal.Currency

	// ---- R8 (cont.): every request needs an idempotency key ----
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		fail("R8", Deny, "The request has no idempotency key, so it cannot be protected against duplicates.")
	}

	// ---- R2: amount, currency, budget ----
	switch {
	case a.Currency != cur:
		fail("R2", Deny, "The request is in %q but the mandate is in %q.", a.Currency, cur)
	case a.Minor <= 0:
		fail("R2", Deny, "The payment amount must be greater than zero.")
	default:
		if a.Minor > m.PerTxCap.Minor {
			fail("R2", Deny, "%s exceeds the per-transaction cap of %s.", a.Display(), m.PerTxCap.Display())
		}
		spent := in.State.SpentMinor
		switch {
		case spent < 0:
			fail("R2", Deny, "Spend history is invalid; refusing to pay.")
		case spent > m.MaxTotal.Minor:
			fail("R2", Deny, "The mandate's budget is already exhausted.")
		default:
			remaining := m.MaxTotal.Minor - spent // both non-negative: cannot overflow
			if a.Minor > remaining {
				fail("R2", Deny, "%s exceeds the remaining budget of %s (already spent %s of %s).",
					a.Display(), money.Amount{Minor: remaining, Currency: cur}.Display(),
					money.Amount{Minor: spent, Currency: cur}.Display(), m.MaxTotal.Display())
			}
		}
	}

	// ---- R3: merchant ----
	mer := req.Merchant
	switch {
	case !mer.Known || mer.ID == "":
		fail("R3", Deny, "Merchant %q is not in the merchant registry.", clip(mer.ID, 40))
	case len(m.AllowedMerchants) == 0 && len(m.Categories) == 0:
		fail("R3", Deny, "The mandate names no allowed merchants or categories, so no merchant is authorized.")
	default:
		if len(m.AllowedMerchants) > 0 && !contains(m.AllowedMerchants, mer.ID) {
			fail("R3", Deny, "Merchant %q is not on the mandate's allowed-merchant list.", clip(mer.ID, 40))
		}
		if len(m.Categories) > 0 && !intersects(m.Categories, mer.Categories) {
			fail("R3", Deny, "Merchant %q is not in an allowed category (%s).", clip(mer.ID, 40), strings.Join(m.Categories, ", "))
		}
		if m.RequiresReturnPolicy && !mer.HasReturnPolicy {
			fail("R3", Deny, "The mandate requires a return policy and merchant %q has none.", clip(mer.ID, 40))
		}
	}

	// ---- R4: single use ----
	if m.SingleUse && in.State.MandateConsumed {
		fail("R4", Deny, "This single-use mandate has already been used.")
	}

	// ---- R5: velocity ----
	cfg := in.Cfg
	if cfg.VelocityMax <= 0 || cfg.VelocityWindow <= 0 {
		cfg = DefaultConfig
	}
	recent := 0
	windowStart := in.Now.Add(-cfg.VelocityWindow)
	for _, t := range in.State.RecentRequests {
		if !t.Before(windowStart) && !t.After(in.Now) {
			recent++
		}
	}
	if recent >= cfg.VelocityMax {
		fail("R5", Deny, "Too many payment requests (%d in the last %s); slowing down.", recent, cfg.VelocityWindow)
	}

	// ---- R6: step-up ----
	if m.StepUpOver.Minor > 0 && a.Minor > m.StepUpOver.Minor && !req.StepUpApproved {
		fail("R6", StepUp, "%s is over the %s you asked to approve personally.", a.Display(), m.StepUpOver.Display())
	}

	// ---- R7: provenance ----
	p := in.Prov
	if !p.Evaluated {
		fail("R7", Deny, "No provenance evidence was supplied, so Leash cannot tell where these payment details came from.")
	} else {
		note := ""
		if len(p.Notes) > 0 {
			note = " (" + clip(p.Notes[0], 120) + ")"
		}
		switch {
		case p.Injection >= SeverityHigh:
			fail("R7", Deny, "Web content the agent read contains instructions aimed at the agent%s, and the agent then asked to pay. Blocked.", note)
		case p.Injection == SeverityMedium:
			fail("R7", StepUp, "Web content the agent read looks like it may contain instructions aimed at the agent%s; a human must confirm.", note)
		}
		if p.MerchantOrigin != OriginTrusted {
			fail("R7", Deny, "The merchant to pay appears only in untrusted web content, not in your mandate or request.")
		}
		if p.AmountOrigin != OriginTrusted {
			fail("R7", StepUp, "The amount comes only from untrusted web content; a human must confirm it.")
		}
		if p.ItemsOrigin != OriginTrusted {
			fail("R7", StepUp, "The items to buy come only from untrusted web content; a human must confirm them.")
		}
	}

	// ---- R9: delivery deadline ----
	if !m.DeliverBy.IsZero() {
		switch {
		case req.PromisedDelivery.IsZero():
			fail("R9", StepUp, "The merchant gave no delivery date, but you need delivery by %s.", m.DeliverBy.UTC().Format("2006-01-02"))
		case req.PromisedDelivery.After(m.DeliverBy):
			fail("R9", Deny, "Promised delivery on %s is after your deadline of %s.",
				req.PromisedDelivery.UTC().Format("2006-01-02"), m.DeliverBy.UTC().Format("2006-01-02"))
		}
	}

	return finish()
}
