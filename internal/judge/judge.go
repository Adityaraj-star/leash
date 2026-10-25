// Package judge defines the AI judge's contract and the one rule that governs
// it: the judge may only TIGHTEN a deterministic decision, never loosen it.
//
//	ALLOW -> STEP_UP -> DENY     (the judge can move a decision to the right)
//	DENY  -> anything else       (never)
//
// The model proposes; code disposes. Tighten is a pure function so the
// "can only tighten" property is exhaustively testable, whatever the model
// (or an attacker steering it) says.
//
// The LLM-backed implementation lives in this package as well; the control
// plane depends only on the Judge interface.
package judge

import (
	"context"
	"strings"
	"unicode"

	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/policy"
	"github.com/Adityaraj-star/leash/internal/provenance"
)

// Verdict is the judge's opinion of a payment request.
type Verdict string

const (
	OK         Verdict = "ok"
	Suspicious Verdict = "suspicious"
	Block      Verdict = "block"
)

// Result is the judge's structured output.
type Result struct {
	Verdict    Verdict  `json:"verdict"`
	Reasons    []string `json:"reasons"`
	Confidence float64  `json:"confidence"`
}

// Input is everything the judge may see. It runs in a separate context from
// the shopping agent and never receives the agent's conversation, only facts.
type Input struct {
	Mandate     *mandate.Mandate
	UserMessage string
	Claim       provenance.Claim
	Prov        policy.Provenance
	// Pages are the pages the agent cited plus any page flagged as suspicious.
	// Their text is untrusted content and must be presented to a model as data.
	Pages []provenance.Evidence
}

// Judge reviews one payment request.
type Judge interface {
	Review(ctx context.Context, in Input) (Result, error)
}

func rank(r policy.Result) int {
	switch r {
	case policy.Allow:
		return 0
	case policy.StepUp:
		return 1
	case policy.Deny:
		return 2
	}
	return -1
}

// Tighten combines a deterministic decision with the judge's output.
//
// Guarantees (see the tests):
//   - The returned Result is never lower than d.Result.
//   - A judge error, an unknown verdict or garbage output counts as
//     "suspicious": a human must confirm. It never counts as OK.
//   - Only an explicit, well-formed OK leaves an ALLOW untouched.
//   - Decisions that are not ALLOW / STEP_UP / DENY (for example REPLAY) are
//     returned unchanged.
//
// The second return value is a one-line summary for the audit trail and
// dashboard; it is built from sanitized text, never from raw model output.
func Tighten(d policy.Decision, r Result, err error) (policy.Decision, string) {
	if rank(d.Result) < 0 {
		return d, ""
	}
	out := policy.Decision{
		Result:   d.Result,
		Findings: append([]policy.Finding(nil), d.Findings...),
		Passed:   append([]string(nil), d.Passed...),
	}

	var target policy.Result
	var reason string
	switch {
	case err != nil:
		target = policy.StepUp
		reason = "The AI judge could not review this request, so a human must confirm it."
	case r.Verdict == OK:
		out.Passed = append(out.Passed, "J")
		return out, "AI judge: no concerns."
	case r.Verdict == Suspicious:
		target = policy.StepUp
		reason = reasonText(r.Reasons, "The AI judge found this request suspicious; a human must confirm it.")
	case r.Verdict == Block:
		target = policy.Deny
		reason = reasonText(r.Reasons, "The AI judge blocked this request.")
	default: // unknown verdict: fail closed, but do not trust the text
		target = policy.StepUp
		reason = "The AI judge returned an unrecognized answer, so a human must confirm this request."
	}

	if rank(target) > rank(out.Result) {
		out.Result = target
	}
	out.Findings = append(out.Findings, policy.Finding{Rule: "J", Result: target, Reason: reason})
	return out, "AI judge: " + reason
}

const maxReasonLen = 240

// reasonText turns model-written reasons into a short, single-line, control
// character free string.
func reasonText(reasons []string, fallback string) string {
	var parts []string
	for _, s := range reasons {
		if s = Sanitize(s); s != "" {
			parts = append(parts, s)
		}
		if len(parts) == 2 {
			break
		}
	}
	if len(parts) == 0 {
		return fallback
	}
	return clip(strings.Join(parts, " "), maxReasonLen)
}

// Sanitize removes control and formatting characters and collapses whitespace.
func Sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// cut on a rune boundary
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
