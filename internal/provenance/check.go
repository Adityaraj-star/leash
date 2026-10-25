package provenance

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/policy"
)

// Quote is a price/items quote that Leash fetched itself, server to server,
// from a registered merchant. Because the agent never touches it, a value
// confirmed against a quote is trusted even though the merchant's web page is
// not.
type Quote struct {
	ID               string       `json:"id"`
	MerchantID       string       `json:"merchant_id"`
	Amount           money.Amount `json:"amount"`
	Items            []string     `json:"items"`
	PromisedDelivery time.Time    `json:"promised_delivery,omitempty"`
}

// Claim is what the agent says it wants to pay for.
type Claim struct {
	MerchantID string
	Amount     money.Amount
	Items      []string
}

// Matches reports whether the claim equals the quote exactly (same merchant,
// same amount, same set of items).
func (q *Quote) Matches(c Claim) bool {
	if q == nil || q.MerchantID != c.MerchantID || q.Amount != c.Amount || len(q.Items) != len(c.Items) {
		return false
	}
	have := map[string]int{}
	for _, it := range q.Items {
		have[Normalize(it)]++
	}
	for _, it := range c.Items {
		k := Normalize(it)
		if have[k] == 0 {
			return false
		}
		have[k]--
	}
	return true
}

// Input is everything Check needs.
type Input struct {
	Mandate     *mandate.Mandate
	UserMessage string   // the user's own words (trusted)
	MerchantIDs []string // names / domain fragments that identify the claimed merchant in text
	Claim       Claim
	Quote       *Quote   // nil when the agent gave no quote id or it could not be verified
	Refs        []string // evidence ids the agent cited
	Store       *Store
	Session     string
}

var numRe = regexp.MustCompile(`\d[\d,]*(?:\.\d+)?`)

// containsAmount reports whether text mentions exactly this amount.
func containsAmount(text string, a money.Amount) bool {
	for _, tok := range numRe.FindAllString(text, -1) {
		tok = strings.ReplaceAll(tok, ",", "")
		if got, err := money.Parse(tok, a.Currency); err == nil && got.Minor == a.Minor {
			return true
		}
	}
	return false
}

func mentions(text, needle string) bool {
	n := Normalize(needle)
	return n != "" && strings.Contains(text, n)
}

func anyMention(text string, needles []string) bool {
	for _, n := range needles {
		if mentions(text, n) {
			return true
		}
	}
	return false
}

// Check builds the policy engine's provenance verdict.
//
// Rules of thumb:
//   - No cited evidence (or an unknown id) means Evaluated=false, which the
//     policy engine denies: Leash will not pay when it cannot see where the
//     details came from.
//   - Injection severity is the maximum over EVERYTHING the session read, not
//     only the pages the agent cited. A manipulated agent cannot hide a
//     poisoned page by leaving it out of its evidence list.
func Check(in Input) policy.Provenance {
	p := policy.Provenance{
		MerchantOrigin: policy.OriginUnknown, AmountOrigin: policy.OriginUnknown, ItemsOrigin: policy.OriginUnknown,
	}

	var cited []Evidence
	for _, id := range in.Refs {
		ev, ok := in.Store.Get(id)
		if !ok {
			p.Notes = append(p.Notes, fmt.Sprintf("evidence %q is unknown", clip(id, 40)))
			return p // Evaluated stays false
		}
		cited = append(cited, ev)
	}
	if len(cited) == 0 {
		p.Notes = append(p.Notes, "no evidence was cited")
		return p
	}
	p.Evaluated = true

	all := append([]Evidence(nil), in.Store.Session(in.Session)...)
	seen := map[string]bool{}
	for _, e := range all {
		seen[e.ID] = true
	}
	for _, e := range cited {
		if !seen[e.ID] {
			all = append(all, e)
		}
	}

	// Injection: worst severity across everything read.
	worst := policy.SeverityNone
	for _, e := range all {
		if e.Severity > worst {
			worst = e.Severity
			p.Notes = append([]string{fmt.Sprintf("page %s: %s", clip(e.URL, 80), firstOr(e.Notes, "instruction-like text"))}, p.Notes...)
		}
	}
	if sw := in.Store.SessionWorst(in.Session); sw > worst {
		worst = sw // a page that has since been evicted from memory still counts
		p.Notes = append([]string{"an earlier page in this session contained instruction-like text"}, p.Notes...)
	}
	p.Injection = worst

	// Trusted text: the signed mandate and the user's own message.
	trustedText := Normalize(in.UserMessage)
	if in.Mandate != nil {
		trustedText += " " + Normalize(in.Mandate.Intent)
	}
	var evText []string
	for _, e := range all {
		evText = append(evText, Normalize(e.URL+" "+e.Title+" "+e.Text))
	}
	evidenceMentions := func(f func(string) bool) bool {
		for _, t := range evText {
			if f(t) {
				return true
			}
		}
		return false
	}

	// Merchant.
	switch {
	case in.Mandate != nil && contains(in.Mandate.AllowedMerchants, in.Claim.MerchantID):
		p.MerchantOrigin = policy.OriginTrusted
	case anyMention(trustedText, in.MerchantIDs) || mentions(trustedText, in.Claim.MerchantID):
		p.MerchantOrigin = policy.OriginTrusted
	case evidenceMentions(func(t string) bool { return anyMention(t, in.MerchantIDs) || mentions(t, in.Claim.MerchantID) }):
		p.MerchantOrigin = policy.OriginUntrustedOnly
	}

	// Amount and items: a quote Leash fetched itself is the trusted source.
	quoteOK := in.Quote.Matches(in.Claim)
	if in.Quote != nil && !quoteOK {
		p.Notes = append(p.Notes, "the amount or items do not match the merchant's own quote")
	}
	switch {
	case quoteOK:
		p.AmountOrigin = policy.OriginTrusted
	case containsAmount(trustedText, in.Claim.Amount):
		p.AmountOrigin = policy.OriginTrusted
	case evidenceMentions(func(t string) bool { return containsAmount(t, in.Claim.Amount) }):
		p.AmountOrigin = policy.OriginUntrustedOnly
	}
	switch {
	case quoteOK:
		p.ItemsOrigin = policy.OriginTrusted
	case allMentioned(trustedText, in.Claim.Items):
		p.ItemsOrigin = policy.OriginTrusted
	case len(in.Claim.Items) > 0 && evidenceMentions(func(t string) bool { return allMentioned(t, in.Claim.Items) }):
		p.ItemsOrigin = policy.OriginUntrustedOnly
	}
	return p
}

func allMentioned(text string, items []string) bool {
	if len(items) == 0 {
		return false
	}
	for _, it := range items {
		if !mentions(text, it) {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func firstOr(list []string, def string) string {
	if len(list) > 0 {
		return list[0]
	}
	return def
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
