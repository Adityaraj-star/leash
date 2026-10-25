// Package provenance tracks where the values in a payment request came from.
//
// Everything the agent reads from the web arrives through leash.browse and is
// stored with a trust label (untrusted_web). When the agent later asks to pay,
// Leash checks whether the merchant, amount and items originate in trusted
// places (the user's signed mandate, the user's own message, or a quote that
// Leash itself fetched from the merchant) or only in untrusted page text, and
// whether any page the agent read contains instructions aimed at the agent.
//
// HONEST LIMITS (also in the README): string matching and classifiers can be
// evaded. Provenance is defense in depth next to the hard caps, allowlists and
// single-use mandates, which hold even when this layer is fooled.
package provenance

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/Adityaraj-star/leash/internal/policy"
)

// category is one kind of injection signal.
type category struct {
	name   string
	weight int
	re     *regexp.Regexp
}

func cat(name string, weight int, expr string) category {
	return category{name: name, weight: weight, re: regexp.MustCompile(expr)}
}

// The expressions run over normalized text: lower-cased, zero-width characters
// removed, whitespace collapsed to single spaces.
var categories = []category{
	cat("override", 4, `\b(ignore|disregard|forget|override|bypass|skip)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b.{0,30}\b(instructions?|rules?|guidelines?|polic(y|ies)|limits?|constraints?|mandate|restrictions?|safeguards?)`),
	cat("authority claim", 4, `\byou (are|have been|were)( now)? (fully |already )?(authori[sz]ed|permitted|allowed|cleared|approved|pre-?approved)\b|\b(the )?(user|owner|customer|account holder|admin(istrator)?)\b.{0,30}\b(has |have )?(already )?(approved|authori[sz]ed|pre-?approved|consented|confirmed|agreed|granted)\b|\b(approved|authori[sz]ed) by (the )?(user|owner|admin)`),
	cat("concealment", 4, `\b(do not|don't|dont|never|without)\b.{0,25}\b(tell|inform|notify|mention|alert|ask|show|reveal)\b.{0,25}\b(the )?(user|human|owner|customer|operator)`),
	cat("exfiltration", 4, `\b(send|email|forward|post|upload|reveal|leak)\b.{0,40}\b(password|credentials?|api[ -]?key|token|secret|card number|cvv|private key)`),
	cat("fake system message", 3, `\b(system (message|notice|override|alert|prompt|instruction)s?|new instructions?|updated instructions?|admin override|developer mode)\b|<\|?(im_start|im_end|system|endoftext)\|?>|\[/?(system|inst)\]|(^|\s)(system|assistant|developer) ?: `),
	cat("addresses the AI", 2, `\bif you are (an? )?(ai|llm|assistant|agent|language model|bot|automated)\b|\b(attention|note|notice|important|hey)[ ,:]{1,3}(to )?(the )?(ai|assistant|agent|llm|model|bot)\b|\b(ai|llm|language model|ai assistant|ai agent|chatbot|automated agent)s? (reading|processing|browsing|visiting|must|should|will|need)\b`),
	cat("payment instruction", 1, `\b(you (must|should|need to|have to|will|shall)|please|now|immediately|first|also|additionally|instead|then)\b.{0,40}\b(buy|purchase|pay|send|transfer|wire|checkout|check out|complete (the )?(purchase|order|payment)|order)\b`),
}

// Hidden-content markers found in HTML (see HTMLToText).
const hiddenBonus = 2

// Report is the result of scanning one piece of content.
type Report struct {
	Severity policy.Severity
	Score    int
	Matched  []string // category names, in order of weight
	Hidden   bool     // injected-looking text sits in content a human would not see
	Notes    []string
}

// homoglyphs maps look-alike letters from other scripts to the ASCII letter they
// imitate. Attackers write "ignоre previоus instructiоns" with Cyrillic о so a
// keyword filter misses it; folding both the page and the trusted text the same
// way makes the match fail-safe. Keys are lower-case (Normalize lower-cases first).
var homoglyphs = map[rune]rune{
	// Cyrillic
	'\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0445': 'x', '\u0443': 'y',
	'\u0456': 'i', '\u0458': 'j', '\u0455': 's', '\u0501': 'd', '\u04bb': 'h', '\u051b': 'q', '\u051d': 'w',
	// Greek
	'\u03bf': 'o', '\u03b1': 'a', '\u03bd': 'v', '\u03c1': 'p', '\u03b9': 'i', '\u03ba': 'k', '\u03c5': 'u',
	// dotless i, long s
	'\u0131': 'i', '\u017f': 's',
}

// fold maps a rune to the plain ASCII character it imitates, if any: full-width
// forms, mathematical alphanumerics (bold, italic, script, fraktur, ...) and the
// common look-alike letters above.
func fold(r rune) rune {
	switch {
	case r >= '\uff01' && r <= '\uff5e': // full-width ASCII
		return r - 0xfee0
	case r >= 0x1d400 && r <= 0x1d6a3: // mathematical alphabets: 52 letters per style
		i := (r - 0x1d400) % 52
		if i < 26 {
			return 'A' + i
		}
		return 'a' + (i - 26)
	case r >= 0x1d7ce && r <= 0x1d7ff: // mathematical digits
		return '0' + (r-0x1d7ce)%10
	}
	if m, ok := homoglyphs[r]; ok {
		return m
	}
	return r
}

// Normalize prepares text for matching: look-alike characters folded to ASCII,
// lower-case, no zero-width or formatting characters, collapsed whitespace.
func Normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		switch {
		case r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\u2060' || r == '\ufeff' || r == '\u00ad':
			continue // zero-width / soft hyphen: used to split keywords
		case unicode.Is(unicode.Cf, r): // bidi controls and other invisible formatting
			continue
		case unicode.IsSpace(r):
			if !lastSpace {
				b.WriteByte(' ')
			}
			lastSpace = true
			continue
		}
		lastSpace = false
		b.WriteRune(unicode.ToLower(fold(unicode.ToLower(r))))
	}
	return strings.TrimSpace(b.String())
}

// hasInvisible reports whether s contains characters used to hide text.
func hasInvisible(s string) bool {
	for _, r := range s {
		if r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\u2060' || r == '\ufeff' || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

func scoreText(text string) (score int, matched []string) {
	n := Normalize(text)
	for _, c := range categories {
		if c.re.MatchString(n) {
			score += c.weight
			matched = append(matched, c.name)
		}
	}
	return score, matched
}

func severity(score int) policy.Severity {
	switch {
	case score >= 4:
		return policy.SeverityHigh
	case score >= 2:
		return policy.SeverityMedium
	case score >= 1:
		return policy.SeverityLow
	}
	return policy.SeverityNone
}

// Scan looks for instructions aimed at an AI agent in visible text and in text
// that was hidden from human readers.
func Scan(visible string, hidden []string) Report {
	score, matched := scoreText(visible)
	hiddenHit := false
	for _, h := range hidden {
		hs, hm := scoreText(h)
		if hs > 0 {
			hiddenHit = true
			score += hs + hiddenBonus
			matched = append(matched, "hidden: "+strings.Join(hm, ", "))
		}
	}
	r := Report{Score: score, Hidden: hiddenHit}
	// Invisible characters inside otherwise instruction-looking text mean someone is evading a filter.
	if hasInvisible(visible) && score > 0 {
		r.Score += 2
		matched = append(matched, "invisible characters used to split words")
	}
	r.Severity = severity(r.Score)
	r.Matched = matched
	if len(matched) > 0 {
		r.Notes = append(r.Notes, "signals: "+strings.Join(matched, "; "))
	}
	return r
}
