package provenance

import (
	"html"
	"regexp"
	"strings"
)

var (
	reScript  = regexp.MustCompile(`(?is)<(script|style|noscript|template)\b[^>]*>.*?</(script|style|noscript|template)>`)
	reComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	// A tag starts with "<" plus a letter, "/", "!" or "?" (HTML spec). Anything
	// else, such as the chat-template marker <|im_start|>, is plain text that a
	// browsing tool would pass to the model, so the detector must see it too.
	reTag        = regexp.MustCompile(`(?s)<(?:/?[a-zA-Z][^>]*|![^>]*|\?[^>]*)>`)
	reBlock      = regexp.MustCompile(`(?i)</?(p|div|br|li|ul|ol|tr|td|th|h[1-6]|section|article|header|footer|main|table|form)\b[^>]*>`)
	reOpenTag    = regexp.MustCompile(`(?is)<([a-z][a-z0-9]*)\b([^>]*)>`)
	reHiddenAttr = regexp.MustCompile(`(?is)(?:style\s*=\s*(?:"[^"]*"|'[^']*')[^>]*)?` + `(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\b|(?:left|top|text-indent)\s*:\s*-\d{3,}|color\s*:\s*(?:#fff(?:fff)?|white)\b|(?:height|width)\s*:\s*0(?:px)?\b|\bhidden\b|aria-hidden\s*=\s*"?true)`)
	reTitle      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// HTMLToText converts HTML to the plain text a naive agent browsing tool would
// hand to a model, and separately returns the fragments a human looking at the
// rendered page would NOT see (comments, display:none, zero-size or
// white-on-white text, off-screen text, aria-hidden). Hidden fragments are
// still part of the returned text: that is exactly why hidden injections work
// against unprotected agents.
//
// This is a deliberately small tokenizer, not a browser. It does not handle
// nested hidden elements of the same tag name or CSS in external stylesheets;
// those are listed as limits in the threat model.
func HTMLToText(src string) (text string, hidden []string) {
	s := reScript.ReplaceAllString(src, " ")
	for _, m := range reComment.FindAllStringSubmatch(s, -1) {
		if t := squash(html.UnescapeString(m[1])); t != "" {
			hidden = append(hidden, t)
		}
	}
	s = reComment.ReplaceAllString(s, " "+"\n")
	// Keep the hidden text visible to the model (as a naive extractor would),
	// but record it separately for the detector.
	hidden = append(hidden, hiddenElements(s)...)
	s = reBlock.ReplaceAllString(s, "\n")
	s = reTag.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return tidy(s), hidden
}

// Title extracts the page <title>, if any.
func Title(src string) string {
	if m := reTitle.FindStringSubmatch(src); m != nil {
		return strings.TrimSpace(html.UnescapeString(reTag.ReplaceAllString(m[1], " ")))
	}
	return ""
}

// squash collapses all whitespace runs (left behind by removed tags) to one space.
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

func tidy(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	for _, l := range lines {
		l = strings.Join(strings.Fields(l), " ")
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

var voidTags = map[string]bool{"br": true, "img": true, "input": true, "hr": true, "meta": true, "link": true, "area": true, "base": true, "col": true, "embed": true, "source": true, "wbr": true}

// hiddenElements returns the text inside elements whose attributes hide them
// from a human reader, matching nested tags of the same name by depth counting
// (Go's regexp has no backreferences).
func hiddenElements(s string) []string {
	var out []string
	for _, m := range reOpenTag.FindAllStringSubmatchIndex(s, -1) {
		name := strings.ToLower(s[m[2]:m[3]])
		attrs := s[m[4]:m[5]]
		if voidTags[name] || !reHiddenAttr.MatchString(attrs) {
			continue
		}
		bodyStart := m[1]
		depth, i := 1, bodyStart
		bodyEnd := len(s)
		low := strings.ToLower(s)
		open, close := "<"+name, "</"+name
		for i < len(s) {
			no := strings.Index(low[i:], open)
			nc := strings.Index(low[i:], close)
			if nc < 0 {
				break
			}
			if no >= 0 && no < nc {
				// an inner opening tag of the same name (guard against prefixes like <p vs <pre)
				if j := i + no + len(open); j < len(low) && (low[j] == ' ' || low[j] == '>' || low[j] == '/' || low[j] == '\n' || low[j] == '\t') {
					depth++
				}
				i += no + len(open)
				continue
			}
			depth--
			if depth == 0 {
				bodyEnd = i + nc
				break
			}
			i += nc + len(close)
		}
		inner := squash(html.UnescapeString(reTag.ReplaceAllString(s[bodyStart:bodyEnd], " ")))
		if inner != "" {
			out = append(out, inner)
		}
	}
	return out
}
