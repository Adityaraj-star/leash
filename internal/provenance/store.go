package provenance

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/Adityaraj-star/leash/internal/policy"
)

// Trust labels. Everything fetched from the web is untrusted, always.
type Trust string

const UntrustedWeb Trust = "untrusted_web"

const maxStoredText = 64 << 10

// Memory bounds. An agent that browses without end must not exhaust the server,
// and eviction must never be a way to make a poisoned page disappear, so:
//   - benign pages are evicted before flagged ones, and
//   - a session's worst severity is remembered separately and survives eviction.
const (
	maxPagesPerSession = 64
	maxTotalPages      = 4000
	maxTrackedSessions = 5000
)

// Evidence is one page the agent read through leash.browse.
type Evidence struct {
	ID        string          `json:"id"`
	Session   string          `json:"session"`
	URL       string          `json:"url"`
	Title     string          `json:"title,omitempty"`
	Trust     Trust           `json:"trust"`
	Text      string          `json:"text"` // exactly what the agent was shown
	Hidden    []string        `json:"hidden,omitempty"`
	Severity  policy.Severity `json:"severity"`
	Notes     []string        `json:"notes,omitempty"`
	SHA256    string          `json:"sha256"`
	FetchedAt time.Time       `json:"fetched_at"`
}

// Store keeps browse evidence, grouped by agent session.
type Store struct {
	mu        sync.Mutex
	now       func() time.Time
	byID      map[string]Evidence
	bySession map[string][]string
	order     []string                   // every stored id, oldest first
	worst     map[string]policy.Severity // per session, never decreases
	lastSeen  map[string]time.Time
}

// NewStore creates an empty store.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		now: now, byID: map[string]Evidence{}, bySession: map[string][]string{},
		worst: map[string]policy.Severity{}, lastSeen: map[string]time.Time{},
	}
}

// dropLocked removes one page from every index (not from worst).
func (s *Store) dropLocked(id string) {
	ev, ok := s.byID[id]
	if !ok {
		return
	}
	delete(s.byID, id)
	ids := s.bySession[ev.Session]
	for i, x := range ids {
		if x == id {
			s.bySession[ev.Session] = append(ids[:i:i], ids[i+1:]...)
			break
		}
	}
	if len(s.bySession[ev.Session]) == 0 {
		delete(s.bySession, ev.Session)
	}
	for i, x := range s.order {
		if x == id {
			s.order = append(s.order[:i:i], s.order[i+1:]...)
			break
		}
	}
}

// victimLocked picks the page to evict from ids: the oldest benign one, else the
// oldest. The page just added (keep) is never chosen, so the agent always gets the
// evidence id it was just handed.
func (s *Store) victimLocked(ids []string, keep string) string {
	victim := ""
	for _, id := range ids {
		if id == keep {
			continue
		}
		if victim == "" {
			victim = id
		}
		if s.byID[id].Severity == policy.SeverityNone {
			return id
		}
	}
	return victim
}

// forgetSessionLocked drops a whole session (its pages and its remembered severity).
func (s *Store) forgetSessionLocked(session string) {
	for _, id := range append([]string(nil), s.bySession[session]...) {
		s.dropLocked(id)
	}
	delete(s.bySession, session)
	delete(s.worst, session)
	delete(s.lastSeen, session)
}

func newEvidenceID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "ev_" + hex.EncodeToString(b[:])
}

// Add scans and stores a fetched page. isHTML selects HTML-to-text conversion.
func (s *Store) Add(session, url, body string, isHTML bool) Evidence {
	var text string
	var hidden []string
	title := ""
	if isHTML {
		text, hidden = HTMLToText(body)
		title = Title(body)
	} else {
		text = strings.TrimSpace(body)
	}
	if len(text) > maxStoredText {
		text = text[:maxStoredText]
	}
	rep := Scan(text, hidden)
	sum := sha256.Sum256([]byte(body))
	ev := Evidence{
		ID: newEvidenceID(), Session: session, URL: url, Title: title, Trust: UntrustedWeb,
		Text: text, Hidden: hidden, Severity: rep.Severity, Notes: rep.Notes,
		SHA256: hex.EncodeToString(sum[:]), FetchedAt: s.now().UTC(),
	}
	s.mu.Lock()
	s.byID[ev.ID] = ev
	s.bySession[session] = append(s.bySession[session], ev.ID)
	s.order = append(s.order, ev.ID)
	s.lastSeen[session] = ev.FetchedAt
	if ev.Severity > s.worst[session] {
		s.worst[session] = ev.Severity
	}
	for len(s.bySession[session]) > maxPagesPerSession {
		v := s.victimLocked(s.bySession[session], ev.ID)
		if v == "" {
			break
		}
		s.dropLocked(v)
	}
	for len(s.byID) > maxTotalPages {
		v := s.victimLocked(s.order, ev.ID)
		if v == "" {
			break
		}
		s.dropLocked(v)
	}
	for len(s.lastSeen) > maxTrackedSessions {
		var oldest string
		var oldestAt time.Time
		for k, at := range s.lastSeen {
			if k != session && (oldest == "" || at.Before(oldestAt)) {
				oldest, oldestAt = k, at
			}
		}
		if oldest == "" {
			break
		}
		s.forgetSessionLocked(oldest)
	}
	s.mu.Unlock()
	return ev
}

// SessionWorst is the worst injection severity the session has EVER read. It
// survives eviction of the pages themselves, so flooding a session with harmless
// pages cannot push a poisoned one out of the check.
func (s *Store) SessionWorst(session string) policy.Severity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.worst[session]
}

// Get returns one piece of evidence.
func (s *Store) Get(id string) (Evidence, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev, ok := s.byID[id]
	return ev, ok
}

// Session returns everything the given session has read, oldest first.
func (s *Store) Session(session string) []Evidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := s.bySession[session]
	out := make([]Evidence, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.byID[id])
	}
	return out
}

// Reset clears all evidence (demo reset).
func (s *Store) Reset() {
	s.mu.Lock()
	s.byID = map[string]Evidence{}
	s.bySession = map[string][]string{}
	s.order = nil
	s.worst = map[string]policy.Severity{}
	s.lastSeen = map[string]time.Time{}
	s.mu.Unlock()
}
