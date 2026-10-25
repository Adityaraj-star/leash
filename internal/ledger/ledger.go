// Package ledger implements Leash's flight recorder: an append-only,
// hash-chained, server-signed log.
//
// Design notes:
//   - Every entry's hash covers seq, timestamp, type, the previous hash and the
//     payload hash (length-prefixed, so fields cannot be shifted into each
//     other). The plan's SHA-256(prev || payload) would leave type/ts
//     unauthenticated; this covers them.
//   - The payload is stored as the exact compact JSON text that was hashed, so
//     verification never needs to re-canonicalize anything.
//   - Entries are signed (Ed25519) so an attacker who can rewrite the store but
//     does not hold the server key cannot forge a consistent chain.
//   - Tail truncation cannot be detected from the log alone. That is what the
//     signed Checkpoint is for: export it with every evidence bundle.
package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"
)

// GenesisHash is the prev_hash of the first entry.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

const (
	hashDomain = "leash.ledger.v1"
	sigDomain  = "leash.ledger.sig.v1"
	cpDomain   = "leash.ledger.checkpoint.v1"

	maxTypeLen    = 64
	maxPayloadLen = 1 << 20
)

// Entry is one record in the chain.
type Entry struct {
	Seq         uint64 `json:"seq"`
	TS          string `json:"ts"`
	Type        string `json:"type"`
	Payload     string `json:"payload"` // compact JSON text, exactly as hashed
	PayloadHash string `json:"payload_hash"`
	PrevHash    string `json:"prev_hash"`
	Hash        string `json:"hash"`
	Sig         string `json:"server_sig"`
}

// Checkpoint is a signed statement "the log had Seq entries and head hash Hash".
type Checkpoint struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
	TS   string `json:"ts"`
	Sig  string `json:"sig"`
}

// Result is the outcome of Verify.
type Result struct {
	OK       bool   `json:"ok"`
	Entries  int    `json:"entries"`
	BrokenAt uint64 `json:"broken_at,omitempty"` // seq of first bad entry (0 = n/a)
	Reason   string `json:"reason,omitempty"`
}

// Store persists entries. Implementations must be append-only: there is
// deliberately no update or delete. (A SQLite implementation should also
// install triggers rejecting UPDATE and DELETE.)
type Store interface {
	Append(e Entry) error
	Last() (Entry, bool, error)
	All() ([]Entry, error)
}

// Ledger appends and verifies entries.
type Ledger struct {
	mu    sync.Mutex
	store Store
	priv  ed25519.PrivateKey
	now   func() time.Time
	head  Entry
	has   bool
}

// GenerateKey creates a fresh Ed25519 server key.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// New opens a ledger over store, resuming from its current head.
func New(store Store, priv ed25519.PrivateKey, now func() time.Time) (*Ledger, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("ledger: invalid signing key")
	}
	if now == nil {
		now = time.Now
	}
	l := &Ledger{store: store, priv: priv, now: now}
	last, ok, err := store.Last()
	if err != nil {
		return nil, fmt.Errorf("ledger: reading head: %w", err)
	}
	l.head, l.has = last, ok
	return l, nil
}

// PublicKey returns the verification key.
func (l *Ledger) PublicKey() ed25519.PublicKey {
	return l.priv.Public().(ed25519.PublicKey)
}

func writeLP(w io.Writer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	w.Write(n[:])
	w.Write(b)
}

func computeHash(seq uint64, ts, typ string, prevHash, payloadHash []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(hashDomain))
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	h.Write(s[:])
	writeLP(h, []byte(ts))
	writeLP(h, []byte(typ))
	writeLP(h, prevHash)
	writeLP(h, payloadHash)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func entrySigMessage(hash [32]byte) []byte {
	return append([]byte(sigDomain), hash[:]...)
}

func checkpointMessage(seq uint64, hash, ts string) []byte {
	var b bytes.Buffer
	b.WriteString(cpDomain)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	b.Write(s[:])
	writeLP(&b, []byte(hash))
	writeLP(&b, []byte(ts))
	return b.Bytes()
}

// Append marshals payload, chains it to the head, signs it and stores it.
func (l *Ledger) Append(typ string, payload any) (Entry, error) {
	if typ == "" || len(typ) > maxTypeLen || !utf8.ValidString(typ) {
		return Entry{}, errors.New("ledger: invalid entry type")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Entry{}, fmt.Errorf("ledger: marshal payload: %w", err)
	}
	if len(raw) > maxPayloadLen || !utf8.Valid(raw) {
		return Entry{}, errors.New("ledger: payload too large or not valid UTF-8")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	prev := GenesisHash
	seq := uint64(1)
	if l.has {
		prev = l.head.Hash
		seq = l.head.Seq + 1
	}
	prevB, _ := hex.DecodeString(prev)
	ph := sha256.Sum256(raw)
	ts := l.now().UTC().Format(time.RFC3339Nano)
	h := computeHash(seq, ts, typ, prevB, ph[:])
	e := Entry{
		Seq:         seq,
		TS:          ts,
		Type:        typ,
		Payload:     string(raw),
		PayloadHash: hex.EncodeToString(ph[:]),
		PrevHash:    prev,
		Hash:        hex.EncodeToString(h[:]),
		Sig:         base64.StdEncoding.EncodeToString(ed25519.Sign(l.priv, entrySigMessage(h))),
	}
	if err := l.store.Append(e); err != nil {
		return Entry{}, fmt.Errorf("ledger: store append: %w", err)
	}
	l.head, l.has = e, true
	return e, nil
}

// Entries returns all entries in order.
func (l *Ledger) Entries() ([]Entry, error) { return l.store.All() }

// Checkpoint returns a signed statement of the current head.
func (l *Ledger) Checkpoint() Checkpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := Checkpoint{Hash: GenesisHash, TS: l.now().UTC().Format(time.RFC3339Nano)}
	if l.has {
		cp.Seq, cp.Hash = l.head.Seq, l.head.Hash
	}
	cp.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(l.priv, checkpointMessage(cp.Seq, cp.Hash, cp.TS)))
	return cp
}

// Verify recomputes the entire chain from the store. If cp is non-nil it is
// also checked, which detects truncation and rewritten history.
func (l *Ledger) Verify(cp *Checkpoint) Result {
	entries, err := l.store.All()
	if err != nil {
		return Result{Reason: "cannot read ledger: " + err.Error()}
	}
	return Verify(entries, l.PublicKey(), cp)
}

// Verify checks entries (and optionally a checkpoint) against pub. It is a
// pure function so an auditor can run it on an exported evidence bundle.
func Verify(entries []Entry, pub ed25519.PublicKey, cp *Checkpoint) Result {
	fail := func(seq uint64, format string, a ...any) Result {
		return Result{OK: false, Entries: len(entries), BrokenAt: seq, Reason: fmt.Sprintf(format, a...)}
	}
	if len(pub) != ed25519.PublicKeySize {
		return fail(0, "invalid verification key")
	}
	prev := GenesisHash
	for i, e := range entries {
		want := uint64(i + 1)
		if e.Seq != want {
			return fail(want, "entry %d: sequence is %d (entry deleted, reordered or inserted)", want, e.Seq)
		}
		if e.PrevHash != prev {
			return fail(want, "entry %d: prev_hash does not match the previous entry (chain broken)", want)
		}
		ph := sha256.Sum256([]byte(e.Payload))
		if hex.EncodeToString(ph[:]) != e.PayloadHash {
			return fail(want, "entry %d: payload was modified", want)
		}
		prevB, err1 := hex.DecodeString(e.PrevHash)
		phB, err2 := hex.DecodeString(e.PayloadHash)
		if err1 != nil || err2 != nil || len(prevB) != 32 || len(phB) != 32 {
			return fail(want, "entry %d: malformed hash field", want)
		}
		h := computeHash(e.Seq, e.TS, e.Type, prevB, phB)
		if hex.EncodeToString(h[:]) != e.Hash {
			return fail(want, "entry %d: timestamp, type or hash fields were modified", want)
		}
		sig, err := base64.StdEncoding.DecodeString(e.Sig)
		if err != nil || !ed25519.Verify(pub, entrySigMessage(h), sig) {
			return fail(want, "entry %d: server signature invalid (entry not written by this server)", want)
		}
		prev = e.Hash
	}
	if cp != nil {
		sig, err := base64.StdEncoding.DecodeString(cp.Sig)
		if err != nil || !ed25519.Verify(pub, checkpointMessage(cp.Seq, cp.Hash, cp.TS), sig) {
			return fail(0, "checkpoint signature invalid")
		}
		if cp.Seq > uint64(len(entries)) {
			return fail(0, "ledger truncated: it has %d entries but the signed checkpoint covers %d", len(entries), cp.Seq)
		}
		wantHash := GenesisHash
		if cp.Seq > 0 {
			wantHash = entries[cp.Seq-1].Hash
		}
		if wantHash != cp.Hash {
			return fail(cp.Seq, "history before the checkpoint was rewritten")
		}
	}
	return Result{OK: true, Entries: len(entries)}
}
