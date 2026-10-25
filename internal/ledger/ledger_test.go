package ledger

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func newLedger(t testing.TB) (*Ledger, *MemStore) {
	t.Helper()
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	st := NewMemStore()
	l, err := New(st, priv, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	return l, st
}

func fill(t testing.TB, l *Ledger, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := l.Append("decision", map[string]any{"i": i, "note": "ok <&> é"}); err != nil {
			t.Fatal(err)
		}
	}
}

func mustOK(t *testing.T, r Result) {
	t.Helper()
	if !r.OK {
		t.Fatalf("expected OK, got %+v", r)
	}
}

func mustFail(t *testing.T, r Result, wantSeq uint64, contains string) {
	t.Helper()
	if r.OK {
		t.Fatalf("expected failure (%s) but chain verified", contains)
	}
	if wantSeq != 0 && r.BrokenAt != wantSeq {
		t.Errorf("BrokenAt=%d want %d (%s)", r.BrokenAt, wantSeq, r.Reason)
	}
	if !strings.Contains(r.Reason, contains) {
		t.Errorf("reason %q does not contain %q", r.Reason, contains)
	}
}

func TestAppendAndVerify(t *testing.T) {
	l, _ := newLedger(t)
	mustOK(t, l.Verify(nil)) // empty ledger verifies
	fill(t, l, 5)
	r := l.Verify(nil)
	mustOK(t, r)
	if r.Entries != 5 {
		t.Errorf("entries=%d", r.Entries)
	}
	es, _ := l.Entries()
	if es[0].PrevHash != GenesisHash || es[1].PrevHash != es[0].Hash {
		t.Error("chain not linked")
	}
}

func TestPayloadIsHashedExactly(t *testing.T) {
	l, _ := newLedger(t)
	e, _ := l.Append("x", map[string]string{"k": "<a href=\"x\">&</a>"})
	sum := sha256.Sum256([]byte(e.Payload))
	if hex.EncodeToString(sum[:]) != e.PayloadHash {
		t.Fatal("payload hash does not cover the stored payload text")
	}
}

func TestTamperPayload(t *testing.T) {
	l, st := newLedger(t)
	fill(t, l, 4)
	st.entries[1].Payload = strings.Replace(st.entries[1].Payload, `"i":1`, `"i":9`, 1)
	mustFail(t, l.Verify(nil), 2, "payload was modified")
}

func TestTamperTypeAndTimestamp(t *testing.T) {
	l, st := newLedger(t)
	fill(t, l, 3)
	st.entries[2].Type = "approved"
	mustFail(t, l.Verify(nil), 3, "modified")

	l2, st2 := newLedger(t)
	fill(t, l2, 3)
	st2.entries[0].TS = "2020-01-01T00:00:00Z"
	mustFail(t, l2.Verify(nil), 1, "modified")
}

func TestDeleteMiddleReorderInsert(t *testing.T) {
	l, st := newLedger(t)
	fill(t, l, 5)
	orig := append([]Entry(nil), st.entries...)

	st.entries = append(append([]Entry(nil), orig[:2]...), orig[3:]...)
	mustFail(t, l.Verify(nil), 3, "sequence")

	st.entries = append([]Entry(nil), orig...)
	st.entries[1], st.entries[2] = st.entries[2], st.entries[1]
	mustFail(t, l.Verify(nil), 2, "sequence")

	st.entries = append(append(append([]Entry(nil), orig[:2]...), orig[1]), orig[2:]...)
	mustFail(t, l.Verify(nil), 3, "sequence")
}

func TestAttackerRecomputesHashesButCannotSign(t *testing.T) {
	l, st := newLedger(t)
	fill(t, l, 3)
	// Attacker rewrites entry 2's payload and re-links the whole chain correctly,
	// but only holds their own key.
	_, evil, _ := GenerateKey()
	forged := NewMemStore()
	fl, _ := New(forged, evil, fixedClock())
	for _, e := range st.entries {
		fl.Append(e.Type, map[string]any{"forged": e.Seq})
	}
	r := Verify(forged.entries, l.PublicKey(), nil)
	mustFail(t, r, 1, "signature invalid")
}

func TestTamperSignature(t *testing.T) {
	l, st := newLedger(t)
	fill(t, l, 2)
	sig, _ := base64.StdEncoding.DecodeString(st.entries[0].Sig)
	sig[0] ^= 1
	st.entries[0].Sig = base64.StdEncoding.EncodeToString(sig)
	mustFail(t, l.Verify(nil), 1, "signature invalid")
}

func TestCheckpointDetectsTruncation(t *testing.T) {
	l, st := newLedger(t)
	fill(t, l, 5)
	cp := l.Checkpoint()
	mustOK(t, l.Verify(&cp))

	st.entries = st.entries[:3] // tail chopped: chain itself still verifies
	mustOK(t, l.Verify(nil))
	mustFail(t, l.Verify(&cp), 0, "truncated")
}

func TestCheckpointDetectsRewrittenHistory(t *testing.T) {
	l, _ := newLedger(t)
	fill(t, l, 3)
	cp := l.Checkpoint()

	// The server key holder (or a bug) rebuilds a different, internally valid
	// history. Only the signed checkpoint can expose that.
	l2, err := New(NewMemStore(), l.priv, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	fill(t, l2, 2)
	l2.Append("decision", map[string]any{"different": true})
	es, _ := l2.Entries()
	mustOK(t, Verify(es, l.PublicKey(), nil))
	mustFail(t, Verify(es, l.PublicKey(), &cp), 3, "rewritten")
}

func TestCheckpointSignatureForged(t *testing.T) {
	l, _ := newLedger(t)
	fill(t, l, 2)
	cp := l.Checkpoint()
	cp.Seq = 1
	mustFail(t, l.Verify(&cp), 0, "checkpoint signature invalid")
}

func TestEmptyLedgerCheckpoint(t *testing.T) {
	l, _ := newLedger(t)
	cp := l.Checkpoint()
	if cp.Seq != 0 || cp.Hash != GenesisHash {
		t.Fatalf("%+v", cp)
	}
	mustOK(t, l.Verify(&cp))
}

func TestAppendValidation(t *testing.T) {
	l, _ := newLedger(t)
	if _, err := l.Append("", 1); err == nil {
		t.Error("empty type accepted")
	}
	if _, err := l.Append(strings.Repeat("a", 65), 1); err == nil {
		t.Error("long type accepted")
	}
	if _, err := l.Append("x", make(chan int)); err == nil {
		t.Error("unmarshalable payload accepted")
	}
}

func TestStoreRejectsNonExtending(t *testing.T) {
	l, st := newLedger(t)
	fill(t, l, 2)
	bad := st.entries[0]
	if err := st.Append(bad); err == nil {
		t.Error("store accepted duplicate seq")
	}
}

func TestConcurrentAppendsStayValid(t *testing.T) {
	l, _ := newLedger(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if _, err := l.Append("evt", map[string]int{"g": g, "i": i}); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	r := l.Verify(nil)
	mustOK(t, r)
	if r.Entries != 200 {
		t.Errorf("entries=%d", r.Entries)
	}
}

func TestFileStorePersistsAndResumes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	_, priv, _ := GenerateKey()

	fs, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := New(fs, priv, fixedClock())
	fill(t, l, 3)
	cp := l.Checkpoint()
	fs.Close()

	fs2, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fs2.Close()
	l2, _ := New(fs2, priv, fixedClock())
	fill(t, l2, 2) // must continue the same chain
	r := l2.Verify(&cp)
	mustOK(t, r)
	if r.Entries != 5 {
		t.Errorf("entries=%d", r.Entries)
	}
}

func TestFileStoreDiskTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	_, priv, _ := GenerateKey()
	fs, _ := OpenFileStore(path)
	defer fs.Close()
	l, _ := New(fs, priv, fixedClock())
	fill(t, l, 4)
	mustOK(t, l.Verify(nil))

	data, _ := os.ReadFile(path)
	edited := strings.Replace(string(data), `\"i\":2`, `\"i\":7`, 1)
	if edited == string(data) {
		t.Fatal("test edit did not apply")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	mustFail(t, l.Verify(nil), 3, "payload was modified")
}

func TestVerifyBadKey(t *testing.T) {
	mustFail(t, Verify(nil, ed25519.PublicKey("short"), nil), 0, "invalid verification key")
}

// FuzzTamper: for arbitrary payloads, a chain verifies, and flipping any single
// byte of any signed field of any entry makes verification fail.
func FuzzTamper(f *testing.F) {
	f.Add("hello", uint8(0), uint8(0), uint8(0))
	f.Add("", uint8(1), uint8(3), uint8(7))
	f.Add("<script>&\"\\u0000", uint8(2), uint8(5), uint8(200))
	f.Fuzz(func(t *testing.T, payload string, which, field, pos uint8) {
		l, st := newLedger(t)
		for i := 0; i < 3; i++ {
			if _, err := l.Append("decision", map[string]any{"v": payload, "i": i}); err != nil {
				t.Fatal(err)
			}
		}
		if r := l.Verify(nil); !r.OK {
			t.Fatalf("untampered chain failed: %+v", r)
		}
		idx := int(which) % len(st.entries)
		e := &st.entries[idx]
		flip := func(s string) string {
			if s == "" {
				return "x"
			}
			b := []byte(s)
			b[int(pos)%len(b)] ^= 0x01
			return string(b)
		}
		switch field % 6 {
		case 0:
			e.Payload = flip(e.Payload)
		case 1:
			e.Type = flip(e.Type)
		case 2:
			e.TS = flip(e.TS)
		case 3:
			e.PrevHash = flip(e.PrevHash)
		case 4:
			e.Hash = flip(e.Hash)
		case 5:
			e.Sig = flip(e.Sig)
		}
		if r := l.Verify(nil); r.OK {
			t.Fatalf("tampering with entry %d field %d went undetected", idx+1, field%6)
		}
	})
}

func ExampleLedger_Verify() {
	_, priv, _ := GenerateKey()
	l, _ := New(NewMemStore(), priv, nil)
	l.Append("request", map[string]string{"merchant": "legitgifts"})
	fmt.Println(l.Verify(nil).OK)
	// Output: true
}
