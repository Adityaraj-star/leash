package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func appendN(t *testing.T, l *Ledger, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := l.Append("e", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFileStoreRepairsATornFinalLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	pub, priv, _ := GenerateKey()
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := New(s, priv, fixedClock())
	appendN(t, l, 3)
	s.Close()

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":4,"ts":"2026-10-1`) // power loss mid-write
	f.Close()

	s2, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("a torn final line must not stop startup: %v", err)
	}
	defer s2.Close()
	if s2.Repaired() == 0 {
		t.Error("expected the repair to be reported")
	}
	l2, err := New(s2, priv, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l2, 2) // the chain continues from the last GOOD entry
	entries, err := l2.Entries()
	if err != nil || len(entries) != 5 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	if res := Verify(entries, pub, nil); !res.OK {
		t.Fatalf("chain must verify after repair: %+v", res)
	}
}

func TestFileStoreKeepsAValidLastLineThatLostItsNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	pub, priv, _ := GenerateKey()
	s, _ := OpenFileStore(path)
	l, _ := New(s, priv, fixedClock())
	appendN(t, l, 2)
	s.Close()
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, data[:len(data)-1], 0o600); err != nil { // drop the final \n
		t.Fatal(err)
	}
	s2, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Repaired() != 0 {
		t.Error("a complete entry must not be discarded")
	}
	l2, _ := New(s2, priv, fixedClock())
	appendN(t, l2, 1)
	entries, _ := l2.Entries()
	if len(entries) != 3 || !Verify(entries, pub, nil).OK {
		t.Fatalf("entries=%d", len(entries))
	}
}

func TestFileStoreStillRejectsCorruptionInTheMiddle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	_, priv, _ := GenerateKey()
	s, _ := OpenFileStore(path)
	l, _ := New(s, priv, fixedClock())
	appendN(t, l, 3)
	s.Close()
	data, _ := os.ReadFile(path)
	// Break the first line but keep it newline-terminated: that is damage, not a torn write.
	data[5] = '#'
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("corruption in the middle of the file must stop startup")
	}
}

func TestFileStoreFailsClosedWhenARollbackIsImpossible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	_, priv, _ := GenerateKey()
	s, _ := OpenFileStore(path)
	l, _ := New(s, priv, fixedClock())
	appendN(t, l, 1)
	s.f.Close() // simulate a dead disk handle: the write fails and so does the rollback
	if _, err := l.Append("e", nil); err == nil {
		t.Fatal("expected the append to fail")
	}
	if _, err := l.Append("e", nil); !errors.Is(err, ErrStoreBroken) {
		t.Fatalf("a broken store must refuse further appends, got %v", err)
	}
}

func TestLoadOrCreateKeyPersistsAndReopensTheLedger(t *testing.T) {
	dir := t.TempDir()
	keyPath, logPath := filepath.Join(dir, "ledger.key"), filepath.Join(dir, "ledger.jsonl")

	pub1, priv1, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := OpenFileStore(logPath)
	l, _ := New(s, priv1, fixedClock())
	appendN(t, l, 3)
	s.Close()

	pub2, priv2, err := LoadOrCreateKey(keyPath) // a restart
	if err != nil {
		t.Fatal(err)
	}
	if !pub1.Equal(pub2) {
		t.Fatal("the key must be stable across restarts")
	}
	s2, _ := OpenFileStore(logPath)
	defer s2.Close()
	l2, err := New(s2, priv2, fixedClock())
	if err != nil {
		t.Fatalf("the ledger must reopen with the persisted key: %v", err)
	}
	entries, _ := l2.Entries()
	if !Verify(entries, pub2, nil).OK {
		t.Fatal("verification must pass after restart")
	}
}

func TestLoadOrCreateKeyRefusesUnsafeOrBrokenFiles(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(bad, []byte("not hex\n"), 0o600)
	if _, _, err := LoadOrCreateKey(bad); err == nil {
		t.Error("a malformed key file must be refused")
	}
	if _, _, err := LoadOrCreateKey(""); err == nil {
		t.Error("an empty path must be refused")
	}
	if runtime.GOOS == "windows" {
		return
	}
	open := filepath.Join(dir, "open.key")
	if _, _, err := LoadOrCreateKey(open); err != nil {
		t.Fatal(err)
	}
	os.Chmod(open, 0o644)
	if _, _, err := LoadOrCreateKey(open); err == nil {
		t.Error("a key file readable by others must be refused")
	}
}
