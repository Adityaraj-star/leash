package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrConflict means an appended entry does not extend the current head.
var ErrConflict = errors.New("ledger: entry does not extend the chain head")

// ErrStoreBroken means an earlier write failed and the file could not be rolled
// back to its last good state. The store refuses further appends (fail closed)
// until the process is restarted, which repairs a torn tail on open.
var ErrStoreBroken = errors.New("ledger: store is broken after a failed write; restart to repair")

// MemStore is an in-memory Store for tests and local demos.
type MemStore struct {
	mu      sync.Mutex
	entries []Entry
}

func NewMemStore() *MemStore { return &MemStore{} }

func checkLinks(prev Entry, hasPrev bool, e Entry) error {
	wantSeq, wantPrev := uint64(1), GenesisHash
	if hasPrev {
		wantSeq, wantPrev = prev.Seq+1, prev.Hash
	}
	if e.Seq != wantSeq || e.PrevHash != wantPrev {
		return fmt.Errorf("%w: got seq=%d, want seq=%d", ErrConflict, e.Seq, wantSeq)
	}
	return nil
}

func (m *MemStore) Append(e Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var last Entry
	has := len(m.entries) > 0
	if has {
		last = m.entries[len(m.entries)-1]
	}
	if err := checkLinks(last, has, e); err != nil {
		return err
	}
	m.entries = append(m.entries, e)
	return nil
}

func (m *MemStore) Last() (Entry, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.entries) == 0 {
		return Entry{}, false, nil
	}
	return m.entries[len(m.entries)-1], true, nil
}

func (m *MemStore) All() ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entry, len(m.entries))
	copy(out, m.entries)
	return out, nil
}

// FileStore is a durable append-only JSON-lines Store. All() re-reads the file
// so verification always sees what is actually on disk.
//
// Crash safety: a power cut can leave a partially written final line. That tail
// was never acknowledged (Append returns only after fsync), so OpenFileStore
// drops it and reports how many bytes it removed (see Repaired). A malformed line
// anywhere else is real corruption and is an error. A failed Append rolls the
// file back to its last good length so no half entry stays behind.
//
// This stands in for the planned SQLite store until modernc.org/sqlite can be
// added; the Store interface is the seam.
type FileStore struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	last     Entry
	has      bool
	size     int64 // length of the file up to the end of the last good line
	repaired int64
	broken   bool
}

// parseLog parses JSON-lines data. goodLen is the length of the prefix that
// consists of complete, valid lines (every line newline-terminated). tornTail is
// true when the data ends with an unterminated, unparsable fragment.
func parseLog(path string, data []byte) (entries []Entry, goodLen int64, tornTail bool, err error) {
	pos, line := 0, 0
	for pos < len(data) {
		line++
		nl := bytes.IndexByte(data[pos:], '\n')
		terminated := nl >= 0
		var raw []byte
		next := len(data)
		if terminated {
			raw, next = data[pos:pos+nl], pos+nl+1
		} else {
			raw = data[pos:]
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			pos = next
			goodLen = int64(next)
			continue
		}
		var e Entry
		if jerr := json.Unmarshal(raw, &e); jerr != nil {
			if !terminated {
				return entries, goodLen, true, nil // torn final write
			}
			return nil, 0, false, fmt.Errorf("ledger file %s line %d: %w", path, line, jerr)
		}
		entries = append(entries, e)
		pos = next
		goodLen = int64(next)
		if !terminated {
			// A valid last line that lost only its newline: keep it, and the
			// caller restores the newline.
			return entries, goodLen, false, nil
		}
	}
	return entries, goodLen, false, nil
}

// OpenFileStore opens (or creates) the log at path, repairing a torn final line.
func OpenFileStore(path string) (*FileStore, error) {
	_, statErr := os.Stat(path)
	created := os.IsNotExist(statErr)
	// Not O_APPEND: on Windows a file opened for append cannot be truncated, and
	// the store needs Truncate to repair a torn tail and to roll back a failed
	// write. It tracks the end of the file itself and writes there (WriteAt).
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	s := &FileStore{path: path, f: f}
	if created {
		syncDir(filepath.Dir(path)) // make the new file's directory entry durable
	}
	data, err := os.ReadFile(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	entries, good, torn, err := parseLog(path, data)
	if err != nil {
		f.Close()
		return nil, err
	}
	if torn {
		s.repaired = int64(len(data)) - good
		if err := f.Truncate(good); err != nil {
			f.Close()
			return nil, fmt.Errorf("ledger: repairing torn tail of %s: %w", path, err)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
	} else if good == int64(len(data)) && len(data) > 0 && data[len(data)-1] != '\n' {
		// Complete last entry, newline missing: restore it so the next append
		// starts on its own line.
		if _, err := f.WriteAt([]byte{'\n'}, int64(len(data))); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
		good++
	}
	s.size = good
	if n := len(entries); n > 0 {
		s.last, s.has = entries[n-1], true
	}
	return s, nil
}

// Repaired reports how many bytes of a torn final line OpenFileStore removed
// (0 when the file was intact). Log it so an operator knows a crash happened.
func (s *FileStore) Repaired() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repaired
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func (s *FileStore) readAll() ([]Entry, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	entries, _, torn, err := parseLog(s.path, data)
	if err != nil {
		return nil, err
	}
	if torn {
		return nil, fmt.Errorf("ledger file %s ends with a partial line", s.path)
	}
	return entries, nil
}

func (s *FileStore) Append(e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken {
		return ErrStoreBroken
	}
	if err := checkLinks(s.last, s.has, e); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, werr := s.f.WriteAt(b, s.size)
	if werr == nil {
		werr = s.f.Sync()
	}
	if werr != nil {
		// Roll back so no half-written (or unsynced) entry stays on disk and the
		// next append reuses the same sequence number cleanly.
		if terr := s.f.Truncate(s.size); terr != nil {
			s.broken = true
			return fmt.Errorf("%w (write: %v; rollback: %v)", ErrStoreBroken, werr, terr)
		}
		_ = s.f.Sync()
		return werr
	}
	s.size += int64(len(b))
	s.last, s.has = e, true
	return nil
}

func (s *FileStore) Last() (Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last, s.has, nil
}

func (s *FileStore) All() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readAll()
}

func (s *FileStore) Close() error { return s.f.Close() }
