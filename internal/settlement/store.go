package settlement

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Store persists request snapshots. Each Save writes the full current state of
// one request; on load the last snapshot per ID wins. (The tamper-evident
// history lives in the ledger; this store only lets the process restart.)
type Store interface {
	Save(r *Request) error
	Load() ([]*Request, error)
}

// MemStore keeps nothing across restarts (tests, ephemeral demos).
type MemStore struct{}

func (MemStore) Save(*Request) error       { return nil }
func (MemStore) Load() ([]*Request, error) { return nil, nil }

// FileStore appends JSON-lines snapshots to a file.
//
// Crash safety matches the ledger's store: a partial final line (power cut
// mid-write) was never acknowledged, so OpenFileStore drops it and reports the
// byte count; a bad line anywhere else is corruption and is an error; a failed
// Save rolls the file back to its last good length.
type FileStore struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	size     int64
	repaired int64
	broken   bool
}

// ErrStoreBroken means an earlier write failed and could not be rolled back.
var ErrStoreBroken = errors.New("settlement: store is broken after a failed write; restart to repair")

// parseSnapshots returns the latest snapshot per request (first-seen order) and
// the length of the prefix made of complete, valid lines. tornTail is true when
// the data ends in an unterminated, unparsable fragment.
func parseSnapshots(data []byte) (out []*Request, goodLen int64, tornTail bool, err error) {
	var order []string
	latest := map[string]*Request{}
	pos := 0
	for pos < len(data) {
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
			pos, goodLen = next, int64(next)
			continue
		}
		var r Request
		if jerr := json.Unmarshal(raw, &r); jerr != nil {
			if !terminated {
				tornTail = true
				break
			}
			return nil, 0, false, fmt.Errorf("settlement: corrupt store line: %w", jerr)
		}
		if _, seen := latest[r.ID]; !seen {
			order = append(order, r.ID)
		}
		cp := r
		latest[r.ID] = &cp
		pos, goodLen = next, int64(next)
	}
	out = make([]*Request, 0, len(order))
	for _, id := range order {
		out = append(out, latest[id])
	}
	return out, goodLen, tornTail, nil
}

// OpenFileStore opens (creating if needed) a snapshot file for appending and
// repairs a torn final line.
func OpenFileStore(path string) (*FileStore, error) {
	// Not O_APPEND: on Windows a file opened for append cannot be truncated, and
	// the store needs Truncate to repair a torn tail and to roll back a failed
	// write. It tracks the end of the file itself and writes there (WriteAt).
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("settlement: open store: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	_, good, torn, err := parseSnapshots(data)
	if err != nil {
		f.Close()
		return nil, err
	}
	s := &FileStore{path: path, f: f, size: good}
	if torn {
		s.repaired = int64(len(data)) - good
		if err := f.Truncate(good); err != nil {
			f.Close()
			return nil, fmt.Errorf("settlement: repairing torn tail of %s: %w", path, err)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
	} else if len(data) > 0 && data[len(data)-1] != '\n' {
		// Complete final snapshot that lost only its newline.
		if _, err := f.WriteAt([]byte{'\n'}, int64(len(data))); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
		s.size = int64(len(data)) + 1
	}
	return s, nil
}

// Repaired reports how many bytes of a torn final line OpenFileStore removed.
func (s *FileStore) Repaired() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repaired
}

// Save appends one snapshot and syncs it to disk. On failure the file is rolled
// back so no partial snapshot is left behind.
func (s *FileStore) Save(r *Request) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken {
		return ErrStoreBroken
	}
	_, werr := s.f.WriteAt(b, s.size)
	if werr == nil {
		werr = s.f.Sync()
	}
	if werr != nil {
		if terr := s.f.Truncate(s.size); terr != nil {
			s.broken = true
			return fmt.Errorf("%w (write: %v; rollback: %v)", ErrStoreBroken, werr, terr)
		}
		_ = s.f.Sync()
		return werr
	}
	s.size += int64(len(b))
	return nil
}

// Load returns the latest snapshot of every request, in first-seen order.
func (s *FileStore) Load() ([]*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	out, _, torn, err := parseSnapshots(data)
	if err != nil {
		return nil, err
	}
	if torn {
		return nil, fmt.Errorf("settlement: store %s ends with a partial line", s.path)
	}
	return out, nil
}

// Close closes the file.
func (s *FileStore) Close() error { return s.f.Close() }
