package ledger

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LoadOrCreateKey returns the ledger's Ed25519 signing key, persisted at path.
//
// The ledger is only verifiable with the key that signed it, so a server that
// generates a fresh key on every start cannot reopen its own ledger. This keeps
// a stable key: the 32-byte seed is stored hex-encoded in a file that only the
// owner can read. On Unix a key file readable by group or others is refused.
// The key is created atomically (O_EXCL) the first time.
func LoadOrCreateKey(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil, errors.New("ledger: key path is required")
	}
	if b, err := os.ReadFile(path); err == nil {
		if runtime.GOOS != "windows" {
			st, serr := os.Stat(path)
			if serr != nil {
				return nil, nil, serr
			}
			if st.Mode().Perm()&0o077 != 0 {
				return nil, nil, fmt.Errorf("ledger: key file %s is accessible to other users (mode %o); run chmod 600", path, st.Mode().Perm())
			}
		}
		seed, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return nil, nil, fmt.Errorf("ledger: key file %s is not a %d-byte hex seed", path, ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		return priv.Public().(ed25519.PublicKey), priv, nil
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}

	pub, priv, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, err // another process created it first, or the path is not writable
	}
	if _, err := f.WriteString(hex.EncodeToString(priv.Seed()) + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return nil, nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return nil, nil, err
	}
	if err := f.Close(); err != nil {
		return nil, nil, err
	}
	syncDir(filepath.Dir(path))
	return pub, priv, nil
}
