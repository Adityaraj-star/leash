// Package mandate defines the user-signed spending mandate and verifies its
// signature.
//
// The browser signs the exact serialized bytes of the mandate JSON with a
// P-256 key (WebCrypto ECDSA/SHA-256). The server verifies those same bytes and
// only then parses them, so there is no cross-language JSON canonicalization
// to get wrong. WebCrypto emits signatures as a raw 64-byte r||s pair, not
// ASN.1 DER, and exports public keys as a 65-byte uncompressed point.
package mandate

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/Adityaraj-star/leash/internal/money"
)

const (
	maxRawLen = 16 << 10
	// SignatureLen is the length of a WebCrypto raw ECDSA P-256 signature.
	SignatureLen = 64
	// PublicKeyLen is the length of an uncompressed P-256 point.
	PublicKeyLen = 65
)

var (
	ErrBadPublicKey = errors.New("mandate: invalid P-256 public key")
	ErrBadSignature = errors.New("mandate: signature does not verify")
)

// Mandate is the parsed, validated form of the signed JSON.
type Mandate struct {
	ID                   string
	Intent               string
	MaxTotal             money.Amount
	PerTxCap             money.Amount // defaults to MaxTotal when omitted
	StepUpOver           money.Amount // zero Minor = step-up disabled
	AllowedMerchants     []string
	Categories           []string
	RequiresReturnPolicy bool
	DeliverBy            time.Time // end of the named day, UTC; zero = no deadline
	SingleUse            bool
	ExpiresAt            time.Time
	Nonce                string
}

type wire struct {
	MandateID string `json:"mandate_id"`
	Intent    string `json:"intent"`
	MaxTotal  struct {
		Amount   string `json:"amount"`
		Currency string `json:"currency"`
	} `json:"max_total"`
	PerTxCap             string   `json:"per_tx_cap"`
	AllowedMerchants     []string `json:"allowed_merchants"`
	Categories           []string `json:"categories"`
	RequiresReturnPolicy bool     `json:"requires_return_policy"`
	DeliverBy            string   `json:"deliver_by"`
	SingleUse            bool     `json:"single_use"`
	StepUpOver           string   `json:"step_up_over"`
	ExpiresAt            string   `json:"expires_at"`
	Nonce                string   `json:"nonce"`
}

// Parse strictly decodes and validates mandate JSON. Unknown fields, trailing
// data, malformed amounts and missing required fields are all rejected.
func Parse(raw []byte) (*Mandate, error) {
	if len(raw) == 0 || len(raw) > maxRawLen {
		return nil, errors.New("mandate: empty or oversized")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var w wire
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("mandate: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("mandate: trailing data after JSON object")
	}

	m := &Mandate{
		ID:                   w.MandateID,
		Intent:               w.Intent,
		AllowedMerchants:     w.AllowedMerchants,
		Categories:           w.Categories,
		RequiresReturnPolicy: w.RequiresReturnPolicy,
		SingleUse:            w.SingleUse,
		Nonce:                w.Nonce,
	}
	if strings.TrimSpace(m.ID) == "" || strings.TrimSpace(m.Nonce) == "" {
		return nil, errors.New("mandate: mandate_id and nonce are required")
	}
	var err error
	if m.MaxTotal, err = money.Parse(w.MaxTotal.Amount, w.MaxTotal.Currency); err != nil {
		return nil, fmt.Errorf("mandate: max_total: %w", err)
	}
	if m.MaxTotal.Minor <= 0 {
		return nil, errors.New("mandate: max_total must be positive")
	}
	cur := m.MaxTotal.Currency
	m.PerTxCap = m.MaxTotal
	if w.PerTxCap != "" {
		if m.PerTxCap, err = money.Parse(w.PerTxCap, cur); err != nil {
			return nil, fmt.Errorf("mandate: per_tx_cap: %w", err)
		}
		if m.PerTxCap.Minor <= 0 {
			return nil, errors.New("mandate: per_tx_cap must be positive")
		}
		if m.PerTxCap.Minor > m.MaxTotal.Minor {
			return nil, errors.New("mandate: per_tx_cap cannot exceed max_total")
		}
	}
	if w.StepUpOver != "" {
		if m.StepUpOver, err = money.Parse(w.StepUpOver, cur); err != nil {
			return nil, fmt.Errorf("mandate: step_up_over: %w", err)
		}
		if m.StepUpOver.Minor > m.PerTxCap.Minor {
			// A payment above the cap is denied before step-up could ever apply, so
			// this setting would silently do nothing: almost certainly a mistake.
			return nil, errors.New("mandate: step_up_over cannot exceed per_tx_cap")
		}
	}
	if m.ExpiresAt, err = time.Parse(time.RFC3339, w.ExpiresAt); err != nil {
		return nil, fmt.Errorf("mandate: expires_at: %w", err)
	}
	m.ExpiresAt = m.ExpiresAt.UTC()
	if w.DeliverBy != "" {
		d, err := time.Parse("2006-01-02", w.DeliverBy)
		if err != nil {
			return nil, fmt.Errorf("mandate: deliver_by: %w", err)
		}
		m.DeliverBy = d.Add(24*time.Hour - time.Nanosecond).UTC()
	}
	for _, s := range append(append([]string{}, m.AllowedMerchants...), m.Categories...) {
		if strings.TrimSpace(s) == "" {
			return nil, errors.New("mandate: empty merchant or category entry")
		}
	}
	return m, nil
}

// ParsePublicKey validates a 65-byte uncompressed P-256 point.
func ParsePublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != PublicKeyLen || raw[0] != 0x04 {
		return nil, ErrBadPublicKey
	}
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil { // checks the point is on the curve
		return nil, ErrBadPublicKey
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}, nil
}

// VerifySignature checks that sig (raw r||s) is a valid P-256/SHA-256
// signature over exactly raw by pub.
func VerifySignature(raw, sig, pub []byte) error {
	key, err := ParsePublicKey(pub)
	if err != nil {
		return err
	}
	if len(sig) != SignatureLen {
		return fmt.Errorf("%w: signature must be %d bytes (raw r||s, not DER)", ErrBadSignature, SignatureLen)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(raw)
	if !ecdsa.Verify(key, digest[:], r, s) {
		return ErrBadSignature
	}
	return nil
}

// Verify checks the signature against the (caller-pinned) enrolled key and, only
// if it verifies, parses the mandate.
func Verify(raw, sig, pub []byte) (*Mandate, error) {
	if err := VerifySignature(raw, sig, pub); err != nil {
		return nil, err
	}
	return Parse(raw)
}

// KeyID is a short stable identifier for an enrolled public key.
func KeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Sign produces a WebCrypto-compatible raw r||s signature. It exists for
// tests, the CLI and the demo agent; real users sign in the browser.
func Sign(priv *ecdsa.PrivateKey, raw []byte) ([]byte, error) {
	digest := sha256.Sum256(raw)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, SignatureLen)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// PublicKeyBytes exports the 65-byte uncompressed point.
func PublicKeyBytes(priv *ecdsa.PrivateKey) ([]byte, error) {
	pk, err := priv.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	return pk.Bytes(), nil
}
