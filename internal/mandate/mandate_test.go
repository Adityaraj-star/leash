package mandate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

const sample = `{
  "mandate_id": "m_01",
  "intent": "Birthday gift for my sister, under $40, arrives before Oct 20",
  "max_total": { "amount": "40.00", "currency": "USD" },
  "per_tx_cap": "40.00",
  "allowed_merchants": ["legitgifts"],
  "categories": ["gifts"],
  "requires_return_policy": true,
  "deliver_by": "2026-10-20",
  "single_use": true,
  "step_up_over": "25.00",
  "expires_at": "2026-10-18T00:00:00Z",
  "nonce": "n-123"
}`

func newKey(t testing.TB) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyBytes(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestParseSample(t *testing.T) {
	m, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if m.MaxTotal.Minor != 4000 || m.PerTxCap.Minor != 4000 || m.StepUpOver.Minor != 2500 {
		t.Errorf("amounts: %+v", m)
	}
	if !m.SingleUse || !m.RequiresReturnPolicy || m.AllowedMerchants[0] != "legitgifts" {
		t.Errorf("flags: %+v", m)
	}
	wantDeliver := time.Date(2026, 10, 20, 23, 59, 59, 999999999, time.UTC)
	if !m.DeliverBy.Equal(wantDeliver) {
		t.Errorf("DeliverBy=%v want %v", m.DeliverBy, wantDeliver)
	}
	if !m.ExpiresAt.Equal(time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("ExpiresAt=%v", m.ExpiresAt)
	}
}

func TestParseDefaultsAndOptional(t *testing.T) {
	m, err := Parse([]byte(`{"mandate_id":"a","intent":"x","max_total":{"amount":"10","currency":"USD"},
		"expires_at":"2026-12-01T00:00:00Z","nonce":"n"}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.PerTxCap != m.MaxTotal || m.StepUpOver.Minor != 0 || !m.DeliverBy.IsZero() {
		t.Errorf("defaults wrong: %+v", m)
	}
}

func TestParseRejects(t *testing.T) {
	bad := map[string]string{
		"unknown field":   strings.Replace(sample, `"nonce": "n-123"`, `"nonce": "n", "extra": 1`, 1),
		"trailing data":   sample + ` {}`,
		"no nonce":        strings.Replace(sample, `"nonce": "n-123"`, `"nonce": ""`, 1),
		"no id":           strings.Replace(sample, `"mandate_id": "m_01"`, `"mandate_id": " "`, 1),
		"zero max":        strings.Replace(sample, `"amount": "40.00"`, `"amount": "0.00"`, 1),
		"float amount":    strings.Replace(sample, `"amount": "40.00"`, `"amount": 40.0`, 1),
		"negative cap":    strings.Replace(sample, `"per_tx_cap": "40.00"`, `"per_tx_cap": "-1.00"`, 1),
		"bad expiry":      strings.Replace(sample, `2026-10-18T00:00:00Z`, `tomorrow`, 1),
		"bad deliver_by":  strings.Replace(sample, `2026-10-20`, `20/10/2026`, 1),
		"empty merchant":  strings.Replace(sample, `["legitgifts"]`, `[""]`, 1),
		"bad currency":    strings.Replace(sample, `"currency": "USD"`, `"currency": "usd"`, 1),
		"not json":        `hello`,
		"empty":           ``,
		"too many digits": strings.Replace(sample, `"40.00"`, `"40.001"`, 1),
	}
	for name, raw := range bad {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: should have been rejected", name)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, pub := newKey(t)
	raw := []byte(sample)
	sig, err := Sign(priv, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureLen {
		t.Fatalf("sig len %d", len(sig))
	}
	m, err := Verify(raw, sig, pub)
	if err != nil || m.ID != "m_01" {
		t.Fatalf("verify: %v %+v", err, m)
	}
}

// Signatures from WebCrypto are raw r||s, big-endian, each left-padded to 32
// bytes. Build one by hand (including a short r that needs padding) to prove
// the padding path works.
func TestVerifyHandBuiltRawSignatureWithPadding(t *testing.T) {
	priv, pub := newKey(t)
	for i := 0; i < 300; i++ {
		raw := []byte(sample + strings.Repeat(" ", i))
		digest := sha256.Sum256(raw)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		if err := VerifySignature(raw, sig, pub); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}

func TestRejectsDERSignature(t *testing.T) {
	priv, pub := newKey(t)
	raw := []byte(sample)
	digest := sha256.Sum256(raw)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, digest[:])
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err := VerifySignature(raw, der, pub); err == nil {
		t.Fatal("DER signature must be rejected: the browser sends raw r||s")
	}
}

func TestTamperedBytesFail(t *testing.T) {
	priv, pub := newKey(t)
	raw := []byte(sample)
	sig, _ := Sign(priv, raw)
	for i := range raw {
		mod := append([]byte(nil), raw...)
		mod[i] ^= 0x01
		if err := VerifySignature(mod, sig, pub); err == nil {
			t.Fatalf("flipping byte %d went undetected", i)
		}
	}
	// Whitespace-only changes also break it: we verify exact bytes by design.
	if err := VerifySignature([]byte(sample+" "), sig, pub); err == nil {
		t.Fatal("re-serialized mandate must not verify")
	}
}

func TestWrongKeyAndBadKeys(t *testing.T) {
	priv, _ := newKey(t)
	_, otherPub := newKey(t)
	raw := []byte(sample)
	sig, _ := Sign(priv, raw)
	if err := VerifySignature(raw, sig, otherPub); err == nil {
		t.Error("signature verified under a different key")
	}
	_, pub := newKey(t)
	for name, k := range map[string][]byte{
		"empty":       nil,
		"short":       pub[:64],
		"compressed":  append([]byte{0x02}, pub[1:33]...),
		"bad prefix":  append([]byte{0x05}, pub[1:]...),
		"off curve":   append([]byte{0x04}, make([]byte, 64)...),
		"too long":    append(append([]byte(nil), pub...), 0),
		"all 0x04 ff": append([]byte{0x04}, []byte(strings.Repeat("\xff", 64))...),
	} {
		if err := VerifySignature(raw, sig, k); err == nil {
			t.Errorf("%s: invalid key accepted", name)
		}
	}
}

func TestBadSignatureValues(t *testing.T) {
	_, pub := newKey(t)
	raw := []byte(sample)
	n := elliptic.P256().Params().N
	zero := make([]byte, 64)
	huge := append(n.FillBytes(make([]byte, 32)), n.FillBytes(make([]byte, 32))...)
	for name, sig := range map[string][]byte{
		"nil": nil, "short": make([]byte, 63), "long": make([]byte, 65), "zeros": zero, "r=s=n": huge,
	} {
		if err := VerifySignature(raw, sig, pub); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyDoesNotParseUnverifiedBytes(t *testing.T) {
	priv, pub := newKey(t)
	raw := []byte(sample)
	sig, _ := Sign(priv, raw)
	evil := []byte(strings.Replace(sample, `"40.00"`, `"4000.00"`, 1))
	if m, err := Verify(evil, sig, pub); err == nil || m != nil {
		t.Fatal("altered mandate verified")
	}
}

func TestKeyID(t *testing.T) {
	_, a := newKey(t)
	_, b := newKey(t)
	if KeyID(a) == KeyID(b) || len(KeyID(a)) != 16 {
		t.Error("KeyID should be short and distinct")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			return
		}
		if m.MaxTotal.Minor <= 0 || m.PerTxCap.Minor <= 0 || m.StepUpOver.Minor < 0 {
			t.Fatalf("Parse accepted non-positive money: %+v", m)
		}
		if m.MaxTotal.Currency != m.PerTxCap.Currency {
			t.Fatal("currency mismatch accepted")
		}
	})
}
