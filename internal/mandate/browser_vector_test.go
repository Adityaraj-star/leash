package mandate

import (
	"encoding/base64"
	"testing"
)

// A known-answer test for the dashboard. These values were produced by the
// browser code in web/static/sign.js, run on WebCrypto (a P-256 key, a mandate
// built by buildMandate, and signatures over the mandate and over an approval
// message). If the Go side ever stops accepting what the browser produces, this
// fails, before a user finds out the hard way.
const (
	browserPublicKey   = "BEnvWTcnd13WtMsYtnNnItBnNoNZ+6RuvLm1OFjwB9XKmpfCDFEzMVC+sbcf3cn+hSv2rrO8/at4xxOcLy1QOdM="
	browserKeyID       = "512d229867d63675"
	browserMandate     = "{\"mandate_id\":\"m_065f4d58\",\"intent\":\"Gift under $40\",\"max_total\":{\"amount\":\"40.00\",\"currency\":\"USD\"},\"per_tx_cap\":\"40.00\",\"allowed_merchants\":[\"legitgifts\"],\"categories\":[\"gifts\"],\"requires_return_policy\":true,\"single_use\":false,\"step_up_over\":\"25.00\",\"expires_at\":\"2026-10-29T00:00:00Z\",\"nonce\":\"58fb6c3fd1be2739\"}"
	browserMandateSig  = "ufdQnTtYoVLpUx/Dvjm9XaqDLlavlgYWYMKuOlbulwYp8eYlyyz+j7Zp0TCIay0g/YVHYfe/3dgA0XpH1hTUCQ=="
	browserApproval    = "leash.approve.v1\nreq_abc\nlegitgifts\n32.00 USD"
	browserApprovalSig = "sU6KjkRoxkykuWviH8nL1T9kjugHwrMmppq2pKNGDVGg4jO9SfTRAvMoK8DH1d1XvZSi54+pt7Ywg8EuhsSCtA=="
)

func TestBrowserProducedKeysAndSignaturesVerify(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString(browserPublicKey)
	if err != nil || len(pub) != PublicKeyLen {
		t.Fatalf("public key: %v (%d bytes)", err, len(pub))
	}
	if got := KeyID(pub); got != browserKeyID {
		t.Fatalf("key id: Go says %s, the browser says %s", got, browserKeyID)
	}

	sig, _ := base64.StdEncoding.DecodeString(browserMandateSig)
	m, err := Verify([]byte(browserMandate), sig, pub)
	if err != nil {
		t.Fatalf("a mandate signed in the browser must verify and parse: %v", err)
	}
	if m.MaxTotal.String() != "40.00" || m.PerTxCap.String() != "40.00" || m.StepUpOver.String() != "25.00" || len(m.AllowedMerchants) != 1 {
		t.Fatalf("parsed: %+v", m)
	}

	asig, _ := base64.StdEncoding.DecodeString(browserApprovalSig)
	if err := VerifySignature([]byte(browserApproval), asig, pub); err != nil {
		t.Fatalf("an approval signed in the browser must verify: %v", err)
	}
	// Changing one character of what was signed must break it.
	if err := VerifySignature([]byte(browserApproval+" "), asig, pub); err == nil {
		t.Fatal("a signature must not verify for different text")
	}
	if err := VerifySignature([]byte(browserApproval), sig, pub); err == nil {
		t.Fatal("a mandate signature must not verify as an approval")
	}
}
