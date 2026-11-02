package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/control"
	"github.com/Adityaraj-star/leash/internal/ledger"
	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/paypal/paypaltest"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

type tick struct {
	mu sync.Mutex
	t  time.Time
}

func (c *tick) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *tick) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// strictRig is the same stack as newRig but the way a real deployment runs it:
// strict plane, enrollment secret equal to the operator token.
func strictRig(t *testing.T) (*rig, *Server, *tick) {
	t.Helper()
	now := func() time.Time { return time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC) }
	fake := paypaltest.New()
	fake.SetClock(now)
	base := fake.Start()
	t.Cleanup(fake.Close)
	client, err := paypal.New(paypal.Config{ClientID: paypaltest.ClientID, ClientSecret: paypaltest.ClientSecret, BaseURL: base, Sleep: func(time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	shop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Desk lamp</h1><p>$32.00. Free returns within 30 days.</p></body></html>`)
	}))
	t.Cleanup(shop.Close)
	_, key, _ := ledger.GenerateKey()
	led, err := ledger.New(ledger.NewMemStore(), key, now)
	if err != nil {
		t.Fatal(err)
	}
	usd := func(s string) money.Amount { return money.MustParse(s, "USD") }
	plane, err := control.New(control.Config{
		Gateway: client, Ledger: led, Now: now, Logf: func(string, ...any) {},
		BrowseHosts:   []string{strings.TrimPrefix(shop.URL, "http://")},
		PaymentSource: map[string]any{"paypal": map[string]any{"vault_id": "VAULT-1"}},
		Strict:        true, EnrollSecret: token,
		Registry: control.MapRegistry{"legitgifts": {ID: "legitgifts", Name: "LegitGifts", Email: "legit@sandbox.example",
			Categories: []string{"gifts"}, HasReturnPolicy: true, DeliverySecret: "s3cret"}},
		Quotes: quotes{"q-lamp": {ID: "q-lamp", MerchantID: "legitgifts", Amount: usd("32.00"), Items: []string{"Desk lamp"},
			PromisedDelivery: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clk := &tick{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s := &Server{Plane: plane, Token: token, Now: clk.now, Heartbeat: 20 * time.Millisecond}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &rig{t: t, plane: plane, srv: srv, priv: priv, shop: shop}, s, clk
}

func (r *rig) strictStepUp(key string) string {
	r.t.Helper()
	conn := r.plane.OpenAgentConn()
	ev, err := conn.Browse(context.Background(), r.shop.URL+"/")
	if err != nil {
		r.t.Fatal(err)
	}
	out, err := conn.RequestPayment(context.Background(), control.PaymentRequest{
		MandateID: "m_api", MerchantID: "legitgifts", Items: []string{"Desk lamp"}, Amount: money.MustParse("32.00", "USD"),
		QuoteID: "q-lamp", EvidenceRefs: []string{ev.EvidenceID}, IdempotencyKey: key,
	})
	if err != nil || out.State != settlement.StepUpPending {
		r.t.Fatalf("expected a step-up: %v %+v", err, out)
	}
	return out.RequestID
}

func TestAStrictServerNeedsASignedApproval(t *testing.T) {
	r, _, _ := strictRig(t)
	r.enrollAndRegister() // the API enrolls with the operator token as the secret
	id := r.strictStepUp("k1")

	// Unsigned: refused, with a hint that says what to do.
	code, b := r.do("POST", "/api/requests/"+id+"/approve", "", true)
	if code != http.StatusForbidden || !strings.Contains(string(b), "signed") {
		t.Fatalf("unsigned approval = %d %s", code, b)
	}
	// Signed by some other key: refused.
	var am struct{ Message string }
	json.Unmarshal(r.must("GET", "/api/requests/"+id+"/approval", "", 200), &am)
	if !strings.HasPrefix(am.Message, "leash.approve.v1\n"+id+"\nlegitgifts\n32.00 USD") {
		t.Fatalf("approval message: %q", am.Message)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad, _ := mandate.Sign(other, []byte(am.Message))
	code, _ = r.do("POST", "/api/requests/"+id+"/approve", fmt.Sprintf(`{"signature":%q}`, base64.StdEncoding.EncodeToString(bad)), true)
	if code != http.StatusForbidden {
		t.Fatalf("a signature by another key = %d", code)
	}
	// A signature over a different amount: refused.
	wrong, _ := mandate.Sign(r.priv, control.ApprovalMessage(id, "legitgifts", money.MustParse("1.00", "USD")))
	code, _ = r.do("POST", "/api/requests/"+id+"/approve", fmt.Sprintf(`{"signature":%q}`, base64.StdEncoding.EncodeToString(wrong)), true)
	if code != http.StatusForbidden {
		t.Fatalf("a signature over another amount = %d", code)
	}
	// The user's own signature over the real message: approved, hold placed.
	good, _ := mandate.Sign(r.priv, []byte(am.Message))
	var out control.Outcome
	json.Unmarshal(r.must("POST", "/api/requests/"+id+"/approve", fmt.Sprintf(`{"signature":%q}`, base64.StdEncoding.EncodeToString(good)), 200), &out)
	if out.State != settlement.Authorized {
		t.Fatalf("after a signed approval: %+v", out)
	}
	var st struct{ Strict bool }
	json.Unmarshal(r.must("GET", "/api/state", "", 200), &st)
	if !st.Strict {
		t.Fatal("the dashboard needs to know the server is strict")
	}
}

func TestRejectingNeedsNoSignature(t *testing.T) {
	r, _, _ := strictRig(t)
	r.enrollAndRegister()
	id := r.strictStepUp("k1")
	var out control.Outcome
	json.Unmarshal(r.must("POST", "/api/requests/"+id+"/reject", "", 200), &out) // refusing is always safe
	if out.State != settlement.Denied {
		t.Fatalf("%+v", out)
	}
}

func TestStateServesTheCachedChainCheck(t *testing.T) {
	r, s, clk := strictRig(t)
	r.enrollAndRegister()
	read := func() string {
		var st struct {
			At    string `json:"chain_checked_at"`
			Chain ledger.Result
		}
		json.Unmarshal(r.must("GET", "/api/state", "", 200), &st)
		if !st.Chain.OK {
			t.Fatalf("chain: %+v", st.Chain)
		}
		return st.At
	}
	first := read()
	clk.add(time.Hour)
	r.strictStepUp("k1") // appends ledger entries
	if got := read(); got != first {
		t.Fatalf("state must not re-verify on every call: %s then %s", first, got)
	}
	// The verify endpoint (and the background verifier) refresh it.
	var v struct {
		At string `json:"checked_at"`
	}
	json.Unmarshal(r.must("GET", "/api/ledger/verify", "", 200), &v)
	if v.At == first {
		t.Fatalf("verify must run fresh: %s", v.At)
	}
	if got := read(); got != v.At {
		t.Fatalf("state should now show the fresh check: %s vs %s", got, v.At)
	}
	if res, _ := s.VerifyChain(); !res.OK {
		t.Fatalf("%+v", res)
	}
}

func TestRunVerifierAndRunSweeperStopWithTheirContext(t *testing.T) {
	r, s, _ := strictRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	go func() { s.RunVerifier(ctx, 10*time.Millisecond, func(string, ...any) {}); done <- struct{}{} }()
	go func() { RunSweeper(ctx, r.plane, 10*time.Millisecond, func(string, ...any) {}); done <- struct{}{} }()
	time.Sleep(40 * time.Millisecond)
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("a background loop did not stop")
		}
	}
}
