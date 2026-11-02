package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/control"
	"github.com/Adityaraj-star/leash/internal/ledger"
	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/paypal/paypaltest"
	"github.com/Adityaraj-star/leash/internal/provenance"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

const token = "test-operator-token"

type quotes map[string]*provenance.Quote

func (q quotes) Quote(_ context.Context, _, id string) (*provenance.Quote, error) {
	if v, ok := q[id]; ok {
		return v, nil
	}
	return nil, errors.New("no such quote")
}

type rig struct {
	t     *testing.T
	plane *control.Plane
	srv   *httptest.Server
	priv  *ecdsa.PrivateKey
	shop  *httptest.Server
}

func newRig(t *testing.T) *rig {
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
		Registry: control.MapRegistry{"legitgifts": {ID: "legitgifts", Name: "LegitGifts", Email: "legit@sandbox.example",
			Categories: []string{"gifts"}, HasReturnPolicy: true, DeliverySecret: "s3cret"}},
		Quotes: quotes{"q-lamp": {ID: "q-lamp", MerchantID: "legitgifts", Amount: usd("32.00"), Items: []string{"Desk lamp"},
			PromisedDelivery: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &Server{Plane: plane, Token: token, Heartbeat: 20 * time.Millisecond, Static: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("dashboard")) })}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &rig{t: t, plane: plane, srv: srv, priv: priv, shop: shop}
}

func (r *rig) do(method, path, body string, auth bool) (int, []byte) {
	r.t.Helper()
	req, _ := http.NewRequest(method, r.srv.URL+path, strings.NewReader(body))
	if auth {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (r *rig) must(method, path, body string, want int) []byte {
	r.t.Helper()
	code, b := r.do(method, path, body, true)
	if code != want {
		r.t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, b)
	}
	return b
}

const mandateText = `{"mandate_id":"m_api","intent":"Gift under $40","max_total":{"amount":"40.00","currency":"USD"},"per_tx_cap":"40.00",` +
	`"allowed_merchants":["legitgifts"],"categories":["gifts"],"requires_return_policy":true,"deliver_by":"2026-10-20","single_use":false,` +
	`"step_up_over":"25.00","expires_at":"2026-10-25T00:00:00Z","nonce":"n-api"}`

func (r *rig) enrollAndRegister() {
	r.t.Helper()
	pub, _ := mandate.PublicKeyBytes(r.priv)
	r.must("POST", "/api/enroll", fmt.Sprintf(`{"public_key":%q}`, base64.StdEncoding.EncodeToString(pub)), 200)
	sig, _ := mandate.Sign(r.priv, []byte(mandateText))
	body, _ := json.Marshal(map[string]string{"mandate": mandateText, "signature": base64.StdEncoding.EncodeToString(sig)})
	r.must("POST", "/api/mandates", string(body), 201)
}

func (r *rig) stepUpRequest(key string) string {
	r.t.Helper()
	b, err := r.plane.Browse(context.Background(), "sess1", r.shop.URL+"/")
	if err != nil {
		r.t.Fatal(err)
	}
	out, err := r.plane.RequestPayment(context.Background(), control.PaymentRequest{
		Session: "sess1", MandateID: "m_api", MerchantID: "legitgifts", Items: []string{"Desk lamp"},
		Amount: money.MustParse("32.00", "USD"), QuoteID: "q-lamp", EvidenceRefs: []string{b.EvidenceID}, IdempotencyKey: key,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	if out.State != settlement.StepUpPending {
		r.t.Fatalf("expected a step-up, got %+v", out)
	}
	return out.RequestID
}

func TestEveryAPIRouteNeedsTheOperatorToken(t *testing.T) {
	r := newRig(t)
	for _, c := range [][2]string{{"GET", "/api/state"}, {"GET", "/api/requests"}, {"GET", "/api/ledger"}, {"GET", "/api/events"},
		{"POST", "/api/enroll"}, {"POST", "/api/mandates/x/revoke"}, {"POST", "/api/requests/x/approve"}} {
		if code, _ := r.do(c[0], c[1], "{}", false); code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token = %d, want 401", c[0], c[1], code)
		}
	}
	req, _ := http.NewRequest("GET", r.srv.URL+"/api/state", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Errorf("wrong token = %d", resp.StatusCode)
	}
	// Open: health and the static dashboard (which holds no data).
	if code, _ := r.do("GET", "/healthz", "", false); code != 200 {
		t.Errorf("healthz = %d", code)
	}
	if code, b := r.do("GET", "/", "", false); code != 200 || string(b) != "dashboard" {
		t.Errorf("static = %d %q", code, b)
	}
	if h := resp.Header.Get("X-Frame-Options"); h != "DENY" {
		t.Errorf("missing security headers: %v", resp.Header)
	}
}

func TestAnEmptyTokenCanNeverStartTheServer(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a server with no token was allowed to start")
		}
	}()
	(&Server{}).Handler()
}

func TestStepUpApprovalThroughTheAPI(t *testing.T) {
	r := newRig(t)
	r.enrollAndRegister()

	var st struct {
		KeyID    string `json:"key_id"`
		Mandates []MandateDTO
		Chain    ledger.Result
	}
	json.Unmarshal(r.must("GET", "/api/state", "", 200), &st)
	if st.KeyID == "" || len(st.Mandates) != 1 || st.Mandates[0].ID != "m_api" || st.Mandates[0].MaxTotal != "40.00" || !st.Chain.OK {
		t.Fatalf("state: %+v", st)
	}

	id := r.stepUpRequest("k1")
	var list []settlement.Request
	json.Unmarshal(r.must("GET", "/api/requests", "", 200), &list)
	if len(list) != 1 || list[0].State != settlement.StepUpPending {
		t.Fatalf("requests: %+v", list)
	}

	var out control.Outcome
	json.Unmarshal(r.must("POST", "/api/requests/"+id+"/approve", "", 200), &out)
	if out.State != settlement.Authorized {
		t.Fatalf("after approve: %+v", out)
	}
	// Approving twice is a conflict, not a second hold.
	r.must("POST", "/api/requests/"+id+"/approve", "", 409)

	var vr struct {
		Result ledger.Result `json:"result"`
	}
	json.Unmarshal(r.must("GET", "/api/ledger/verify", "", 200), &vr)
	if !vr.Result.OK || vr.Result.Entries < 5 {
		t.Fatalf("verify: %+v", vr)
	}
	var es []ledger.Entry
	json.Unmarshal(r.must("GET", "/api/ledger?after=2&limit=3", "", 200), &es)
	if len(es) != 3 || es[0].Seq != 3 {
		t.Fatalf("ledger paging: %+v", es)
	}
}

func TestRejectRevokeAndErrors(t *testing.T) {
	r := newRig(t)
	// Nothing is enrolled yet.
	sig, _ := mandate.Sign(r.priv, []byte(mandateText))
	body, _ := json.Marshal(map[string]string{"mandate": mandateText, "signature": base64.StdEncoding.EncodeToString(sig)})
	r.must("POST", "/api/mandates", string(body), 412)

	r.enrollAndRegister()
	// A different key cannot be enrolled over the pinned one.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub2, _ := mandate.PublicKeyBytes(other)
	r.must("POST", "/api/enroll", fmt.Sprintf(`{"public_key":%q}`, base64.StdEncoding.EncodeToString(pub2)), 409)

	// A forged signature is refused.
	bad := bytes.Repeat([]byte{1}, 64)
	body, _ = json.Marshal(map[string]string{"mandate": strings.Replace(mandateText, "m_api", "m_evil", 1), "signature": base64.StdEncoding.EncodeToString(bad)})
	r.must("POST", "/api/mandates", string(body), 400)

	r.must("POST", "/api/enroll", `{"public_key":"%%%"}`, 400)
	r.must("POST", "/api/enroll", `{"public_key":"AAAA","extra":1}`, 400) // unknown fields are rejected
	r.must("GET", "/api/requests/nope", "", 404)
	r.must("GET", "/api/evidence/nope", "", 404)
	r.must("POST", "/api/requests/nope/reject", "", 404)

	id := r.stepUpRequest("k2")
	var out control.Outcome
	json.Unmarshal(r.must("POST", "/api/requests/"+id+"/reject", "", 200), &out)
	if out.State != settlement.Denied {
		t.Fatalf("after reject: %+v", out)
	}

	id2 := r.stepUpRequest("k3")
	var rv struct {
		Released []string `json:"holds_released"`
	}
	json.Unmarshal(r.must("POST", "/api/mandates/m_api/revoke", "", 200), &rv)
	// The pending step-up was cancelled, so approving it now must not place a hold.
	code, b := r.do("POST", "/api/requests/"+id2+"/approve", "", true)
	if code == 200 {
		var o control.Outcome
		json.Unmarshal(b, &o)
		if o.State == settlement.Authorized {
			t.Fatalf("a revoked mandate's request was authorized: %s", b)
		}
	}
	var st struct{ Mandates []MandateDTO }
	json.Unmarshal(r.must("GET", "/api/state", "", 200), &st)
	if !st.Mandates[0].Revoked {
		t.Fatalf("mandate not shown as revoked: %+v", st.Mandates)
	}
}

func TestLiveEventStream(t *testing.T) {
	r := newRig(t)
	req, _ := http.NewRequest("GET", r.srv.URL+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		r.enrollAndRegister() // produces user.enrolled and mandate.registered
	}()
	sc := bufio.NewScanner(resp.Body)
	seen := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data: ") {
			var e ledger.Entry
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e); err != nil {
				t.Fatalf("bad event: %v", err)
			}
			seen[e.Type] = true
			if seen["user.enrolled"] && seen["mandate.registered"] {
				return
			}
		}
	}
	t.Fatalf("stream ended without the expected events: %v (%v)", seen, sc.Err())
}
