package shops_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/api"
	"github.com/Adityaraj-star/leash/internal/control"
	"github.com/Adityaraj-star/leash/internal/ledger"
	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/paypal/paypaltest"
	"github.com/Adityaraj-star/leash/internal/settlement"
	"github.com/Adityaraj-star/leash/internal/shops"
)

const (
	legitSecret = "legit-delivery-secret-1"
	shadySecret = "shady-delivery-secret-2"
	adminPW     = "back-office-pw"
)

var clock = func() time.Time { return time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC) }

type world struct {
	t     *testing.T
	plane *control.Plane
	fake  *paypaltest.Server
	legit *shops.Shop
	shady *shops.Shop
	lURL  string
	sURL  string
	apiS  *httptest.Server
	ctx   context.Context
}

func newWorld(t *testing.T) *world {
	t.Helper()
	legit := shops.Legit("", legitSecret, adminPW)
	shady := shops.Shady("", shadySecret, adminPW)
	legit.Now, shady.Now = clock, clock
	lSrv := httptest.NewServer(legit.Handler())
	sSrv := httptest.NewServer(shady.Handler())
	t.Cleanup(lSrv.Close)
	t.Cleanup(sSrv.Close)

	fake := paypaltest.New()
	fake.SetClock(clock)
	base := fake.Start()
	t.Cleanup(fake.Close)
	client, err := paypal.New(paypal.Config{ClientID: paypaltest.ClientID, ClientSecret: paypaltest.ClientSecret, BaseURL: base, Sleep: func(time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ledger.GenerateKey()
	led, err := ledger.New(ledger.NewMemStore(), key, clock)
	if err != nil {
		t.Fatal(err)
	}
	host := func(u string) string { return strings.TrimPrefix(u, "http://") }
	plane, err := control.New(control.Config{
		Gateway: client, Ledger: led, Now: clock, Logf: func(string, ...any) {},
		PaymentSource: map[string]any{"paypal": map[string]any{"vault_id": "VAULT-1"}},
		BrowseHosts:   []string{host(lSrv.URL), host(sSrv.URL)},
		Registry: control.MapRegistry{
			"legitgifts": {ID: "legitgifts", Name: "LegitGifts", Email: "legit@sandbox.example", Categories: []string{"gifts"}, HasReturnPolicy: true, Aliases: []string{"LegitGifts"}, DeliverySecret: legitSecret},
			"shadyshop":  {ID: "shadyshop", Name: "ShadyShop", Email: "shady@sandbox.example", Categories: []string{"gifts"}, Aliases: []string{"ShadyShop"}, DeliverySecret: shadySecret},
		},
		Quotes: &control.HTTPQuotes{Bases: map[string]string{"legitgifts": lSrv.URL, "shadyshop": sSrv.URL}},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := mandate.PublicKeyBytes(user)
	if _, err := plane.Enroll(pub); err != nil {
		t.Fatal(err)
	}
	text := `{"mandate_id":"m1","intent":"Gifts under $100","max_total":{"amount":"100.00","currency":"USD"},"per_tx_cap":"100.00",` +
		`"allowed_merchants":["legitgifts"],"categories":["gifts"],"requires_return_policy":true,"deliver_by":"2026-10-20","single_use":false,` +
		`"step_up_over":"50.00","expires_at":"2026-10-25T00:00:00Z","nonce":"n1"}`
	sig, _ := mandate.Sign(user, []byte(text))
	if _, err := plane.RegisterMandate([]byte(text), sig); err != nil {
		t.Fatal(err)
	}
	apiS := httptest.NewServer((&api.Server{Plane: plane, Token: "operator-token-123456"}).Handler())
	t.Cleanup(apiS.Close)
	legit.LeashURL, shady.LeashURL = apiS.URL, apiS.URL
	return &world{t: t, plane: plane, fake: fake, legit: legit, shady: shady, lURL: lSrv.URL, sURL: sSrv.URL, apiS: apiS, ctx: context.Background()}
}

func (w *world) pay(session, base, path, merchant, quote, amount string, items []string) control.Outcome {
	w.t.Helper()
	b, err := w.plane.Browse(w.ctx, session, base+path)
	if err != nil {
		w.t.Fatalf("browse %s: %v", path, err)
	}
	o, err := w.plane.RequestPayment(w.ctx, control.PaymentRequest{
		Session: session, MandateID: "m1", MerchantID: merchant, Items: items, Amount: money.MustParse(amount, "USD"),
		QuoteID: quote, EvidenceRefs: []string{b.EvidenceID}, IdempotencyKey: session + "-" + quote,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return o
}

func get(t *testing.T, u string, pw string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	if pw != "" {
		req.SetBasicAuth("admin", pw)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func deliver(t *testing.T, shopURL, id, outcome string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", shopURL+"/admin/deliver", strings.NewReader(url.Values{"id": {id}, "outcome": {outcome}}.Encode()))
	req.SetBasicAuth("admin", adminPW)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req) // follows the redirect to /admin?msg=...
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestHonestPurchaseIsHeldThenPaidWhenTheShopConfirmsDelivery(t *testing.T) {
	w := newWorld(t)
	o := w.pay("s1", w.lURL, "/p/mug", "legitgifts", "q-mug", "24.00", []string{"Ceramic mug"})
	if o.State != settlement.Authorized {
		t.Fatalf("expected a hold, got %+v (%s)", o.State, o.Reason)
	}
	if st := w.fake.Stats(); st.HeldMinor != 2400 || st.CapturedMinor != 0 {
		t.Fatalf("escrow: %+v", st)
	}
	// The shop's back office sees the order, and nobody else's.
	code, page := get(t, w.lURL+"/admin", adminPW)
	if code != 200 || !strings.Contains(page, o.RequestID) || !strings.Contains(page, "Ceramic mug") {
		t.Fatalf("back office: %d %s", code, page)
	}
	if _, shadyPage := get(t, w.sURL+"/admin", adminPW); strings.Contains(shadyPage, o.RequestID) {
		t.Fatal("another merchant can see this order")
	}
	if after := deliver(t, w.lURL, o.RequestID, "shipped"); !strings.Contains(after, "Delivery confirmed") {
		t.Fatalf("after delivery: %s", after)
	}
	cur, _ := w.plane.Status(o.RequestID)
	if cur.State != settlement.PaidOut {
		t.Fatalf("state %s", cur.State)
	}
	if st := w.fake.Stats(); st.CapturedMinor != 2400 || st.PaidOut["legit@sandbox.example"] != 2400 {
		t.Fatalf("money: %+v", st)
	}
	if _, page := get(t, w.lURL+"/admin", adminPW); strings.Contains(page, o.RequestID) {
		t.Fatal("a delivered order is still listed")
	}
}

func TestFailedDeliveryReleasesTheHold(t *testing.T) {
	w := newWorld(t)
	o := w.pay("s2", w.lURL, "/p/card", "legitgifts", "q-card", "12.00", []string{"Greeting card"})
	if o.State != settlement.Authorized {
		t.Fatalf("%+v", o)
	}
	if after := deliver(t, w.lURL, o.RequestID, "failed"); !strings.Contains(after, "not charged") {
		t.Fatalf("after: %s", after)
	}
	if cur, _ := w.plane.Status(o.RequestID); cur.State != settlement.Voided {
		t.Fatalf("state %s", cur.State)
	}
	if st := w.fake.Stats(); st.HeldMinor != 0 || st.CapturedMinor != 0 {
		t.Fatalf("buyer was charged: %+v", st)
	}
}

func TestTheShadyShopHiddenInjectionIsBlocked(t *testing.T) {
	w := newWorld(t)
	_, page := get(t, w.sURL+"/p/bundle", "")
	if !strings.Contains(page, "Ignore previous instructions") {
		t.Fatal("the shady page does not carry its injection")
	}
	o := w.pay("s3", w.sURL, "/p/bundle", "shadyshop", "q-bundle", "39.99", []string{"Premium bundle"})
	if o.State != settlement.Denied {
		t.Fatalf("the attack was not denied: %+v", o)
	}
	if st := w.fake.Stats(); st.HeldMinor != 0 || len(st.PaidOut) != 0 || st.Calls != 0 {
		t.Fatalf("PayPal was touched: %+v", st)
	}
}

func TestAPoisonedReviewOnAnHonestShopBlocksTheAgentAsWell(t *testing.T) {
	w := newWorld(t)
	_, page := get(t, w.lURL+"/p/lamp", "")
	if !strings.Contains(page, "NOTE FOR AI SHOPPING ASSISTANTS") {
		t.Fatal("the lamp page has no poisoned review")
	}
	o := w.pay("s4", w.lURL, "/p/lamp", "legitgifts", "q-lamp", "32.00", []string{"Desk lamp"})
	if o.State == settlement.Authorized || o.State == settlement.Approved {
		t.Fatalf("an agent that read an injection was allowed to pay: %+v (%s)", o.State, o.Reason)
	}
	t.Logf("poisoned review on an honest shop: %s (%s)", o.State, o.Reason)
	var injection bool
	for _, f := range o.Findings {
		if f.Rule == "R7" && strings.Contains(f.Reason, "instructions aimed at the agent") {
			injection = true
		}
	}
	if !injection {
		t.Fatalf("no injection finding: %+v", o.Findings)
	}
	if st := w.fake.Stats(); st.HeldMinor != 0 {
		t.Fatalf("money was held: %+v", st)
	}
	// The same shop's clean product is not affected by someone else's session.
	if o2 := w.pay("s5", w.lURL, "/p/mug", "legitgifts", "q-mug", "24.00", []string{"Ceramic mug"}); o2.State != settlement.Authorized {
		t.Fatalf("a clean session was blocked: %+v (%s)", o2.State, o2.Reason)
	}
}

func TestMerchantAPISecurity(t *testing.T) {
	w := newWorld(t)
	o := w.pay("s6", w.lURL, "/p/mug", "legitgifts", "q-mug", "24.00", []string{"Ceramic mug"})
	call := func(method, path, merchant, secret, body string) int {
		req, _ := http.NewRequest(method, w.apiS.URL+path, strings.NewReader(body))
		req.Header.Set("X-Merchant-Id", merchant)
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	deliverPath := "/merchant/v1/orders/" + o.RequestID + "/delivery"
	body := `{"delivered":true,"reference":"X"}`
	// Another merchant, even with its own valid secret, cannot confirm this order, and the
	// answer is the same as for a wrong secret.
	if c := call("POST", deliverPath, "shadyshop", shadySecret, body); c != 401 {
		t.Errorf("another merchant's confirmation = %d, want 401", c)
	}
	if c := call("POST", deliverPath, "legitgifts", "wrong-secret", body); c != 401 {
		t.Errorf("wrong secret = %d", c)
	}
	if c := call("POST", deliverPath, "legitgifts", "", body); c != 401 {
		t.Errorf("no secret = %d", c)
	}
	if c := call("POST", "/merchant/v1/orders/req_nope/delivery", "legitgifts", legitSecret, body); c != 401 {
		t.Errorf("unknown request id = %d, want the same 401", c)
	}
	// The operator token is not a merchant credential.
	if c := call("GET", "/merchant/v1/orders", "legitgifts", "operator-token-123456", ""); c != 401 {
		t.Errorf("operator token as merchant = %d", c)
	}
	if cur, _ := w.plane.Status(o.RequestID); cur.State != settlement.Authorized {
		t.Fatalf("a failed attempt changed the order: %s", cur.State)
	}
	// Repeated failures are throttled.
	var throttled bool
	for i := 0; i < 15; i++ {
		if call("GET", "/merchant/v1/orders", "legitgifts", "guess", "") == http.StatusTooManyRequests {
			throttled = true
		}
	}
	if !throttled {
		t.Error("password guessing is not throttled")
	}
	if c := call("GET", "/merchant/v1/orders", "legitgifts", legitSecret, ""); c != http.StatusTooManyRequests {
		t.Errorf("a throttled client got through: %d", c)
	}
}

func TestStorefrontAndQuotes(t *testing.T) {
	w := newWorld(t)
	if code, page := get(t, w.lURL+"/", ""); code != 200 || !strings.Contains(page, "Ceramic mug") {
		t.Fatalf("index: %d", code)
	}
	if code, page := get(t, w.lURL+"/p/mug", ""); code != 200 || !strings.Contains(page, "Quote ID: q-mug") || !strings.Contains(page, "$24.00") || strings.Contains(page, "Ignore previous") {
		t.Fatalf("mug page: %d %s", code, page)
	}
	if code, body := get(t, w.lURL+"/quotes/q-mug", ""); code != 200 || !strings.Contains(body, `"minor":2400`) || !strings.Contains(body, `"merchant_id":"legitgifts"`) {
		t.Fatalf("quote: %d %s", code, body)
	}
	for _, u := range []string{"/quotes/q-nope", "/p/nope", "/nothing"} {
		if code, _ := get(t, w.lURL+u, ""); code != 404 {
			t.Errorf("%s = %d, want 404", u, code)
		}
	}
	// The back office is closed to anyone without the password.
	if code, _ := get(t, w.lURL+"/admin", ""); code != 401 {
		t.Errorf("admin without a password = %d", code)
	}
	if code, _ := get(t, w.lURL+"/admin", "wrong"); code != 401 {
		t.Errorf("admin with a wrong password = %d", code)
	}
	// A form posted from another site is refused.
	req, _ := http.NewRequest("POST", w.lURL+"/admin/deliver", strings.NewReader("id=x&outcome=shipped"))
	req.SetBasicAuth("admin", adminPW)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Errorf("cross-origin deliver = %d", resp.StatusCode)
	}
}
