package paypal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/money"
)

type recorded struct {
	Method string
	Path   string // escaped path
	Header http.Header
	Body   string
}

type fakePayPal struct {
	t          *testing.T
	srv        *httptest.Server
	mu         sync.Mutex
	tokenCalls int
	reqs       []recorded
	handle     func(n int, w http.ResponseWriter, r *http.Request) // n = 1-based API call number
}

func newFake(t *testing.T, handle func(n int, w http.ResponseWriter, r *http.Request)) *fakePayPal {
	f := &fakePayPal{t: t, handle: handle}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/oauth2/token" {
			f.mu.Lock()
			f.tokenCalls++
			n := f.tokenCalls
			f.mu.Unlock()
			id, sec, ok := r.BasicAuth()
			if !ok || id != "id" || sec != "sec" {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":"invalid_client","error_description":"bad creds"}`)
				return
			}
			if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" {
				t.Errorf("bad token request form")
			}
			fmt.Fprintf(w, `{"access_token":"tok%d","expires_in":3600,"token_type":"Bearer"}`, n)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.URL.EscapedPath(), r.Header.Clone(), string(body)})
		n := len(f.reqs)
		f.mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		f.handle(n, w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func (f *fakePayPal) client(t *testing.T) (*Client, *clock, *[]time.Duration) {
	t.Helper()
	ck := &clock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	var sleeps []time.Duration
	c, err := New(Config{
		ClientID: "id", ClientSecret: "sec", BaseURL: f.srv.URL,
		Now:   ck.now,
		Sleep: func(d time.Duration) { sleeps = append(sleeps, d) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, ck, &sleeps
}

func okJSON(body string) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) { io.WriteString(w, body) }
}

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("body is not JSON: %q (%v)", s, err)
	}
	return m
}

func TestNewGuards(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"no creds", Config{BaseURL: SandboxBaseURL}, false},
		{"sandbox default", Config{ClientID: "a", ClientSecret: "b"}, true},
		{"live refused", Config{ClientID: "a", ClientSecret: "b", BaseURL: "https://api-m.paypal.com"}, false},
		{"legacy live refused", Config{ClientID: "a", ClientSecret: "b", BaseURL: "https://api.paypal.com"}, false},
		{"live allowed explicitly", Config{ClientID: "a", ClientSecret: "b", BaseURL: "https://api-m.paypal.com", AllowLive: true}, true},
		{"plain http refused", Config{ClientID: "a", ClientSecret: "b", BaseURL: "http://example.com"}, false},
		{"localhost http ok", Config{ClientID: "a", ClientSecret: "b", BaseURL: "http://127.0.0.1:9999"}, true},
		{"garbage url", Config{ClientID: "a", ClientSecret: "b", BaseURL: "::::"}, false},
	}
	for _, c := range cases {
		_, err := New(c.cfg)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestTokenIsCachedAndRefreshedAfterExpiry(t *testing.T) {
	f := newFake(t, okJSON(`{"id":"O1","status":"CREATED"}`))
	c, ck, _ := f.client(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.GetOrder(ctx, "O1"); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokenCalls != 1 {
		t.Fatalf("token fetched %d times, want 1", f.tokenCalls)
	}
	if got := f.reqs[0].Header.Get("Authorization"); got != "Bearer tok1" {
		t.Errorf("auth header %q", got)
	}
	ck.t = ck.t.Add(2 * time.Hour)
	if _, err := c.GetOrder(ctx, "O1"); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls != 2 || f.reqs[3].Header.Get("Authorization") != "Bearer tok2" {
		t.Fatalf("expired token not refreshed: calls=%d", f.tokenCalls)
	}
}

func TestBadCredentialsSurfaceAsAPIError(t *testing.T) {
	f := newFake(t, okJSON(`{}`))
	c, _ := New(Config{ClientID: "id", ClientSecret: "WRONG", BaseURL: f.srv.URL})
	_, err := c.GetOrder(context.Background(), "O1")
	ae, ok := err.(*APIError)
	if !ok || ae.Status != 401 || ae.Name != "invalid_client" || !strings.Contains(ae.Message, "bad creds") {
		t.Fatalf("err=%#v", err)
	}
	if len(f.reqs) != 0 {
		t.Error("API call made without a token")
	}
}

func TestCreateOrderAuthorizeBody(t *testing.T) {
	f := newFake(t, okJSON(`{"id":"ORD1","status":"PAYER_ACTION_REQUIRED","intent":"AUTHORIZE",
		"links":[{"href":"https://pp/self","rel":"self","method":"GET"},{"href":"https://pp/approve","rel":"payer-action","method":"GET"}]}`))
	c, _, _ := f.client(t)
	o, err := c.CreateOrder(context.Background(), CreateOrderParams{
		Amount: money.MustParse("40.00", "USD"), ReferenceID: "req_1", Description: "gift", CustomID: "m_01",
		RequestID: "idem-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.ID != "ORD1" || o.ApproveURL() != "https://pp/approve" {
		t.Errorf("order=%+v approve=%q", o, o.ApproveURL())
	}
	r := f.reqs[0]
	if r.Method != "POST" || r.Path != "/v2/checkout/orders" {
		t.Errorf("%s %s", r.Method, r.Path)
	}
	if r.Header.Get("PayPal-Request-Id") != "idem-1" || r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("headers: %v", r.Header)
	}
	body := decode(t, r.Body)
	if body["intent"] != "AUTHORIZE" {
		t.Errorf("intent=%v", body["intent"])
	}
	pu := body["purchase_units"].([]any)[0].(map[string]any)
	amt := pu["amount"].(map[string]any)
	if amt["currency_code"] != "USD" || amt["value"] != "40.00" || pu["custom_id"] != "m_01" || pu["reference_id"] != "req_1" {
		t.Errorf("purchase unit: %v", pu)
	}
	if _, has := body["payment_source"]; has {
		t.Error("payment_source should be absent unless given")
	}
}

func TestCreateOrderPaymentSourcePassthrough(t *testing.T) {
	f := newFake(t, okJSON(`{"id":"ORD2"}`))
	c, _, _ := f.client(t)
	_, err := c.CreateOrder(context.Background(), CreateOrderParams{
		Amount: money.MustParse("1.00", "USD"), RequestID: "k",
		PaymentSource: map[string]any{"paypal": map[string]any{"vault_id": "VAULT123"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ps := decode(t, f.reqs[0].Body)["payment_source"].(map[string]any)["paypal"].(map[string]any)
	if ps["vault_id"] != "VAULT123" {
		t.Errorf("payment_source: %v", ps)
	}
}

func TestMutatingCallsValidateBeforeAnyRequest(t *testing.T) {
	f := newFake(t, okJSON(`{}`))
	c, _, _ := f.client(t)
	ctx := context.Background()
	usd := money.MustParse("5.00", "USD")
	bad := []error{
		func() error { _, e := c.CreateOrder(ctx, CreateOrderParams{Amount: usd}); return e }(), // no request id
		func() error {
			_, e := c.CreateOrder(ctx, CreateOrderParams{Amount: money.Amount{}, RequestID: "k"})
			return e
		}(), // zero amount
		func() error {
			_, e := c.CreateOrder(ctx, CreateOrderParams{Amount: usd, Intent: "SALE", RequestID: "k"})
			return e
		}(), // bad intent
		func() error { _, e := c.AuthorizeOrder(ctx, "O", ""); return e }(),
		func() error { _, e := c.Capture(ctx, "A", CaptureParams{}); return e }(),
		func() error {
			_, e := c.Capture(ctx, "A", CaptureParams{RequestID: "k", Amount: &money.Amount{Minor: 0, Currency: "USD"}})
			return e
		}(),
		c.Void(ctx, "A", ""),
		func() error { _, e := c.RefundCapture(ctx, "C", RefundParams{}); return e }(),
		func() error { _, e := c.CreatePayout(ctx, PayoutParams{RequestID: "k"}); return e }(),
		func() error {
			_, e := c.CreatePayout(ctx, PayoutParams{RequestID: "k", SenderBatchID: "b", Items: []PayoutItem{{Receiver: "", Amount: usd}}})
			return e
		}(),
	}
	for i, err := range bad {
		if err == nil {
			t.Errorf("case %d: expected a validation error", i)
		}
	}
	if len(f.reqs) != 0 || f.tokenCalls != 0 {
		t.Errorf("invalid calls reached the network: reqs=%d tokens=%d", len(f.reqs), f.tokenCalls)
	}
}

func TestAuthorizeOrderParsesHold(t *testing.T) {
	f := newFake(t, okJSON(`{"id":"ORD1","status":"COMPLETED","purchase_units":[{"payments":{"authorizations":[
		{"id":"AUTH1","status":"CREATED","amount":{"currency_code":"USD","value":"40.00"},"expiration_time":"2026-11-15T00:00:00Z"}]}}]}`))
	c, _, _ := f.client(t)
	o, err := c.AuthorizeOrder(context.Background(), "ORD1", "idem-2")
	if err != nil {
		t.Fatal(err)
	}
	a := o.Authorization()
	if a == nil || a.ID != "AUTH1" || a.ExpirationTime == "" {
		t.Fatalf("authorization=%+v", a)
	}
	amt, err := a.Amount.ToAmount()
	if err != nil || amt.Minor != 4000 {
		t.Errorf("amount=%v %v", amt, err)
	}
	if f.reqs[0].Path != "/v2/checkout/orders/ORD1/authorize" || f.reqs[0].Header.Get("PayPal-Request-Id") != "idem-2" {
		t.Errorf("request=%+v", f.reqs[0])
	}
}

func TestCapturePartialAndFull(t *testing.T) {
	f := newFake(t, okJSON(`{"id":"CAP1","status":"COMPLETED","final_capture":false,"amount":{"currency_code":"USD","value":"4.00"}}`))
	c, _, _ := f.client(t)
	ctx := context.Background()
	part := money.MustParse("4.00", "USD")
	cp, err := c.Capture(ctx, "AUTH1", CaptureParams{Amount: &part, RequestID: "cap-1", InvoiceID: "INV-1"})
	if err != nil || cp.ID != "CAP1" {
		t.Fatalf("%v %+v", err, cp)
	}
	b := decode(t, f.reqs[0].Body)
	amt := b["amount"].(map[string]any)
	if amt["value"] != "4.00" || amt["currency_code"] != "USD" || b["final_capture"] != false || b["invoice_id"] != "INV-1" {
		t.Errorf("partial capture body: %v", b)
	}
	if f.reqs[0].Path != "/v2/payments/authorizations/AUTH1/capture" {
		t.Errorf("path %s", f.reqs[0].Path)
	}

	if _, err := c.Capture(ctx, "AUTH1", CaptureParams{FinalCapture: true, RequestID: "cap-2"}); err != nil {
		t.Fatal(err)
	}
	b = decode(t, f.reqs[1].Body)
	if _, has := b["amount"]; has || b["final_capture"] != true {
		t.Errorf("full capture body: %v", b)
	}
}

func TestVoidAccepts204(t *testing.T) {
	f := newFake(t, func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	c, _, _ := f.client(t)
	if err := c.Void(context.Background(), "AUTH1", "void-1"); err != nil {
		t.Fatal(err)
	}
	r := f.reqs[0]
	if r.Method != "POST" || r.Path != "/v2/payments/authorizations/AUTH1/void" || r.Header.Get("PayPal-Request-Id") != "void-1" {
		t.Errorf("%+v", r)
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Error("POST must declare JSON even with an empty body")
	}
}

func TestRefundBody(t *testing.T) {
	f := newFake(t, okJSON(`{"id":"REF1","status":"COMPLETED"}`))
	c, _, _ := f.client(t)
	amt := money.MustParse("12.34", "USD")
	r, err := c.RefundCapture(context.Background(), "CAP1", RefundParams{Amount: &amt, NoteToPayer: "item never arrived", RequestID: "ref-1"})
	if err != nil || r.ID != "REF1" {
		t.Fatal(err)
	}
	b := decode(t, f.reqs[0].Body)
	if b["note_to_payer"] != "item never arrived" || b["amount"].(map[string]any)["value"] != "12.34" {
		t.Errorf("%v", b)
	}
	if f.reqs[0].Path != "/v2/payments/captures/CAP1/refund" {
		t.Errorf("path %s", f.reqs[0].Path)
	}
}

func TestPayoutUsesCurrencyNotCurrencyCode(t *testing.T) {
	f := newFake(t, okJSON(`{"batch_header":{"payout_batch_id":"PB1","batch_status":"PENDING"}}`))
	c, _, _ := f.client(t)
	b, err := c.CreatePayout(context.Background(), PayoutParams{
		SenderBatchID: "batch-1", EmailSubject: "Payment from Leash", RequestID: "po-1",
		Items: []PayoutItem{{Receiver: "legitgifts@business.example.com", Amount: money.MustParse("29.99", "USD"), Note: "order 7", SenderItemID: "item-1"}},
	})
	if err != nil || b.BatchHeader.PayoutBatchID != "PB1" {
		t.Fatalf("%v %+v", err, b)
	}
	body := decode(t, f.reqs[0].Body)
	hdr := body["sender_batch_header"].(map[string]any)
	item := body["items"].([]any)[0].(map[string]any)
	amt := item["amount"].(map[string]any)
	if hdr["sender_batch_id"] != "batch-1" || item["recipient_type"] != "EMAIL" || item["receiver"] != "legitgifts@business.example.com" {
		t.Errorf("payout body: %v", body)
	}
	if amt["currency"] != "USD" || amt["value"] != "29.99" {
		t.Errorf("amount: %v", amt)
	}
	if _, wrong := amt["currency_code"]; wrong {
		t.Error("Payouts API uses \"currency\", not \"currency_code\"")
	}
	if f.reqs[0].Path != "/v1/payments/payouts" || f.reqs[0].Header.Get("PayPal-Request-Id") != "po-1" {
		t.Errorf("%+v", f.reqs[0])
	}
}

func TestRetriesIdempotentCallsWithSameRequestID(t *testing.T) {
	f := newFake(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, `{"id":"CAP9","status":"COMPLETED"}`)
	})
	c, _, sleeps := f.client(t)
	cp, err := c.Capture(context.Background(), "AUTH1", CaptureParams{RequestID: "same-key", FinalCapture: true})
	if err != nil || cp.ID != "CAP9" {
		t.Fatalf("%v %+v", err, cp)
	}
	if len(f.reqs) != 3 {
		t.Fatalf("calls=%d want 3", len(f.reqs))
	}
	for i, r := range f.reqs {
		if r.Header.Get("PayPal-Request-Id") != "same-key" || r.Body != f.reqs[0].Body {
			t.Errorf("attempt %d changed request id or body", i)
		}
	}
	if len(*sleeps) != 2 || (*sleeps)[0] != 250*time.Millisecond || (*sleeps)[1] != 500*time.Millisecond {
		t.Errorf("backoff=%v", *sleeps)
	}
}

func TestRetryGivesUpAndReportsLastError(t *testing.T) {
	f := newFake(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Paypal-Debug-Id", "dbg-503")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"name":"SERVICE_UNAVAILABLE","message":"try later"}`)
	})
	c, _, _ := f.client(t)
	_, err := c.GetOrder(context.Background(), "O1")
	ae, ok := err.(*APIError)
	if !ok || ae.Status != 503 || ae.Name != "SERVICE_UNAVAILABLE" || ae.DebugID != "dbg-503" {
		t.Fatalf("err=%#v", err)
	}
	if len(f.reqs) != 3 { // 1 try + 2 retries
		t.Errorf("calls=%d", len(f.reqs))
	}
}

func TestNoRetryOnClientError(t *testing.T) {
	f := newFake(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"name":"UNPROCESSABLE_ENTITY","message":"The requested action could not be performed.",
			"debug_id":"abc123","details":[{"issue":"AUTHORIZATION_VOIDED"}]}`)
	})
	c, _, _ := f.client(t)
	err := c.Void(context.Background(), "AUTH1", "k")
	ae, ok := err.(*APIError)
	if !ok || ae.Status != 422 || ae.Name != "UNPROCESSABLE_ENTITY" || ae.DebugID != "abc123" || !strings.Contains(string(ae.Details), "AUTHORIZATION_VOIDED") {
		t.Fatalf("err=%#v", err)
	}
	if len(f.reqs) != 1 {
		t.Errorf("a 4xx must not be retried (calls=%d)", len(f.reqs))
	}
	if !strings.Contains(ae.Error(), "abc123") {
		t.Error("Error() should include the debug id")
	}
}

func TestUnauthorizedRefreshesTokenOnce(t *testing.T) {
	f := newFake(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer tok1" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"name":"AUTHENTICATION_FAILURE","message":"expired"}`)
			return
		}
		io.WriteString(w, `{"id":"O1"}`)
	})
	c, _, _ := f.client(t)
	if _, err := c.GetOrder(context.Background(), "O1"); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls != 2 || len(f.reqs) != 2 {
		t.Errorf("tokens=%d calls=%d", f.tokenCalls, len(f.reqs))
	}
}

func TestPersistent401DoesNotLoop(t *testing.T) {
	f := newFake(t, func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	c, _, _ := f.client(t)
	_, err := c.GetOrder(context.Background(), "O1")
	if ae, ok := err.(*APIError); !ok || ae.Status != 401 {
		t.Fatalf("err=%v", err)
	}
	if len(f.reqs) != 2 {
		t.Errorf("calls=%d want exactly 2 (one refresh)", len(f.reqs))
	}
}

func TestPathParametersAreEscaped(t *testing.T) {
	f := newFake(t, okJSON(`{}`))
	c, _, _ := f.client(t)
	c.GetOrder(context.Background(), "../payouts/x?y=1")
	if got := f.reqs[0].Path; got != "/v2/checkout/orders/..%2Fpayouts%2Fx%3Fy=1" {
		t.Errorf("path not escaped: %s", got)
	}
}

func TestCancelledContextStopsRetries(t *testing.T) {
	f := newFake(t, func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
	c, _, _ := f.client(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.GetOrder(ctx, "O1"); err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
}

func TestVerifyWebhookSplicesRawBodyByteForByte(t *testing.T) {
	var gotBody string
	f := newFake(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		io.WriteString(w, `{"verification_status":"SUCCESS"}`)
	})
	c, _, _ := f.client(t)
	event := `{"id":"WH-1","event_type":"PAYMENT.CAPTURE.COMPLETED","summary":"a <b> & c","links":[{"href":"https://x/y?a=1&b=2"}]}`
	h := http.Header{}
	h.Set("PAYPAL-AUTH-ALGO", "SHA256withRSA")
	h.Set("PAYPAL-CERT-URL", "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-1")
	h.Set("PAYPAL-TRANSMISSION-ID", "tid-1")
	h.Set("PAYPAL-TRANSMISSION-SIG", "sig==")
	h.Set("PAYPAL-TRANSMISSION-TIME", "2026-10-17T12:00:00Z")
	ok, err := c.VerifyWebhook(context.Background(), h, []byte(event+"\n"), "WH-ID-1")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if !strings.Contains(gotBody, `"webhook_event":`+event+`}`) {
		t.Fatalf("event was altered in transit (it must be passed through byte-for-byte):\n%s", gotBody)
	}
	m := decode(t, gotBody)
	if m["transmission_id"] != "tid-1" || m["webhook_id"] != "WH-ID-1" || m["auth_algo"] != "SHA256withRSA" ||
		m["transmission_sig"] != "sig==" || m["transmission_time"] != "2026-10-17T12:00:00Z" {
		t.Errorf("verification fields: %v", m)
	}
	if len(f.reqs) != 1 {
		t.Errorf("a webhook verification POST has no idempotency key and must not be retried; calls=%d", len(f.reqs))
	}
}

func TestVerifyWebhookFailureAndBadInput(t *testing.T) {
	f := newFake(t, okJSON(`{"verification_status":"FAILURE"}`))
	c, _, _ := f.client(t)
	h := http.Header{}
	for _, k := range []string{"PAYPAL-AUTH-ALGO", "PAYPAL-CERT-URL", "PAYPAL-TRANSMISSION-ID", "PAYPAL-TRANSMISSION-SIG", "PAYPAL-TRANSMISSION-TIME"} {
		h.Set(k, "v")
	}
	ok, err := c.VerifyWebhook(context.Background(), h, []byte(`{"id":"x"}`), "WH")
	if err != nil || ok {
		t.Errorf("FAILURE must verify as false: ok=%v err=%v", ok, err)
	}
	if _, err := c.VerifyWebhook(context.Background(), h, []byte(`not json`), "WH"); err == nil {
		t.Error("invalid JSON body accepted")
	}
	if _, err := c.VerifyWebhook(context.Background(), h, []byte(`{}`), ""); err == nil {
		t.Error("missing webhook id accepted")
	}
	h.Del("PAYPAL-TRANSMISSION-SIG")
	if _, err := c.VerifyWebhook(context.Background(), h, []byte(`{}`), "WH"); err == nil {
		t.Error("missing header accepted")
	}
}

func TestMoneyConversion(t *testing.T) {
	m := MoneyFrom(money.MustParse("7.05", "USD"))
	if m.CurrencyCode != "USD" || m.Value != "7.05" {
		t.Errorf("%+v", m)
	}
	if a, err := (Money{"JPY", "500"}).ToAmount(); err != nil || a.Minor != 500 {
		t.Errorf("%v %v", a, err)
	}
	if _, err := (Money{"USD", "1.2.3"}).ToAmount(); err == nil {
		t.Error("garbage amount parsed")
	}
}
