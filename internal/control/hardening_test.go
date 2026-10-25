package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/paypal/paypaltest"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

// ---------------------------------------------------------------- fixtures

// lostAuthorizeAnswer performs the real authorization, then loses PayPal's answer.
type lostAuthorizeAnswer struct{ settlement.Gateway }

func (g lostAuthorizeAnswer) AuthorizeOrder(ctx context.Context, orderID, reqID string) (*paypal.Order, error) {
	if _, err := g.Gateway.AuthorizeOrder(ctx, orderID, reqID); err != nil {
		return nil, err
	}
	return nil, errors.New("read tcp: connection reset by peer")
}

// pendingCapture makes PayPal report captures as still PENDING.
type pendingCapture struct{ settlement.Gateway }

func (g pendingCapture) Capture(ctx context.Context, authID string, p paypal.CaptureParams) (*paypal.Capture, error) {
	c, err := g.Gateway.Capture(ctx, authID, p)
	if err == nil {
		c.Status = "PENDING"
	}
	return c, err
}

func buildStrict(t *testing.T, mut func(*Config)) (*harness, error) {
	t.Helper()
	h := newHarness(t, hopts{})
	srv := httptest.NewServer(h.fake.Handler())
	t.Cleanup(srv.Close)
	client, err := paypal.New(paypal.Config{ClientID: paypaltest.ClientID, ClientSecret: paypaltest.ClientSecret, BaseURL: srv.URL, Sleep: func(time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	reg := MapRegistry{
		"legitgifts": {ID: "legitgifts", Name: "LegitGifts", Email: "legitgifts@sandbox.example", Categories: []string{"gifts"}, HasReturnPolicy: true, DeliverySecret: "legit-secret"},
	}
	cfg := Config{
		Gateway: client, Ledger: h.led, Registry: reg, Quotes: h.quote,
		BrowseHosts: []string{strings.TrimPrefix(h.shop.URL, "http://")}, Now: h.clk.now, Logf: func(string, ...any) {},
		PaymentSource: map[string]any{"paypal": map[string]any{"vault_id": "VAULT-1"}},
		Strict:        true, EnrollSecret: "setup-secret",
	}
	if mut != nil {
		mut(&cfg)
	}
	plane, err := New(cfg)
	if err != nil {
		return nil, err
	}
	h.plane = plane
	return h, nil
}

func strictHarness(t *testing.T, mut func(*Config)) *harness {
	t.Helper()
	h, err := buildStrict(t, mut)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) setupStrict() {
	h.t.Helper()
	pub, err := mandate.PublicKeyBytes(h.priv)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.plane.EnrollWithSecret(pub, "setup-secret"); err != nil {
		h.t.Fatal(err)
	}
	h.register(mandateJSON("m_01", "40.00", "40.00", "25.00", true))
}

// legitVia builds a legitimate request whose evidence was read through the connection.
func (h *harness) legitVia(c *AgentConn, mandateID, quoteID, key string) PaymentRequest {
	h.t.Helper()
	r, err := c.Browse(context.Background(), h.shop.URL+"/legit/mug")
	if err != nil {
		h.t.Fatal(err)
	}
	q := h.quote[quoteID]
	return PaymentRequest{MandateID: mandateID, MerchantID: "legitgifts", Items: q.Items, Amount: q.Amount,
		QuoteID: quoteID, EvidenceRefs: []string{r.EvidenceID}, IdempotencyKey: key}
}

func (h *harness) payVia(c *AgentConn, req PaymentRequest) Outcome {
	h.t.Helper()
	o, err := c.RequestPayment(context.Background(), req)
	if err != nil {
		h.t.Fatalf("RequestPayment: %v", err)
	}
	return o
}

func (h *harness) attest(id string) (Outcome, error) {
	return h.plane.AttestDelivery(context.Background(), "legitgifts", "legit-secret", id, settlement.Delivery{Delivered: true, Reference: "trk-1"})
}

// ---------------------------------------------------------------- sessions

func TestStrictRefusesSessionsTheAgentMadeUp(t *testing.T) {
	h := strictHarness(t, nil)
	h.setupStrict()
	if _, err := h.plane.Browse(context.Background(), "made-up", h.shop.URL+"/legit/mug"); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("browse with a made-up session: %v", err)
	}
	if err := h.plane.SetUserMessage("made-up", "hi"); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("user message for a made-up session: %v", err)
	}
	o, err := h.plane.RequestPayment(context.Background(), PaymentRequest{
		Session: "made-up", MandateID: "m_01", MerchantID: "legitgifts", Items: []string{"Ceramic mug"},
		Amount: usd("24.00"), QuoteID: "q-mug", IdempotencyKey: "k-1",
	})
	if err != nil || o.State != settlement.Denied || !strings.Contains(o.Reason, "session") {
		t.Fatalf("%v %+v", err, o)
	}
	h.noMoneyMoved()
}

func TestAnAgentConnectionCannotSwitchSessions(t *testing.T) {
	h := strictHarness(t, nil)
	h.setupStrict()
	conn := h.plane.OpenAgentConn()
	if _, err := conn.Browse(context.Background(), h.shop.URL+"/legit/poisoned"); err != nil {
		t.Fatal(err)
	}
	req := h.legitVia(conn, "m_01", "q-mug", "k-1")
	req.Session = h.plane.NewSession() // an agent trying to pay "from a clean session"
	o := h.payVia(conn, req)
	if o.State == settlement.Authorized {
		t.Fatalf("the poisoned page read on this connection must still count: %+v", o)
	}
	h.noMoneyMoved()
}

func TestSessionsExpire(t *testing.T) {
	h := strictHarness(t, nil)
	conn := h.plane.OpenAgentConn()
	if _, err := conn.Browse(context.Background(), h.shop.URL+"/legit/mug"); err != nil {
		t.Fatal(err)
	}
	h.clk.mu.Lock()
	h.clk.t = h.clk.t.Add(2 * time.Hour)
	h.clk.mu.Unlock()
	if _, err := conn.Browse(context.Background(), h.shop.URL+"/legit/mug"); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("an expired session must be refused: %v", err)
	}
}

func TestOnlyTheUsersOwnWordsCountAsTheUsersInstruction(t *testing.T) {
	h := strictHarness(t, nil)
	pub, _ := mandate.PublicKeyBytes(h.priv)
	h.plane.EnrollWithSecret(pub, "setup-secret")
	h.register(mandateJSON("m_02", "40.00", "40.00", "25.00", false))
	conn := h.plane.OpenAgentConn()
	ev, err := conn.Browse(context.Background(), h.shop.URL+"/legit/mug")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(key string) PaymentRequest {
		return PaymentRequest{MandateID: "m_02", MerchantID: "legitgifts", Items: []string{"Mystery crate"},
			Amount: usd("12.34"), EvidenceRefs: []string{ev.EvidenceID}, IdempotencyKey: key}
	}
	before := h.payVia(conn, mk("k-1"))
	if !strings.Contains(reasons(before), "untrusted web content") {
		t.Fatalf("without the user's words the amount and items are only web content: %s", reasons(before))
	}
	// The USER side supplies the user's words (the agent has no way to).
	if err := h.plane.SetUserMessage(conn.SessionID(), "Please buy the Mystery crate from legitgifts for 12.34"); err != nil {
		t.Fatal(err)
	}
	after := h.payVia(conn, mk("k-2"))
	if strings.Contains(reasons(after), "untrusted web content") {
		t.Fatalf("the user's own words should now back the amount and items: %s", reasons(after))
	}
}

// ---------------------------------------------------------------- who may approve, enroll, refund

func TestSignedApprovalIsTheOnlyWayToApproveInStrictMode(t *testing.T) {
	h := strictHarness(t, nil)
	h.setupStrict()
	conn := h.plane.OpenAgentConn()
	o := h.payVia(conn, h.legitVia(conn, "m_01", "q-lamp", "k-1")) // $32 is over the $25 step-up line
	if o.State != settlement.StepUpPending {
		t.Fatalf("setup: %+v", o)
	}
	ctx := context.Background()
	if _, err := h.plane.ApproveStepUp(ctx, o.RequestID, "anyone"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("an unsigned approval must be refused: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := ApprovalMessage(o.RequestID, "legitgifts", usd("32.00"))
	if sig, _ := mandate.Sign(other, msg); true {
		if _, err := h.plane.ApproveStepUpSigned(ctx, o.RequestID, sig); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("a signature by another key must be refused: %v", err)
		}
	}
	wrong := ApprovalMessage(o.RequestID, "legitgifts", usd("1.00"))
	if sig, _ := mandate.Sign(h.priv, wrong); true {
		if _, err := h.plane.ApproveStepUpSigned(ctx, o.RequestID, sig); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("a signature over a different amount must be refused: %v", err)
		}
	}
	sig, _ := mandate.Sign(h.priv, msg)
	got, err := h.plane.ApproveStepUpSigned(ctx, o.RequestID, sig)
	if err != nil || got.State != settlement.Authorized {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestStrictEnrollmentNeedsTheSecret(t *testing.T) {
	h := strictHarness(t, nil)
	pub, _ := mandate.PublicKeyBytes(h.priv)
	if _, err := h.plane.Enroll(pub); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("plain Enroll must be refused in strict mode: %v", err)
	}
	if _, err := h.plane.EnrollWithSecret(pub, "wrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("a wrong secret must be refused: %v", err)
	}
	if _, err := h.plane.EnrollWithSecret(pub, "setup-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := buildStrict(t, func(c *Config) { c.EnrollSecret = "" }); err == nil {
		t.Fatal("Strict without an EnrollSecret and no enrolled key must not start")
	}
}

func TestTheAgentCannotRefundOrDisputeMoneyThatWasTaken(t *testing.T) {
	h := newHarness(t, hopts{})
	h.setup()
	conn := h.plane.OpenAgentConn()
	o := h.payVia(conn, h.legitVia(conn, "m_01", "q-mug", "k-1"))
	if _, err := h.attest(o.RequestID); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := conn.ReportProblem(ctx, o.RequestID, "please refund me"); !errors.Is(err, ErrNeedsUser) {
		t.Fatalf("after payout only the user may act: %v", err)
	}
	if st, _ := h.plane.Status(o.RequestID); st.State != settlement.PaidOut {
		t.Fatalf("state changed: %+v", st)
	}
	if _, err := h.plane.UserRefund(ctx, o.RequestID, "me", "changed my mind"); !errors.Is(err, settlement.ErrAlreadyPaidOut) {
		t.Fatalf("%v", err)
	}
	if d, err := h.plane.UserDispute(o.RequestID, "me", "never arrived"); err != nil || d.State != settlement.Disputed {
		t.Fatalf("%v %+v", err, d)
	}
	// A different agent connection cannot even see this request.
	other := h.plane.OpenAgentConn()
	if _, err := other.Status(o.RequestID); !errors.Is(err, ErrNotYours) {
		t.Fatalf("%v", err)
	}
	if _, err := other.ReportProblem(ctx, o.RequestID, "x"); !errors.Is(err, ErrNotYours) {
		t.Fatalf("%v", err)
	}
}

// ---------------------------------------------------------------- the guard, retries and the window

func TestAnExpiredMandateCannotGetAHoldFromALateBuyerApproval(t *testing.T) {
	h := strictHarness(t, func(c *Config) { c.PaymentSource = nil }) // the buyer approves in PayPal
	h.setupStrict()
	conn := h.plane.OpenAgentConn()
	o := h.payVia(conn, h.legitVia(conn, "m_01", "q-mug", "k-1"))
	if o.State != settlement.Approved || o.BuyerApprovalURL == "" {
		t.Fatalf("setup: %+v", o)
	}
	req, _ := h.plane.Request(o.RequestID)
	if err := h.fake.ApproveOrder(req.OrderID); err != nil {
		t.Fatal(err)
	}
	h.clk.mu.Lock()
	h.clk.t = h.clk.t.Add(10 * 24 * time.Hour) // the mandate expired on Oct 25
	h.clk.mu.Unlock()
	got, err := h.plane.RetryAuthorize(context.Background(), o.RequestID)
	if err != nil || got.State != settlement.Voided {
		t.Fatalf("%v %+v", err, got)
	}
	if st := h.fake.Stats(); st.HeldMinor != 0 {
		t.Fatalf("nothing may be held for an expired mandate: %+v", st)
	}
}

func TestALostAuthorizeAnswerIsAdoptedNotDenied(t *testing.T) {
	h := strictHarness(t, func(c *Config) { c.Gateway = lostAuthorizeAnswer{c.Gateway} })
	h.setupStrict()
	conn := h.plane.OpenAgentConn()
	o := h.payVia(conn, h.legitVia(conn, "m_01", "q-mug", "k-1"))
	if o.State != settlement.Authorized {
		t.Fatalf("the hold PayPal placed must be adopted: %+v", o)
	}
	if st := h.fake.Stats(); st.HeldMinor != 2400 {
		t.Fatalf("%+v", st)
	}
	h.mustVerify()
}

func TestSweepRetriesAStuckCapture(t *testing.T) {
	h := newHarness(t, hopts{})
	h.setup()
	conn := h.plane.OpenAgentConn()
	o := h.payVia(conn, h.legitVia(conn, "m_01", "q-mug", "k-1"))
	h.fake.FailNext = 50
	if _, err := h.attest(o.RequestID); err == nil {
		t.Fatal("expected the capture to fail")
	}
	if st, _ := h.plane.Status(o.RequestID); st.State != settlement.Delivered {
		t.Fatalf("state = %s", st.State)
	}
	h.fake.FailNext = 0
	if changed, err := h.plane.Sweep(context.Background()); err != nil || len(changed) != 1 {
		t.Fatalf("sweep: %v %v", changed, err)
	}
	if st, _ := h.plane.Status(o.RequestID); st.State != settlement.PaidOut {
		t.Fatalf("state = %s", st.State)
	}
	h.mustVerify()
}

func TestInspectionWindowLetsTheBuyerBackOut(t *testing.T) {
	h := strictHarness(t, func(c *Config) { c.InspectionPeriod = 24 * time.Hour })
	h.setupStrict()
	conn := h.plane.OpenAgentConn()
	o := h.payVia(conn, h.legitVia(conn, "m_01", "q-mug", "k-1"))
	del, err := h.attest(o.RequestID)
	if err != nil || del.State != settlement.Delivered {
		t.Fatalf("%v %+v", err, del)
	}
	if st := h.fake.Stats(); st.CapturedMinor != 0 || st.HeldMinor != 2400 {
		t.Fatalf("still held, not captured: %+v", st)
	}
	got, err := conn.ReportProblem(context.Background(), o.RequestID, "the mug arrived broken")
	if err != nil || got.State != settlement.Voided {
		t.Fatalf("%v %+v", err, got)
	}
	if st := h.fake.Stats(); st.HeldMinor != 0 || st.CapturedMinor != 0 {
		t.Fatalf("the buyer must not be charged: %+v", st)
	}
}

func TestInspectionWindowEndsInPayoutWhenNobodyObjects(t *testing.T) {
	h := strictHarness(t, func(c *Config) { c.InspectionPeriod = 24 * time.Hour })
	h.setupStrict()
	conn := h.plane.OpenAgentConn()
	o := h.payVia(conn, h.legitVia(conn, "m_01", "q-mug", "k-1"))
	if _, err := h.attest(o.RequestID); err != nil {
		t.Fatal(err)
	}
	h.clk.mu.Lock()
	h.clk.t = h.clk.t.Add(25 * time.Hour)
	h.clk.mu.Unlock()
	if _, err := h.plane.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.plane.Status(o.RequestID); st.State != settlement.PaidOut {
		t.Fatalf("state = %s", st.State)
	}
}

func TestAPendingCaptureIsFinishedByItsWebhook(t *testing.T) {
	h := strictHarness(t, func(c *Config) { c.Gateway = pendingCapture{c.Gateway} })
	h.setupStrict()
	conn := h.plane.OpenAgentConn()
	o := h.payVia(conn, h.legitVia(conn, "m_01", "q-mug", "k-1"))
	del, err := h.attest(o.RequestID)
	if err != nil || del.State != settlement.CapturePending {
		t.Fatalf("%v %+v", err, del)
	}
	req, _ := h.plane.Request(o.RequestID)
	got, err := h.plane.OnCaptureCompleted(context.Background(), o.RequestID, req.CaptureID)
	if err != nil || got.State != settlement.PaidOut {
		t.Fatalf("%v %+v", err, got)
	}
}
