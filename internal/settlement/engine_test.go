package settlement_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/ledger"
	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/paypal/paypaltest"
	"github.com/Adityaraj-star/leash/internal/policy"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t    *testing.T
	fake *paypaltest.Server
	led  *ledger.Ledger
	eng  *settlement.Engine
	clk  *clock
	gw   settlement.Gateway
}

type opts struct {
	vault    bool // pass a payment source (no buyer redirect)
	store    settlement.Store
	recorder settlement.Recorder
	wrap     func(settlement.Gateway) settlement.Gateway
	tune     func(*settlement.Config) // adjust the engine config before it is built
}

func newEnv(t *testing.T, o opts) *env {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	fake := paypaltest.New()
	fake.SetClock(clk.now)
	url := fake.Start()
	t.Cleanup(fake.Close)

	cl, err := paypal.New(paypal.Config{ClientID: paypaltest.ClientID, ClientSecret: paypaltest.ClientSecret, BaseURL: url, Sleep: func(time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ledger.GenerateKey()
	led, err := ledger.New(ledger.NewMemStore(), priv, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	var gw settlement.Gateway = cl
	if o.wrap != nil {
		gw = o.wrap(gw)
	}
	var rec settlement.Recorder = led
	if o.recorder != nil {
		rec = o.recorder
	}
	cfg := settlement.Config{Gateway: gw, Recorder: rec, Store: o.store, Now: clk.now, Logf: func(string, ...any) {}}
	if o.vault {
		cfg.PaymentSource = map[string]any{"paypal": map[string]any{"vault_id": "VAULT-1"}}
	}
	if o.tune != nil {
		o.tune(&cfg)
	}
	eng, err := settlement.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, fake: fake, led: led, eng: eng, clk: clk, gw: gw}
}

func usd(s string) money.Amount { return money.MustParse(s, "USD") }

func (e *env) open(key string, amt string) *settlement.Request {
	e.t.Helper()
	r, err := e.eng.Open(settlement.OpenInput{
		MandateID: "m_01", MerchantID: "legitgifts", MerchantEmail: "legitgifts@sandbox.example",
		Amount: usd(amt), Items: []string{"Ceramic mug"}, IdempotencyKey: key,
		DeliverBy: e.clk.now().Add(48 * time.Hour),
	})
	if err != nil {
		e.t.Fatalf("open: %v", err)
	}
	return r
}

func (e *env) approved(key, amt string) *settlement.Request {
	e.t.Helper()
	r := e.open(key, amt)
	r, err := e.eng.Decide(r.ID, policy.Decision{Result: policy.Allow}, "")
	if err != nil {
		e.t.Fatalf("decide: %v", err)
	}
	if r.State != settlement.Approved {
		e.t.Fatalf("state = %s, want APPROVED", r.State)
	}
	return r
}

func (e *env) authorized(key, amt string) *settlement.Request {
	e.t.Helper()
	r := e.approved(key, amt)
	r, err := e.eng.Authorize(context.Background(), r.ID)
	if err != nil {
		e.t.Fatalf("authorize: %v", err)
	}
	return r
}

func (e *env) mustVerify() {
	e.t.Helper()
	if res := e.led.Verify(nil); !res.OK {
		e.t.Fatalf("ledger does not verify: %+v", res)
	}
}

func TestHappyPathEscrow(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")

	if r.State != settlement.Authorized || r.AuthorizationID == "" || r.HoldExpiresAt.IsZero() {
		t.Fatalf("not authorized: %+v", r)
	}
	st := e.fake.Stats()
	if st.HeldMinor != 2400 || st.CapturedMinor != 0 || len(st.PaidOut) != 0 {
		t.Fatalf("while held: %+v (buyer must not be charged yet)", st)
	}

	r, err := e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true, Reference: "TRACK-1", Source: "legitgifts"})
	if err != nil || r.State != settlement.Delivered {
		t.Fatalf("confirm delivery: %v %+v", err, r)
	}
	r, err = e.eng.Settle(ctx, r.ID)
	if err != nil || r.State != settlement.PaidOut {
		t.Fatalf("settle: %v %+v", err, r)
	}
	st = e.fake.Stats()
	if st.CapturedMinor != 2400 || st.HeldMinor != 0 || st.PaidOut["legitgifts@sandbox.example"] != 2400 {
		t.Fatalf("after settle: %+v", st)
	}
	if r.CaptureID == "" || r.PayoutBatchID == "" {
		t.Fatalf("missing ids: %+v", r)
	}
	want := []settlement.State{settlement.Evaluated, settlement.Approved, settlement.Authorized, settlement.Delivered, settlement.Captured, settlement.PaidOut}
	if len(r.History) != len(want) {
		t.Fatalf("history = %+v", r.History)
	}
	for i, h := range r.History {
		if h.To != want[i] {
			t.Fatalf("history[%d].To = %s, want %s", i, h.To, want[i])
		}
	}
	e.mustVerify()
}

func TestBuyerApprovalFallback(t *testing.T) {
	e := newEnv(t, opts{vault: false})
	ctx := context.Background()
	r := e.approved("k1", "10.00")

	r, err := e.eng.Authorize(ctx, r.ID)
	if !errors.Is(err, settlement.ErrBuyerApprovalRequired) {
		t.Fatalf("err = %v, want ErrBuyerApprovalRequired", err)
	}
	if r.State != settlement.Approved || r.BuyerApprovalURL == "" || r.OrderID == "" {
		t.Fatalf("expected APPROVED with approval URL: %+v", r)
	}
	if e.fake.Stats().HeldMinor != 0 {
		t.Fatal("nothing must be held before the buyer approves")
	}
	// Calling again before the buyer approves must not create a second order.
	orders := countCalls(e.fake.Calls(), "POST /v2/checkout/orders")
	if _, err := e.eng.Authorize(ctx, r.ID); !errors.Is(err, settlement.ErrBuyerApprovalRequired) {
		t.Fatalf("second try: %v", err)
	}
	if n := countCalls(e.fake.Calls(), "POST /v2/checkout/orders"); n != orders {
		t.Fatalf("created %d orders, want %d", n, orders)
	}

	if err := e.fake.ApproveOrder(r.OrderID); err != nil {
		t.Fatal(err)
	}
	r, err = e.eng.Authorize(ctx, r.ID)
	if err != nil || r.State != settlement.Authorized || r.BuyerApprovalURL != "" {
		t.Fatalf("after buyer approval: %v %+v", err, r)
	}
	if e.fake.Stats().HeldMinor != 1000 {
		t.Fatalf("held = %d", e.fake.Stats().HeldMinor)
	}
}

func countCalls(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if c == prefix {
			n++
		}
	}
	return n
}

func TestFailedDeliveryVoidsAndNeverCharges(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	r := e.authorized("k1", "24.00")
	r, err := e.eng.ConfirmDelivery(context.Background(), r.ID, settlement.Delivery{Delivered: false, Note: "carrier lost the parcel"})
	if err != nil || r.State != settlement.Voided {
		t.Fatalf("%v %+v", err, r)
	}
	st := e.fake.Stats()
	if st.HeldMinor != 0 || st.CapturedMinor != 0 || len(st.PaidOut) != 0 {
		t.Fatalf("buyer must never be charged: %+v", st)
	}
	e.mustVerify()
}

func TestDeniedNeverTouchesPayPal(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	r := e.open("k1", "24.00")
	d := policy.Decision{Result: policy.Deny, Findings: []policy.Finding{{Rule: "R7", Result: policy.Deny, Reason: "Injected page told the agent to pay."}}}
	r, err := e.eng.Decide(r.ID, d, "")
	if err != nil || r.State != settlement.Denied {
		t.Fatalf("%v %+v", err, r)
	}
	if _, err := e.eng.Authorize(context.Background(), r.ID); !errors.Is(err, settlement.ErrBadState) {
		t.Fatalf("authorize on DENIED: %v", err)
	}
	if calls := e.fake.Calls(); len(calls) != 0 {
		t.Fatalf("PayPal was called for a denied request: %v", calls)
	}
	// Even the decisions that are not a clean ALLOW or STEP_UP fail closed.
	r2 := e.open("k2", "5.00")
	r2, _ = e.eng.Decide(r2.ID, policy.Decision{Result: policy.Replay}, "")
	if r2.State != settlement.Denied {
		t.Fatalf("REPLAY must not approve: %s", r2.State)
	}
	r3 := e.open("k3", "5.00")
	r3, _ = e.eng.Decide(r3.ID, policy.Decision{Result: "WHATEVER"}, "")
	if r3.State != settlement.Denied {
		t.Fatalf("unknown result must not approve: %s", r3.State)
	}
}

func TestStepUpFlow(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	stepUp := policy.Decision{Result: policy.StepUp, Findings: []policy.Finding{{Rule: "R6", Result: policy.StepUp, Reason: "Over your limit."}}}

	r := e.open("k1", "30.00")
	r, _ = e.eng.Decide(r.ID, stepUp, "")
	if r.State != settlement.StepUpPending {
		t.Fatalf("state = %s", r.State)
	}
	if _, err := e.eng.Authorize(context.Background(), r.ID); !errors.Is(err, settlement.ErrBadState) {
		t.Fatal("authorize must wait for the human")
	}
	r, err := e.eng.Approve(r.ID, "aditya")
	if err != nil || r.State != settlement.Approved {
		t.Fatalf("%v %+v", err, r)
	}

	// A human can never approve a DENY.
	d := e.open("k2", "30.00")
	d, _ = e.eng.Decide(d.ID, policy.Decision{Result: policy.Deny}, "")
	if _, err := e.eng.Approve(d.ID, "aditya"); !errors.Is(err, settlement.ErrBadState) {
		t.Fatalf("approving a DENIED request: %v", err)
	}

	// Rejecting works, and stale step-ups expire.
	j := e.open("k3", "30.00")
	j, _ = e.eng.Decide(j.ID, stepUp, "")
	if j, err = e.eng.Reject(j.ID, "aditya"); err != nil || j.State != settlement.Denied {
		t.Fatalf("%v %+v", err, j)
	}
	x := e.open("k4", "30.00")
	x, _ = e.eng.Decide(x.ID, stepUp, "")
	e.clk.add(time.Hour)
	changed, err := e.eng.Sweep(context.Background())
	if err != nil || len(changed) != 1 || changed[0] != x.ID {
		t.Fatalf("sweep: %v %v", changed, err)
	}
	if got, _ := e.eng.Get(x.ID); got.State != settlement.Expired {
		t.Fatalf("state = %s", got.State)
	}
}

func TestOutOfOrderOperationsAreRejected(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")

	if _, err := e.eng.Capture(ctx, r.ID); !errors.Is(err, settlement.ErrBadState) {
		t.Fatalf("capture before delivery: %v", err)
	}
	if _, err := e.eng.Payout(ctx, r.ID); !errors.Is(err, settlement.ErrBadState) {
		t.Fatalf("payout before capture: %v", err)
	}
	if _, err := e.eng.Refund(ctx, r.ID, "x"); !errors.Is(err, settlement.ErrBadState) {
		t.Fatalf("refund before capture: %v", err)
	}
	if _, err := e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.Settle(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	// Everything after PAID_OUT is refused, so nothing can pay twice.
	if _, err := e.eng.Settle(ctx, r.ID); !errors.Is(err, settlement.ErrBadState) {
		t.Fatalf("second settle: %v", err)
	}
	if _, err := e.eng.Void(ctx, r.ID, "oops"); !errors.Is(err, settlement.ErrBadState) {
		t.Fatalf("void after payout: %v", err)
	}
	if _, err := e.eng.Refund(ctx, r.ID, "oops"); !errors.Is(err, settlement.ErrAlreadyPaidOut) {
		t.Fatalf("refund after payout: %v", err)
	}
	st := e.fake.Stats()
	if st.CapturedMinor != 2400 || st.PaidOut["legitgifts@sandbox.example"] != 2400 {
		t.Fatalf("money moved more than once: %+v", st)
	}
	if r, err := e.eng.Dispute(r.ID, "item not as described"); err != nil || r.State != settlement.Disputed {
		t.Fatalf("dispute: %v %+v", err, r)
	}
}

func TestRefundAfterCapture(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})
	if _, err := e.eng.Capture(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	r, err := e.eng.Refund(ctx, r.ID, "item arrived broken")
	if err != nil || r.State != settlement.Refunded || r.RefundID == "" {
		t.Fatalf("%v %+v", err, r)
	}
	if e.fake.Stats().RefundedMinor != 2400 || len(e.fake.Stats().PaidOut) != 0 {
		t.Fatalf("%+v", e.fake.Stats())
	}
	e.mustVerify()
}

// A PayPal outage while placing the hold is an UNKNOWN outcome, not a refusal:
// the hold might exist. The request must not be denied (that would orphan a hold
// at PayPal); it stays APPROVED for Reconcile. Nothing is charged either way.
func TestPayPalOutageWhileHoldingIsUnknownNotDenied(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	r := e.approved("k1", "24.00")
	e.fake.FailNext = 50 // PayPal is down for every retry
	_, err := e.eng.Authorize(context.Background(), r.ID)
	if !errors.Is(err, settlement.ErrOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrOutcomeUnknown", err)
	}
	got, _ := e.eng.Get(r.ID)
	if got.State != settlement.Approved {
		t.Fatalf("state = %s, want APPROVED (outcome unknown, not refused)", got.State)
	}
	st := e.fake.Stats()
	if st.HeldMinor != 0 || st.CapturedMinor != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestCaptureFailureStaysDeliveredAndRetriesSafely(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})

	e.fake.FailNext = 50
	if _, err := e.eng.Settle(ctx, r.ID); err == nil {
		t.Fatal("expected failure while PayPal is down")
	}
	if got, _ := e.eng.Get(r.ID); got.State != settlement.Delivered {
		t.Fatalf("state = %s, want DELIVERED so the capture can be retried", got.State)
	}
	e.fake.FailNext = 0
	r, err := e.eng.Settle(ctx, r.ID)
	if err != nil || r.State != settlement.PaidOut {
		t.Fatalf("retry: %v %+v", err, r)
	}
	if st := e.fake.Stats(); st.CapturedMinor != 2400 || st.PaidOut["legitgifts@sandbox.example"] != 2400 {
		t.Fatalf("%+v", st)
	}
}

func TestPayoutFailureLeavesFundsCapturedAndRetryable(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})
	if _, err := e.eng.Capture(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	e.fake.FailNext = 50
	if _, err := e.eng.Payout(ctx, r.ID); err == nil {
		t.Fatal("expected failure")
	}
	if got, _ := e.eng.Get(r.ID); got.State != settlement.Captured {
		t.Fatalf("state = %s", got.State)
	}
	e.fake.FailNext = 0
	if r, err := e.eng.Payout(ctx, r.ID); err != nil || r.State != settlement.PaidOut {
		t.Fatalf("%v %+v", err, r)
	}
	if got := e.fake.Stats().PaidOut["legitgifts@sandbox.example"]; got != 2400 {
		t.Fatalf("paid out %d, want exactly 2400", got)
	}
}

// brokenRecorder simulates the evidence ledger being unavailable.
type brokenRecorder struct{}

func (brokenRecorder) Append(string, any) (ledger.Entry, error) {
	return ledger.Entry{}, errors.New("disk full")
}

func TestNoEvidenceNoMoneyMovement(t *testing.T) {
	// A healthy ledger lets us get to an approved request...
	e := newEnv(t, opts{vault: true})
	r := e.approved("k1", "24.00")
	// ...then swap in an engine whose ledger is broken, sharing the same PayPal.
	broken, err := settlement.New(settlement.Config{Gateway: e.gw, Recorder: brokenRecorder{}, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Open(settlement.OpenInput{MandateID: "m", MerchantID: "x", Amount: usd("1.00"), IdempotencyKey: "z"}); err == nil {
		t.Fatal("Open must fail without a ledger")
	}
	if len(broken.List()) != 0 {
		t.Fatal("a request that could not be recorded must not exist")
	}
	_ = r
	if calls := e.fake.Calls(); len(calls) != 0 {
		t.Fatalf("PayPal called without evidence: %v", calls)
	}
}

func TestIntentIsWrittenBeforeMoneyMoves(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})
	e.eng.Settle(ctx, r.ID)

	entries, err := e.led.Entries()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, en := range entries {
		if en.Type == "settlement.intent" {
			for _, op := range []string{"order", "authorize", "capture", "payout"} {
				if contains(en.Payload, `"op":"`+op+`"`) {
					seen[op] = true
				}
			}
		}
	}
	for _, op := range []string{"order", "authorize", "capture", "payout"} {
		if !seen[op] {
			t.Errorf("no write-ahead intent record for %q", op)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// tamperGateway makes PayPal report a hold for the wrong amount.
type tamperGateway struct{ settlement.Gateway }

func (g tamperGateway) AuthorizeOrder(ctx context.Context, id, rid string) (*paypal.Order, error) {
	o, err := g.Gateway.AuthorizeOrder(ctx, id, rid)
	if err == nil {
		o.PurchaseUnits[0].Payments.Authorizations[0].Amount.Value = "99.00"
	}
	return o, err
}

func TestMismatchedHoldIsReleasedAndDenied(t *testing.T) {
	e := newEnv(t, opts{vault: true, wrap: func(g settlement.Gateway) settlement.Gateway { return tamperGateway{g} }})
	r := e.approved("k1", "24.00")
	if _, err := e.eng.Authorize(context.Background(), r.ID); err == nil {
		t.Fatal("expected an error")
	}
	if got, _ := e.eng.Get(r.ID); got.State != settlement.Denied {
		t.Fatalf("state = %s", got.State)
	}
	if e.fake.Stats().HeldMinor != 0 {
		t.Fatalf("mismatched hold must be released: %+v", e.fake.Stats())
	}
}

func TestSweepReleasesLateAndLapsingHolds(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	late := e.authorized("k1", "10.00") // deliver_by = +48h, hold lasts 72h
	e.clk.add(49 * time.Hour)
	changed, err := e.eng.Sweep(ctx)
	if err != nil || len(changed) != 1 {
		t.Fatalf("sweep: %v %v", changed, err)
	}
	got, _ := e.eng.Get(late.ID)
	if got.State != settlement.Expired {
		t.Fatalf("state = %s", got.State)
	}
	if e.fake.Stats().HeldMinor != 0 {
		t.Fatal("expired request must release its hold")
	}

	// No delivery deadline: the hold itself is about to lapse (72h - 2h safety).
	r, _ := e.eng.Open(settlement.OpenInput{MandateID: "m_02", MerchantID: "legitgifts", MerchantEmail: "x@y.z", Amount: usd("5.00"), IdempotencyKey: "k2"})
	e.eng.Decide(r.ID, policy.Decision{Result: policy.Allow}, "")
	if _, err := e.eng.Authorize(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	e.clk.add(69 * time.Hour)
	if changed, _ := e.eng.Sweep(ctx); len(changed) != 0 {
		t.Fatalf("hold still has margin, nothing should change: %v", changed)
	}
	e.clk.add(2 * time.Hour)
	if changed, _ := e.eng.Sweep(ctx); len(changed) != 1 {
		t.Fatalf("lapsing hold should be released: %v", changed)
	}
	e.mustVerify()
}

func TestOpenDuplicateKeyReturnsOriginal(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	first := e.open("same-key", "24.00")
	dup, err := e.eng.Open(settlement.OpenInput{MandateID: "m_01", MerchantID: "legitgifts", Amount: usd("24.00"), IdempotencyKey: "same-key"})
	if !errors.Is(err, settlement.ErrDuplicateKey) || dup.ID != first.ID {
		t.Fatalf("%v %+v", err, dup)
	}
	if n := len(e.eng.List()); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
	// A different mandate may reuse the key.
	if _, err := e.eng.Open(settlement.OpenInput{MandateID: "m_other", MerchantID: "legitgifts", Amount: usd("1.00"), IdempotencyKey: "same-key"}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSettleMovesMoneyOnce(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})

	var wg sync.WaitGroup
	var ok, bad int32
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.eng.Settle(ctx, r.ID)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
			} else {
				bad++
			}
		}()
	}
	wg.Wait()
	if ok != 1 || bad != 7 {
		t.Fatalf("ok=%d bad=%d, want exactly one success", ok, bad)
	}
	if st := e.fake.Stats(); st.CapturedMinor != 2400 || st.PaidOut["legitgifts@sandbox.example"] != 2400 {
		t.Fatalf("%+v", st)
	}
	e.mustVerify()
}

func TestMandateUsage(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	a := e.authorized("k1", "10.00")
	b := e.approved("k2", "5.00")
	denied := e.open("k3", "7.00")
	e.eng.Decide(denied.ID, policy.Decision{Result: policy.Deny}, "")
	voided := e.authorized("k4", "3.00")
	e.eng.Void(ctx, voided.ID, "changed my mind")

	u := e.eng.MandateUsage("m_01", "", "USD")
	if u.SpentMinor != 1500 || !u.Consumed || len(u.Recent) != 4 {
		t.Fatalf("%+v (denied and voided requests must not count as spend; all four count toward velocity)", u)
	}
	// Excluding a request removes it from its own history.
	u = e.eng.MandateUsage("m_01", b.ID, "USD")
	if u.SpentMinor != 1000 || len(u.Recent) != 3 {
		t.Fatalf("%+v", u)
	}
	_ = a
	if u := e.eng.MandateUsage("nobody", "", "USD"); u.SpentMinor != 0 || u.Consumed {
		t.Fatalf("%+v", u)
	}
}

func TestFileStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.jsonl")
	st, err := settlement.OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, opts{vault: true, store: st})
	r := e.authorized("k1", "24.00")
	st.Close()

	st2, err := settlement.OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	eng2, err := settlement.New(settlement.Config{Gateway: e.gw, Recorder: e.led, Store: st2, Now: e.clk.now, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := eng2.Get(r.ID)
	if err != nil || got.State != settlement.Authorized || got.AuthorizationID != r.AuthorizationID || len(got.History) != len(r.History) {
		t.Fatalf("%v %+v", err, got)
	}
	// The reloaded engine can carry on and finish the payment.
	if _, err := eng2.ConfirmDelivery(context.Background(), r.ID, settlement.Delivery{Delivered: true}); err != nil {
		t.Fatal(err)
	}
	if got, err := eng2.Settle(context.Background(), r.ID); err != nil || got.State != settlement.PaidOut {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestTransitionTable(t *testing.T) {
	all := []settlement.State{settlement.Requested, settlement.Evaluated, settlement.StepUpPending, settlement.Approved, settlement.Authorized,
		settlement.Delivered, settlement.Captured, settlement.PaidOut, settlement.Denied, settlement.Expired, settlement.Voided, settlement.Refunded, settlement.Disputed}
	// No path leads from a failure exit back into the money flow.
	for _, from := range []settlement.State{settlement.Denied, settlement.Expired, settlement.Voided, settlement.Refunded, settlement.Disputed} {
		if !from.Terminal() {
			t.Errorf("%s should be terminal", from)
		}
		for _, to := range all {
			if settlement.CanTransition(from, to) {
				t.Errorf("%s -> %s must be impossible", from, to)
			}
		}
	}
	// Money can only be captured after delivery and paid out after capture.
	for _, from := range all {
		if settlement.CanTransition(from, settlement.Captured) && from != settlement.Delivered {
			t.Errorf("%s -> CAPTURED must be impossible", from)
		}
		if settlement.CanTransition(from, settlement.PaidOut) && from != settlement.Captured {
			t.Errorf("%s -> PAID_OUT must be impossible", from)
		}
		if settlement.CanTransition(from, settlement.Authorized) && from != settlement.Approved {
			t.Errorf("%s -> AUTHORIZED must be impossible", from)
		}
		if settlement.CanTransition(from, settlement.Approved) && from != settlement.Evaluated && from != settlement.StepUpPending {
			t.Errorf("%s -> APPROVED must be impossible", from)
		}
	}
}
