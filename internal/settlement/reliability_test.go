package settlement_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

// ---------------------------------------------------------------- gateway doubles

// lostAuthorizeResponse performs the real authorization, then loses the answer:
// PayPal now holds the money but Leash only sees a network error.
type lostAuthorizeResponse struct{ settlement.Gateway }

func (g lostAuthorizeResponse) AuthorizeOrder(ctx context.Context, orderID, reqID string) (*paypal.Order, error) {
	if _, err := g.Gateway.AuthorizeOrder(ctx, orderID, reqID); err != nil {
		return nil, err
	}
	return nil, errors.New("read tcp: connection reset by peer")
}

// refuse makes PayPal answer 422 to one operation (a definitive refusal).
type refuse struct {
	settlement.Gateway
	createOrder, authorize bool
}

func (g refuse) CreateOrder(ctx context.Context, p paypal.CreateOrderParams) (*paypal.Order, error) {
	if g.createOrder {
		return nil, &paypal.APIError{Status: 422, Name: "UNPROCESSABLE_ENTITY", Message: "refused"}
	}
	return g.Gateway.CreateOrder(ctx, p)
}

func (g refuse) AuthorizeOrder(ctx context.Context, orderID, reqID string) (*paypal.Order, error) {
	if g.authorize {
		return nil, &paypal.APIError{Status: 422, Name: "INSTRUMENT_DECLINED", Message: "refused"}
	}
	return g.Gateway.AuthorizeOrder(ctx, orderID, reqID)
}

// slowPayout makes payouts and captures report non-final statuses.
type slowPayout struct {
	settlement.Gateway
	pendingCapture bool
	payoutStatus   *string // the status PayPal currently reports for the payout item
}

func (g slowPayout) Capture(ctx context.Context, authID string, p paypal.CaptureParams) (*paypal.Capture, error) {
	c, err := g.Gateway.Capture(ctx, authID, p)
	if err == nil && g.pendingCapture {
		c.Status = "PENDING"
	}
	return c, err
}

func (g slowPayout) CreatePayout(ctx context.Context, p paypal.PayoutParams) (*paypal.PayoutBatch, error) {
	b, err := g.Gateway.CreatePayout(ctx, p)
	if err == nil && g.payoutStatus != nil {
		g.override(b)
	}
	return b, err
}

func (g slowPayout) GetPayout(ctx context.Context, id string) (*paypal.PayoutBatch, error) {
	b, err := g.Gateway.GetPayout(ctx, id)
	if err == nil && g.payoutStatus != nil {
		g.override(b)
	}
	return b, err
}

func (g slowPayout) override(b *paypal.PayoutBatch) {
	b.BatchHeader.BatchStatus = *g.payoutStatus
	for i := range b.Items {
		b.Items[i].TransactionStatus = *g.payoutStatus
	}
}

// spy records the order parameters the engine sends.
type spy struct {
	settlement.Gateway
	last *paypal.CreateOrderParams
}

func (g *spy) CreateOrder(ctx context.Context, p paypal.CreateOrderParams) (*paypal.Order, error) {
	g.last = &p
	return g.Gateway.CreateOrder(ctx, p)
}

// ---------------------------------------------------------------- unknown vs refused

func TestLostAuthorizeResponseAdoptsTheExistingHold(t *testing.T) {
	e := newEnv(t, opts{vault: true, wrap: func(g settlement.Gateway) settlement.Gateway { return lostAuthorizeResponse{g} }})
	r := e.approved("k1", "24.00")
	got, err := e.eng.Authorize(context.Background(), r.ID)
	if err != nil || got.State != settlement.Authorized || got.AuthorizationID == "" {
		t.Fatalf("the hold PayPal already placed must be adopted, got err=%v %+v", err, got)
	}
	if st := e.fake.Stats(); st.HeldMinor != 2400 {
		t.Fatalf("%+v", st)
	}
	e.mustVerify()
}

func TestReconcilePlacesTheHoldAfterAnOutage(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	r := e.approved("k1", "24.00")
	e.fake.FailNext = 50
	if _, err := e.eng.Authorize(context.Background(), r.ID); !errors.Is(err, settlement.ErrOutcomeUnknown) {
		t.Fatalf("err = %v", err)
	}
	e.fake.FailNext = 0 // PayPal is back
	changed, err := e.eng.Reconcile(context.Background())
	if err != nil || len(changed) != 1 || changed[0] != r.ID {
		t.Fatalf("reconcile: %v %v", changed, err)
	}
	if got, _ := e.eng.Get(r.ID); got.State != settlement.Authorized {
		t.Fatalf("state = %s", got.State)
	}
	if st := e.fake.Stats(); st.HeldMinor != 2400 {
		t.Fatalf("exactly one hold expected: %+v", st)
	}
	// Running it again changes nothing and cannot double-hold.
	if changed, err := e.eng.Reconcile(context.Background()); err != nil || len(changed) != 0 {
		t.Fatalf("second reconcile: %v %v", changed, err)
	}
	if st := e.fake.Stats(); st.HeldMinor != 2400 {
		t.Fatalf("%+v", st)
	}
}

func TestDefinitiveRefusalDeniesAtEitherStep(t *testing.T) {
	for name, g := range map[string]refuse{"create order": {createOrder: true}, "authorize": {authorize: true}} {
		g := g
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, opts{vault: true, wrap: func(in settlement.Gateway) settlement.Gateway { g.Gateway = in; return g }})
			r := e.approved("k1", "24.00")
			if _, err := e.eng.Authorize(context.Background(), r.ID); err == nil || errors.Is(err, settlement.ErrOutcomeUnknown) {
				t.Fatalf("err = %v, want a definitive error", err)
			}
			if got, _ := e.eng.Get(r.ID); got.State != settlement.Denied {
				t.Fatalf("state = %s, want DENIED", got.State)
			}
			if st := e.fake.Stats(); st.HeldMinor != 0 {
				t.Fatalf("%+v", st)
			}
		})
	}
}

func TestFallbackOrderCarriesReturnUrlsAndNoShipping(t *testing.T) {
	var s *spy
	e := newEnv(t, opts{vault: false, wrap: func(g settlement.Gateway) settlement.Gateway { s = &spy{Gateway: g}; return s },
		tune: func(c *settlement.Config) {
			c.ReturnURL, c.CancelURL = "https://leash.example/return", "https://leash.example/cancel"
		}})
	r := e.approved("k1", "10.00")
	if _, err := e.eng.Authorize(context.Background(), r.ID); !errors.Is(err, settlement.ErrBuyerApprovalRequired) {
		t.Fatalf("err = %v", err)
	}
	if s.last == nil || !s.last.NoShipping || s.last.ReturnURL != "https://leash.example/return" || s.last.CancelURL != "https://leash.example/cancel" {
		t.Fatalf("fallback order params: %+v", s.last)
	}

	// With a vaulted method the payment source is used as given.
	var s2 *spy
	e2 := newEnv(t, opts{vault: true, wrap: func(g settlement.Gateway) settlement.Gateway { s2 = &spy{Gateway: g}; return s2 }})
	r2 := e2.approved("k1", "10.00")
	if _, err := e2.eng.Authorize(context.Background(), r2.ID); err != nil {
		t.Fatal(err)
	}
	if s2.last.NoShipping || s2.last.PaymentSource == nil {
		t.Fatalf("vaulted order params: %+v", s2.last)
	}
}

// ---------------------------------------------------------------- guard and expiry

func TestGuardVoidsInsteadOfPlacingAHold(t *testing.T) {
	e := newEnv(t, opts{vault: true, tune: func(c *settlement.Config) {
		c.Guard = func(*settlement.Request) (bool, string) {
			return false, "Your mandate was revoked, so nothing was held."
		}
	}})
	r := e.approved("k1", "24.00")
	got, err := e.eng.Authorize(context.Background(), r.ID)
	if !errors.Is(err, settlement.ErrGuardRejected) || got.State != settlement.Voided {
		t.Fatalf("err=%v %+v", err, got)
	}
	if st := e.fake.Stats(); st.HeldMinor != 0 {
		t.Fatalf("nothing may be held: %+v", st)
	}
}

func TestApprovedRequestsExpireWhenTheBuyerNeverApproves(t *testing.T) {
	e := newEnv(t, opts{vault: false})
	r := e.approved("k1", "10.00")
	if _, err := e.eng.Authorize(context.Background(), r.ID); !errors.Is(err, settlement.ErrBuyerApprovalRequired) {
		t.Fatal(err)
	}
	e.clk.add(4 * time.Hour)
	changed, err := e.eng.Sweep(context.Background())
	if err != nil || len(changed) != 1 {
		t.Fatalf("sweep: %v %v", changed, err)
	}
	if got, _ := e.eng.Get(r.ID); got.State != settlement.Expired {
		t.Fatalf("state = %s", got.State)
	}
}

// ---------------------------------------------------------------- capture and payout

func TestFailedCaptureIsRetriedByReconcile(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	if _, err := e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true}); err != nil {
		t.Fatal(err)
	}
	e.fake.FailNext = 50
	if _, err := e.eng.Settle(ctx, r.ID); err == nil {
		t.Fatal("expected the capture to fail")
	}
	if got, _ := e.eng.Get(r.ID); got.State != settlement.Delivered {
		t.Fatalf("state = %s", got.State)
	}
	e.fake.FailNext = 0
	if changed, err := e.eng.Reconcile(ctx); err != nil || len(changed) != 1 {
		t.Fatalf("reconcile: %v %v", changed, err)
	}
	if got, _ := e.eng.Get(r.ID); got.State != settlement.PaidOut {
		t.Fatalf("state = %s, want PAID_OUT", got.State)
	}
	if st := e.fake.Stats(); st.CapturedMinor != 2400 || st.PaidOut["legitgifts@sandbox.example"] != 2400 {
		t.Fatalf("exactly one capture and one payout expected: %+v", st)
	}
	e.mustVerify()
}

func TestInspectionWindowKeepsTheHoldAndAllowsAProblemReport(t *testing.T) {
	tune := func(c *settlement.Config) { c.InspectionPeriod = 24 * time.Hour }
	ctx := context.Background()

	// The buyer reports a problem inside the window: released, never charged.
	e := newEnv(t, opts{vault: true, tune: tune})
	r := e.authorized("k1", "24.00")
	r, err := e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})
	if err != nil || r.State != settlement.Delivered || r.CaptureAfter.IsZero() {
		t.Fatalf("%v %+v", err, r)
	}
	if got, err := e.eng.SettleIfDue(ctx, r.ID); err != nil || got.State != settlement.Delivered {
		t.Fatalf("must not capture inside the window: %v %+v", err, got)
	}
	if st := e.fake.Stats(); st.CapturedMinor != 0 || st.HeldMinor != 2400 {
		t.Fatalf("%+v", st)
	}
	if got, err := e.eng.Void(ctx, r.ID, "item was not as described"); err != nil || got.State != settlement.Voided {
		t.Fatalf("%v %+v", err, got)
	}
	if st := e.fake.Stats(); st.HeldMinor != 0 || st.CapturedMinor != 0 {
		t.Fatalf("buyer must not be charged: %+v", st)
	}

	// No problem: it settles once the window has passed.
	e2 := newEnv(t, opts{vault: true, tune: tune})
	r2 := e2.authorized("k1", "24.00")
	if _, err := e2.eng.ConfirmDelivery(ctx, r2.ID, settlement.Delivery{Delivered: true}); err != nil {
		t.Fatal(err)
	}
	e2.clk.add(25 * time.Hour)
	if got, err := e2.eng.SettleIfDue(ctx, r2.ID); err != nil || got.State != settlement.PaidOut {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestALapsingHoldIsSettledBeforeTheInspectionWindowEnds(t *testing.T) {
	e := newEnv(t, opts{vault: true, tune: func(c *settlement.Config) { c.InspectionPeriod = 90 * 24 * time.Hour }})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	if _, err := e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true}); err != nil {
		t.Fatal(err)
	}
	e.clk.add(r.HoldExpiresAt.Sub(e.clk.now()) - time.Hour) // inside the safety margin
	got, err := e.eng.SettleIfDue(ctx, r.ID)
	if err != nil || got.State != settlement.PaidOut {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestAPendingCaptureDoesNotPayTheMerchant(t *testing.T) {
	e := newEnv(t, opts{vault: true, wrap: func(g settlement.Gateway) settlement.Gateway { return slowPayout{Gateway: g, pendingCapture: true} }})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	if _, err := e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true}); err != nil {
		t.Fatal(err)
	}
	got, err := e.eng.Settle(ctx, r.ID)
	if err != nil || got.State != settlement.CapturePending || got.CaptureID == "" {
		t.Fatalf("%v %+v", err, got)
	}
	if st := e.fake.Stats(); len(st.PaidOut) != 0 {
		t.Fatalf("merchant must not be paid before PayPal confirms: %+v", st)
	}
	if _, err := e.eng.CaptureCompleted(r.ID, "someone-elses-capture"); err == nil {
		t.Fatal("a confirmation for a different capture must be refused")
	}
	if got, err = e.eng.CaptureCompleted(r.ID, got.CaptureID); err != nil || got.State != settlement.Captured {
		t.Fatalf("%v %+v", err, got)
	}
	if changed, err := e.eng.Reconcile(ctx); err != nil || len(changed) != 1 {
		t.Fatalf("reconcile: %v %v", changed, err)
	}
	if got, _ := e.eng.Get(r.ID); got.State != settlement.PaidOut {
		t.Fatalf("state = %s", got.State)
	}
}

func TestADeniedPendingCaptureReturnsToDelivered(t *testing.T) {
	e := newEnv(t, opts{vault: true, wrap: func(g settlement.Gateway) settlement.Gateway { return slowPayout{Gateway: g, pendingCapture: true} }})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})
	got, _ := e.eng.Settle(ctx, r.ID)
	got, err := e.eng.CaptureDenied(r.ID, got.CaptureID, "issuer declined")
	if err != nil || got.State != settlement.Delivered || got.CaptureAttempts != 1 || got.CaptureID != "" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestPayoutIsNotPaidUntilPayPalConfirmsIt(t *testing.T) {
	status := "PENDING"
	e := newEnv(t, opts{vault: true, wrap: func(g settlement.Gateway) settlement.Gateway { return slowPayout{Gateway: g, payoutStatus: &status} }})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})
	got, err := e.eng.Settle(ctx, r.ID)
	if err != nil || got.State != settlement.PayoutPending {
		t.Fatalf("%v %+v", err, got)
	}
	if changed, _ := e.eng.Reconcile(ctx); len(changed) != 0 {
		t.Fatalf("still pending, nothing should change: %v", changed)
	}
	status = "SUCCESS"
	if changed, err := e.eng.Reconcile(ctx); err != nil || len(changed) != 1 {
		t.Fatalf("%v %v", changed, err)
	}
	if got, _ := e.eng.Get(r.ID); got.State != settlement.PaidOut {
		t.Fatalf("state = %s", got.State)
	}
}

func TestAFailedPayoutReturnsToCapturedAndRetriesWithANewBatch(t *testing.T) {
	status := "FAILED"
	e := newEnv(t, opts{vault: true, wrap: func(g settlement.Gateway) settlement.Gateway { return slowPayout{Gateway: g, payoutStatus: &status} }})
	ctx := context.Background()
	r := e.authorized("k1", "24.00")
	e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})
	if _, err := e.eng.Settle(ctx, r.ID); err == nil {
		t.Fatal("a failed payout must be reported")
	}
	got, _ := e.eng.Get(r.ID)
	if got.State != settlement.Captured || got.PayoutAttempts != 1 {
		t.Fatalf("funds must stay in escrow and be retryable: %+v", got)
	}
	status = "SUCCESS"
	if got, err := e.eng.Payout(ctx, r.ID); err != nil || got.State != settlement.PaidOut {
		t.Fatalf("retry must use a fresh batch id and succeed: %v %+v", err, got)
	}
}

// ---------------------------------------------------------------- storage

func TestSettlementStoreRepairsATornFinalSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.jsonl")
	st, err := settlement.OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, opts{vault: true, store: st})
	r := e.authorized("k1", "24.00")
	st.Close()

	appendRaw(t, path, `{"id":"req_x","mandate_id":"m_01","sta`) // power cut mid-write

	st2, err := settlement.OpenFileStore(path)
	if err != nil {
		t.Fatalf("a torn tail must not stop startup: %v", err)
	}
	defer st2.Close()
	if st2.Repaired() == 0 {
		t.Error("the repair should be reported")
	}
	loaded, err := st2.Load()
	if err != nil || len(loaded) != 1 || loaded[0].ID != r.ID || loaded[0].State != settlement.Authorized {
		t.Fatalf("%v %+v", err, loaded)
	}
}

func TestSettlementStoreRejectsCorruptionInTheMiddle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.jsonl")
	st, _ := settlement.OpenFileStore(path)
	e := newEnv(t, opts{vault: true, store: st})
	e.authorized("k1", "24.00")
	st.Close()
	appendRaw(t, path, "{not json}\n"+`{"id":"req_y"}`+"\n") // a complete bad line followed by more data
	if _, err := settlement.OpenFileStore(path); err == nil {
		t.Fatal("corruption that is not a torn tail must stop startup")
	}
}
