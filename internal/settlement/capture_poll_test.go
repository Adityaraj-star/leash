package settlement_test

import (
	"context"
	"testing"

	"github.com/Adityaraj-star/leash/internal/settlement"
)

// PayPal reports the capture as PENDING; Reconcile polls it and pays the merchant
// only after it completes. No webhook or public URL is involved.
func TestReconcilePollsAPendingCaptureToCompletion(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	e.fake.PendingCaptures = true
	r := e.authorized("k1", "24.00")
	if _, err := e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true}); err != nil {
		t.Fatal(err)
	}
	got, err := e.eng.Settle(ctx, r.ID)
	if err != nil || got.State != settlement.CapturePending {
		t.Fatalf("%v %+v", err, got)
	}
	if changed, err := e.eng.Reconcile(ctx); err != nil || len(changed) != 0 {
		t.Fatalf("still pending, nothing should move: %v %v", changed, err)
	}
	if st := e.fake.Stats(); len(st.PaidOut) != 0 {
		t.Fatalf("the merchant must not be paid yet: %+v", st)
	}

	if err := e.fake.SetCaptureStatus(got.CaptureID, "COMPLETED"); err != nil {
		t.Fatal(err)
	}
	if changed, err := e.eng.Reconcile(ctx); err != nil || len(changed) != 1 {
		t.Fatalf("reconcile: %v %v", changed, err)
	}
	if cur, _ := e.eng.Get(r.ID); cur.State != settlement.PaidOut {
		t.Fatalf("state = %s, want PAID_OUT", cur.State)
	}
	if st := e.fake.Stats(); st.PaidOut["legitgifts@sandbox.example"] != 2400 {
		t.Fatalf("exactly one payout expected: %+v", st)
	}
	e.mustVerify()
}

func TestReconcileReturnsADeclinedCaptureToDelivered(t *testing.T) {
	e := newEnv(t, opts{vault: true})
	ctx := context.Background()
	e.fake.PendingCaptures = true
	r := e.authorized("k1", "24.00")
	e.eng.ConfirmDelivery(ctx, r.ID, settlement.Delivery{Delivered: true})
	got, _ := e.eng.Settle(ctx, r.ID)
	if err := e.fake.SetCaptureStatus(got.CaptureID, "DECLINED"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.CaptureUpdate(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	cur, _ := e.eng.Get(r.ID)
	if cur.State != settlement.Delivered || cur.CaptureID != "" || cur.CaptureAttempts != 1 {
		t.Fatalf("%+v", cur)
	}
}
