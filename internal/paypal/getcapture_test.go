package paypal_test

import (
	"context"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/paypal/paypaltest"
)

func TestGetCaptureReportsTheCurrentStatus(t *testing.T) {
	fake := paypaltest.New()
	base := fake.Start()
	defer fake.Close()
	fake.PendingCaptures = true
	c, err := paypal.New(paypal.Config{ClientID: paypaltest.ClientID, ClientSecret: paypaltest.ClientSecret, BaseURL: base, Sleep: func(time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	amt := money.MustParse("5.00", "USD")
	order, err := c.CreateOrder(ctx, paypal.CreateOrderParams{
		Intent: "AUTHORIZE", Amount: amt, RequestID: "r1",
		PaymentSource: map[string]any{"paypal": map[string]any{"vault_id": "V"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if order, err = c.AuthorizeOrder(ctx, order.ID, "r2"); err != nil {
		t.Fatal(err)
	}
	cp, err := c.Capture(ctx, order.Authorization().ID, paypal.CaptureParams{FinalCapture: true, RequestID: "r3"})
	if err != nil || cp.Status != "PENDING" {
		t.Fatalf("%v %+v", err, cp)
	}
	got, err := c.GetCapture(ctx, cp.ID)
	if err != nil || got.Status != "PENDING" {
		t.Fatalf("%v %+v", err, got)
	}
	fake.SetCaptureStatus(cp.ID, "COMPLETED")
	if got, err = c.GetCapture(ctx, cp.ID); err != nil || got.Status != "COMPLETED" {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := c.GetCapture(ctx, "CAP-nope"); err == nil {
		t.Fatal("an unknown capture must be an error")
	}
}
