package paypal

import (
	"context"
	"net/http"
	"testing"

	"github.com/Adityaraj-star/leash/internal/money"
)

// PayPal's capture reply carries only an id and a status unless asked otherwise.
// Capture must read the capture back so the amount is known.
func TestCaptureReadsBackAMinimalReply(t *testing.T) {
	f := newFake(t, func(n int, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.Write([]byte(`{"id":"CAP1","status":"COMPLETED","links":[]}`))
		case r.URL.Path == "/v2/payments/captures/CAP1":
			w.Write([]byte(`{"id":"CAP1","status":"COMPLETED","amount":{"currency_code":"USD","value":"12.00"},"final_capture":true}`))
		default:
			http.NotFound(w, r)
		}
	})
	c, _, _ := f.client(t)
	amt := money.Amount{Minor: 1200, Currency: "USD"}
	cp, err := c.Capture(context.Background(), "AUTH1", CaptureParams{Amount: &amt, FinalCapture: true, RequestID: "req-1"})
	if err != nil {
		t.Fatal(err)
	}
	if cp.Amount.Value != "12.00" || cp.Amount.CurrencyCode != "USD" || cp.Status != "COMPLETED" {
		t.Fatalf("capture was not read back: %+v", cp)
	}
}
