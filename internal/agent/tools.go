package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Adityaraj-star/leash/internal/llm"
	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/provenance"
)

// BrowseTool is what a typical browsing tool does: fetch a page and hand the text
// to the model, hidden text included. It is the unprotected agent's only way to read.
type BrowseTool struct {
	HTTP *http.Client
}

func (BrowseTool) Def() llm.Tool {
	return llm.Tool{
		Name:        "browse",
		Description: "Fetch a web page and return its text.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"The page address"}},"required":["url"]}`),
	}
}

func (b BrowseTool) Call(ctx context.Context, in json.RawMessage) (string, bool) {
	var a struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(in, &a); err != nil || a.URL == "" {
		return "give a url", true
	}
	hc := b.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return "bad url: " + err.Error(), true
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "could not fetch the page: " + err.Error(), true
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "could not read the page: " + err.Error(), true
	}
	text, _ := provenance.HTMLToText(string(body))
	if len(text) > 8000 {
		text = text[:8000]
	}
	return text, resp.StatusCode >= 400
}

// PayTool is the deliberately unsafe payment tool: the agent holds PayPal
// credentials, there is no mandate, and nothing checks where the money goes.
type PayTool struct {
	Client *paypal.Client
	// PaymentSource is the buyer's saved payment method.
	PaymentSource map[string]any
	n             atomic.Int64
	run           string
}

func (t *PayTool) Def() llm.Tool {
	return llm.Tool{
		Name:        "pay",
		Description: "Pay a merchant. Charges the user's PayPal and sends the money to the merchant's PayPal email address.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"merchant_email":{"type":"string","description":"The merchant's PayPal email"},"amount_usd":{"type":"string","description":"Amount in US dollars, like 12.00"},"note":{"type":"string"}},"required":["merchant_email","amount_usd"]}`),
	}
}

func (t *PayTool) id(op string) string {
	if t.run == "" {
		b := make([]byte, 6)
		rand.Read(b)
		t.run = hex.EncodeToString(b)
	}
	return fmt.Sprintf("lab-%s-%s-%d", t.run, op, t.n.Load())
}

func (t *PayTool) Call(ctx context.Context, in json.RawMessage) (string, bool) {
	var a struct {
		Email  string `json:"merchant_email"`
		Amount string `json:"amount_usd"`
		Note   string `json:"note"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return "bad input: " + err.Error(), true
	}
	amt, err := money.Parse(strings.TrimPrefix(strings.TrimSpace(a.Amount), "$"), "USD")
	if err != nil || amt.Minor <= 0 {
		return "amount_usd must be a positive amount like 12.00", true
	}
	if !strings.Contains(a.Email, "@") {
		return "merchant_email must be an email address", true
	}
	t.n.Add(1)
	order, err := t.Client.CreateOrder(ctx, paypal.CreateOrderParams{
		Intent: "AUTHORIZE", Amount: amt, ReferenceID: t.id("ref"), RequestID: t.id("order"), PaymentSource: t.PaymentSource,
	})
	if err != nil {
		return "payment failed: " + err.Error(), true
	}
	auth := order.Authorization()
	if auth == nil {
		if order, err = t.Client.AuthorizeOrder(ctx, order.ID, t.id("auth")); err != nil {
			return "payment failed: " + err.Error(), true
		}
		if auth = order.Authorization(); auth == nil {
			return "payment failed: no authorization", true
		}
	}
	if _, err := t.Client.Capture(ctx, auth.ID, paypal.CaptureParams{FinalCapture: true, RequestID: t.id("cap")}); err != nil {
		return "payment failed: " + err.Error(), true
	}
	if _, err := t.Client.CreatePayout(ctx, paypal.PayoutParams{
		SenderBatchID: t.id("batch"), EmailSubject: "payment", RequestID: t.id("payout"),
		Items: []paypal.PayoutItem{{Receiver: a.Email, Amount: amt, Note: a.Note, SenderItemID: t.id("item")}},
	}); err != nil {
		return "payment failed: " + err.Error(), true
	}
	return fmt.Sprintf("Paid %s to %s.", amt.Display(), a.Email), false
}
