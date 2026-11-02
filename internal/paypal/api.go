package paypal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Adityaraj-star/leash/internal/money"
)

// ---------- shared types ----------

// Money is PayPal's Orders/Payments amount object.
type Money struct {
	CurrencyCode string `json:"currency_code"`
	Value        string `json:"value"`
}

// MoneyFrom converts an Amount to PayPal's string form (the only place floats-as-strings appear).
func MoneyFrom(a money.Amount) Money { return Money{CurrencyCode: a.Currency, Value: a.String()} }

// ToAmount parses PayPal's string amount back into minor units.
func (m Money) ToAmount() (money.Amount, error) { return money.Parse(m.Value, m.CurrencyCode) }

type Link struct {
	Href   string `json:"href"`
	Rel    string `json:"rel"`
	Method string `json:"method"`
}

type Authorization struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	Amount         Money  `json:"amount"`
	CreateTime     string `json:"create_time"`
	ExpirationTime string `json:"expiration_time"`
	Links          []Link `json:"links"`
}

type Capture struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Amount       Money  `json:"amount"`
	FinalCapture bool   `json:"final_capture"`
	CreateTime   string `json:"create_time"`
	Links        []Link `json:"links"`
}

type Refund struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Amount Money  `json:"amount"`
}

type Payments struct {
	Authorizations []Authorization `json:"authorizations"`
	Captures       []Capture       `json:"captures"`
}

type PurchaseUnit struct {
	ReferenceID string    `json:"reference_id"`
	Amount      *Money    `json:"amount"`
	Payments    *Payments `json:"payments"`
}

type Order struct {
	ID            string         `json:"id"`
	Status        string         `json:"status"`
	Intent        string         `json:"intent"`
	Links         []Link         `json:"links"`
	PurchaseUnits []PurchaseUnit `json:"purchase_units"`
}

// ApproveURL returns the buyer-approval link, if the order needs one.
func (o *Order) ApproveURL() string {
	for _, l := range o.Links {
		if l.Rel == "approve" || l.Rel == "payer-action" {
			return l.Href
		}
	}
	return ""
}

// Authorization returns the first authorization on the order, if any.
func (o *Order) Authorization() *Authorization {
	for _, pu := range o.PurchaseUnits {
		if pu.Payments != nil && len(pu.Payments.Authorizations) > 0 {
			return &pu.Payments.Authorizations[0]
		}
	}
	return nil
}

// ---------- Orders v2 ----------

// CreateOrderParams describes an order. With Intent "AUTHORIZE" the funds are
// held, not taken: this is Leash's escrow primitive.
type CreateOrderParams struct {
	Intent      string // "AUTHORIZE" (default) or "CAPTURE"
	Amount      money.Amount
	ReferenceID string
	Description string
	CustomID    string
	InvoiceID   string
	// PaymentSource is passed through untouched (for example a vaulted PayPal
	// payment method). Its exact shape is what spike S2 must establish.
	PaymentSource map[string]any
	// NoShipping tells PayPal's checkout not to ask for a shipping address
	// (Leash buys digital goods). Ignored when PaymentSource is set.
	NoShipping bool
	// ReturnURL and CancelURL are where the buyer lands after approving. Only
	// used together with NoShipping.
	ReturnURL, CancelURL string
	RequestID            string // required
}

// CreateOrder creates an order (POST /v2/checkout/orders).
func (c *Client) CreateOrder(ctx context.Context, p CreateOrderParams) (*Order, error) {
	if err := requireID(p.RequestID); err != nil {
		return nil, err
	}
	if p.Intent == "" {
		p.Intent = "AUTHORIZE"
	}
	if p.Intent != "AUTHORIZE" && p.Intent != "CAPTURE" {
		return nil, fmt.Errorf("paypal: unsupported intent %q", p.Intent)
	}
	if p.Amount.Minor <= 0 || !money.ValidCurrency(p.Amount.Currency) {
		return nil, errors.New("paypal: order amount must be positive with a valid currency")
	}
	pu := map[string]any{"amount": MoneyFrom(p.Amount)}
	if p.ReferenceID != "" {
		pu["reference_id"] = p.ReferenceID
	}
	if p.Description != "" {
		pu["description"] = p.Description
	}
	if p.CustomID != "" {
		pu["custom_id"] = p.CustomID
	}
	if p.InvoiceID != "" {
		pu["invoice_id"] = p.InvoiceID
	}
	body := map[string]any{"intent": p.Intent, "purchase_units": []any{pu}}
	if p.PaymentSource != nil {
		body["payment_source"] = p.PaymentSource
	} else if p.NoShipping {
		ctxt := map[string]any{"shipping_preference": "NO_SHIPPING", "user_action": "PAY_NOW"}
		if p.ReturnURL != "" {
			ctxt["return_url"] = p.ReturnURL
		}
		if p.CancelURL != "" {
			ctxt["cancel_url"] = p.CancelURL
		}
		body["payment_source"] = map[string]any{"paypal": map[string]any{"experience_context": ctxt}}
	}
	var o Order
	if err := c.do(ctx, http.MethodPost, "/v2/checkout/orders", body, &o, p.RequestID); err != nil {
		return nil, err
	}
	return &o, nil
}

// GetOrder fetches an order.
func (c *Client) GetOrder(ctx context.Context, orderID string) (*Order, error) {
	var o Order
	if err := c.do(ctx, http.MethodGet, "/v2/checkout/orders/"+url.PathEscape(orderID), nil, &o, ""); err != nil {
		return nil, err
	}
	return &o, nil
}

// AuthorizeOrder authorizes an approved order, placing the hold
// (POST /v2/checkout/orders/{id}/authorize).
func (c *Client) AuthorizeOrder(ctx context.Context, orderID, requestID string) (*Order, error) {
	if err := requireID(requestID); err != nil {
		return nil, err
	}
	var o Order
	if err := c.do(ctx, http.MethodPost, "/v2/checkout/orders/"+url.PathEscape(orderID)+"/authorize", nil, &o, requestID); err != nil {
		return nil, err
	}
	return &o, nil
}

// ---------- Payments v2 ----------

// GetAuthorization fetches an authorization (status, expiry).
func (c *Client) GetAuthorization(ctx context.Context, authID string) (*Authorization, error) {
	var a Authorization
	if err := c.do(ctx, http.MethodGet, "/v2/payments/authorizations/"+url.PathEscape(authID), nil, &a, ""); err != nil {
		return nil, err
	}
	return &a, nil
}

// CaptureParams controls a capture. Amount nil captures the full authorization.
type CaptureParams struct {
	Amount       *money.Amount
	FinalCapture bool // true releases the remainder of the hold
	InvoiceID    string
	NoteToPayer  string
	RequestID    string // required
}

// Capture takes funds from an authorization (POST .../authorizations/{id}/capture).
func (c *Client) Capture(ctx context.Context, authID string, p CaptureParams) (*Capture, error) {
	if err := requireID(p.RequestID); err != nil {
		return nil, err
	}
	body := map[string]any{"final_capture": p.FinalCapture}
	if p.Amount != nil {
		if p.Amount.Minor <= 0 {
			return nil, errors.New("paypal: capture amount must be positive")
		}
		body["amount"] = MoneyFrom(*p.Amount)
	}
	if p.InvoiceID != "" {
		body["invoice_id"] = p.InvoiceID
	}
	if p.NoteToPayer != "" {
		body["note_to_payer"] = p.NoteToPayer
	}
	var cp Capture
	if err := c.do(ctx, http.MethodPost, "/v2/payments/authorizations/"+url.PathEscape(authID)+"/capture", body, &cp, p.RequestID); err != nil {
		return nil, err
	}
	return &cp, nil
}

// Void releases an authorization so the buyer is never charged
// (POST .../authorizations/{id}/void). PayPal answers 204 or 200.
func (c *Client) Void(ctx context.Context, authID, requestID string) error {
	if err := requireID(requestID); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/v2/payments/authorizations/"+url.PathEscape(authID)+"/void", nil, nil, requestID)
}

// GetCapture fetches a capture. Its status moves from PENDING to COMPLETED or
// DECLINED, so polling it needs no public webhook URL.
func (c *Client) GetCapture(ctx context.Context, captureID string) (*Capture, error) {
	var cp Capture
	if err := c.do(ctx, http.MethodGet, "/v2/payments/captures/"+url.PathEscape(captureID), nil, &cp, ""); err != nil {
		return nil, err
	}
	return &cp, nil
}

// RefundParams controls a refund. Amount nil refunds the full capture.
type RefundParams struct {
	Amount      *money.Amount
	NoteToPayer string
	RequestID   string // required
}

// RefundCapture refunds a capture (POST /v2/payments/captures/{id}/refund).
func (c *Client) RefundCapture(ctx context.Context, captureID string, p RefundParams) (*Refund, error) {
	if err := requireID(p.RequestID); err != nil {
		return nil, err
	}
	body := map[string]any{}
	if p.Amount != nil {
		if p.Amount.Minor <= 0 {
			return nil, errors.New("paypal: refund amount must be positive")
		}
		body["amount"] = MoneyFrom(*p.Amount)
	}
	if p.NoteToPayer != "" {
		body["note_to_payer"] = p.NoteToPayer
	}
	var r Refund
	if err := c.do(ctx, http.MethodPost, "/v2/payments/captures/"+url.PathEscape(captureID)+"/refund", body, &r, p.RequestID); err != nil {
		return nil, err
	}
	return &r, nil
}

// ---------- Payouts v1 ----------

// PayoutItem is one recipient. Note: the Payouts API names the currency field
// "currency", unlike Orders/Payments which use "currency_code".
type PayoutItem struct {
	Receiver     string // PayPal account email
	Amount       money.Amount
	Note         string
	SenderItemID string
}

type PayoutParams struct {
	SenderBatchID string // unique per batch
	EmailSubject  string
	Items         []PayoutItem
	RequestID     string // required
}

type PayoutBatch struct {
	BatchHeader struct {
		PayoutBatchID string `json:"payout_batch_id"`
		BatchStatus   string `json:"batch_status"`
	} `json:"batch_header"`
	Items []struct {
		PayoutItemID      string `json:"payout_item_id"`
		TransactionID     string `json:"transaction_id"`
		TransactionStatus string `json:"transaction_status"`
		PayoutItem        struct {
			Receiver string `json:"receiver"`
			Amount   struct {
				Value    string `json:"value"`
				Currency string `json:"currency"`
			} `json:"amount"`
		} `json:"payout_item"`
	} `json:"items"`
}

// CreatePayout pays out to recipients (POST /v1/payments/payouts).
func (c *Client) CreatePayout(ctx context.Context, p PayoutParams) (*PayoutBatch, error) {
	if err := requireID(p.RequestID); err != nil {
		return nil, err
	}
	if p.SenderBatchID == "" || len(p.Items) == 0 {
		return nil, errors.New("paypal: payout needs a sender_batch_id and at least one item")
	}
	type amt struct {
		Value    string `json:"value"`
		Currency string `json:"currency"`
	}
	type item struct {
		RecipientType string `json:"recipient_type"`
		Amount        amt    `json:"amount"`
		Receiver      string `json:"receiver"`
		Note          string `json:"note,omitempty"`
		SenderItemID  string `json:"sender_item_id,omitempty"`
	}
	items := make([]item, 0, len(p.Items))
	for _, it := range p.Items {
		if it.Receiver == "" || it.Amount.Minor <= 0 || !money.ValidCurrency(it.Amount.Currency) {
			return nil, errors.New("paypal: each payout item needs a receiver and a positive amount")
		}
		items = append(items, item{
			RecipientType: "EMAIL",
			Amount:        amt{Value: it.Amount.String(), Currency: it.Amount.Currency},
			Receiver:      it.Receiver, Note: it.Note, SenderItemID: it.SenderItemID,
		})
	}
	body := map[string]any{
		"sender_batch_header": map[string]string{"sender_batch_id": p.SenderBatchID, "email_subject": p.EmailSubject},
		"items":               items,
	}
	var b PayoutBatch
	if err := c.do(ctx, http.MethodPost, "/v1/payments/payouts", body, &b, p.RequestID); err != nil {
		return nil, err
	}
	return &b, nil
}

// GetPayout fetches a payout batch (GET /v1/payments/payouts/{id}).
func (c *Client) GetPayout(ctx context.Context, batchID string) (*PayoutBatch, error) {
	var b PayoutBatch
	if err := c.do(ctx, http.MethodGet, "/v1/payments/payouts/"+url.PathEscape(batchID), nil, &b, ""); err != nil {
		return nil, err
	}
	return &b, nil
}

// ---------- Webhooks ----------

// VerifyWebhook asks PayPal to verify a webhook delivery
// (POST /v1/notifications/verify-webhook-signature). headers are the request
// headers PayPal sent; body is the raw request body, untouched. It returns
// true only for verification_status SUCCESS.
func (c *Client) VerifyWebhook(ctx context.Context, headers http.Header, body []byte, webhookID string) (bool, error) {
	if webhookID == "" {
		return false, errors.New("paypal: webhook id is required")
	}
	if !json.Valid(body) {
		return false, errors.New("paypal: webhook body is not valid JSON")
	}
	get := func(k string) string { return headers.Get(k) }
	fields := []struct{ key, val string }{
		{"auth_algo", get("PAYPAL-AUTH-ALGO")},
		{"cert_url", get("PAYPAL-CERT-URL")},
		{"transmission_id", get("PAYPAL-TRANSMISSION-ID")},
		{"transmission_sig", get("PAYPAL-TRANSMISSION-SIG")},
		{"transmission_time", get("PAYPAL-TRANSMISSION-TIME")},
		{"webhook_id", webhookID},
	}
	// Splice the raw event in byte-for-byte: PayPal verifies the signature over
	// the original body, so it must not be re-marshaled or HTML-escaped.
	var b bytes.Buffer
	b.WriteByte('{')
	for _, f := range fields {
		if f.val == "" && f.key != "webhook_id" {
			return false, fmt.Errorf("paypal: missing webhook header for %s", f.key)
		}
		k, _ := json.Marshal(f.key)
		v, _ := json.Marshal(f.val)
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
		b.WriteByte(',')
	}
	b.WriteString(`"webhook_event":`)
	b.Write(bytes.TrimSpace(body))
	b.WriteByte('}')

	var out struct {
		VerificationStatus string `json:"verification_status"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/notifications/verify-webhook-signature", rawBody(b.Bytes()), &out, ""); err != nil {
		return false, err
	}
	return strings.EqualFold(out.VerificationStatus, "SUCCESS"), nil
}
