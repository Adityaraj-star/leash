package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/paypal/paypaltest"
)

type result struct {
	Spike, Check string
	OK           bool
	Detail       string
}

type runner struct {
	ctx    context.Context
	c      *paypal.Client
	fake   *paypaltest.Server // nil against the real sandbox
	out    io.Writer
	in     *bufio.Reader
	opts   options
	res    []result
	sleep  func(time.Duration)
	serial int
}

type options struct {
	vaultSource   string
	merchantEmail string
	webhookID     string
	listen        string
	outFile       string
}

func main() {
	var o options
	useFake := flag.Bool("fake", false, "run against the in-process fake instead of the PayPal sandbox")
	flag.StringVar(&o.vaultSource, "vault-source", "", `payment_source JSON for S2, e.g. {"paypal":{"vault_id":"..."}}`)
	flag.StringVar(&o.merchantEmail, "merchant-email", "", "sandbox business account email to pay out to (S3)")
	flag.StringVar(&o.webhookID, "webhook-id", "", "webhook id from the developer dashboard (s3-webhook)")
	flag.StringVar(&o.listen, "listen", ":8080", "address for s3-webhook")
	flag.StringVar(&o.outFile, "out", "docs/spikes.md", "file the results are appended to ('' to skip)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: spike [flags] s1|s2|s3|s3-webhook|s4|all")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(flag.Arg(0), o, *useFake, os.Stdout, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "spike:", err)
		os.Exit(1)
	}
}

func run(which string, o options, useFake bool, out io.Writer, in io.Reader) error {
	loadDotEnv(".env")
	r := &runner{ctx: context.Background(), out: out, in: bufio.NewReader(in), opts: o, sleep: time.Sleep}
	mode := "sandbox"
	cfg := paypal.Config{
		ClientID: os.Getenv("PAYPAL_CLIENT_ID"), ClientSecret: os.Getenv("PAYPAL_CLIENT_SECRET"),
		BaseURL: os.Getenv("PAYPAL_BASE_URL"),
	}
	if useFake {
		mode = "fake"
		r.fake = paypaltest.New()
		cfg = paypal.Config{ClientID: paypaltest.ClientID, ClientSecret: paypaltest.ClientSecret, BaseURL: r.fake.Start()}
		defer r.fake.Close()
		r.sleep = func(time.Duration) {}
	} else if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return errors.New("set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET (sandbox app credentials), or use -fake")
	}
	c, err := paypal.New(cfg)
	if err != nil {
		return err
	}
	r.c = c

	switch which {
	case "s1":
		r.s1()
	case "s2":
		r.s2()
	case "s3":
		r.s3()
	case "s3-webhook":
		return r.webhookListener()
	case "s4":
		r.s4()
	case "all":
		r.s1()
		r.s2()
		r.s3()
		r.s4()
	default:
		return fmt.Errorf("unknown spike %q", which)
	}
	r.report()
	if o.outFile != "" {
		if err := r.appendMarkdown(o.outFile, mode); err != nil {
			return err
		}
		fmt.Fprintf(out, "\nResults appended to %s\n", o.outFile)
	}
	return nil
}

// ------------------------------------------------------------------ helpers

func (r *runner) record(spike, check string, err error, detail string) bool {
	res := result{Spike: spike, Check: check, OK: err == nil, Detail: detail}
	if err != nil {
		res.Detail = describe(err)
		if detail != "" {
			res.Detail = detail + " | " + res.Detail
		}
	}
	r.res = append(r.res, res)
	mark := "PASS"
	if !res.OK {
		mark = "FAIL"
	}
	fmt.Fprintf(r.out, "[%s] %s %s: %s\n", mark, spike, check, res.Detail)
	return res.OK
}

func (r *runner) note(spike, check, detail string) {
	r.res = append(r.res, result{Spike: spike, Check: check, OK: true, Detail: detail})
	fmt.Fprintf(r.out, "[NOTE] %s %s: %s\n", spike, check, detail)
}

func describe(err error) string {
	var ae *paypal.APIError
	if errors.As(err, &ae) {
		return fmt.Sprintf("HTTP %d %s: %s (debug id %s)", ae.Status, ae.Name, ae.Message, ae.DebugID)
	}
	return err.Error()
}

func (r *runner) id(prefix string) string {
	r.serial++
	return fmt.Sprintf("spike-%s-%d-%d", prefix, time.Now().UnixNano(), r.serial)
}

func usd(s string) money.Amount { return money.MustParse(s, "USD") }

// approve gets the buyer's approval for an order: automatic in fake mode, a
// manual step in the sandbox.
func (r *runner) approve(o *paypal.Order) error {
	if r.fake != nil {
		return r.fake.ApproveOrder(o.ID)
	}
	url := o.ApproveURL()
	if url == "" {
		return errors.New("the order has no approval link")
	}
	fmt.Fprintf(r.out, "\n  Open this link, log in as your SANDBOX BUYER and approve the payment:\n  %s\n  Press Enter here when done... ", url)
	_, err := r.in.ReadString('\n')
	return err
}

// ------------------------------------------------------------------ S1

func (r *runner) s1() {
	const s = "S1"
	fmt.Fprintln(r.out, "\n--- S1: Orders AUTHORIZE, authorize, partial capture, void ---")
	order, err := r.c.CreateOrder(r.ctx, paypal.CreateOrderParams{
		Intent: "AUTHORIZE", Amount: usd("5.00"), ReferenceID: "spike-s1", Description: "Leash spike S1", RequestID: r.id("s1-order"),
		NoShipping: true, ReturnURL: "https://example.com/return", CancelURL: "https://example.com/cancel",
	})
	if !r.record(s, "create AUTHORIZE order", err, "") {
		return
	}
	r.record(s, "order status", nil, fmt.Sprintf("status=%s approve_link=%v", order.Status, order.ApproveURL() != ""))
	if err := r.approve(order); !r.record(s, "buyer approval", err, "") {
		return
	}
	order, err = r.c.AuthorizeOrder(r.ctx, order.ID, r.id("s1-auth"))
	if !r.record(s, "authorize", err, "") {
		return
	}
	auth := order.Authorization()
	if auth == nil {
		r.record(s, "authorization present", errors.New("no authorization in the response"), "")
		return
	}
	r.record(s, "authorization", nil, fmt.Sprintf("id=%s status=%s expires=%s (created %s): record this honor window in the ADR", auth.ID, auth.Status, auth.ExpirationTime, auth.CreateTime))

	part := usd("2.00")
	cap, err := r.c.Capture(r.ctx, auth.ID, paypal.CaptureParams{Amount: &part, FinalCapture: false, RequestID: r.id("s1-cap")})
	if r.record(s, "partial capture $2.00 of $5.00", err, "") {
		r.record(s, "capture", nil, fmt.Sprintf("id=%s status=%s final=%v", cap.ID, cap.Status, cap.FinalCapture))
	}
	err = r.c.Void(r.ctx, auth.ID, r.id("s1-void"))
	r.record(s, "void remainder after a partial capture", err, "")
	if a, gerr := r.c.GetAuthorization(r.ctx, auth.ID); gerr == nil {
		r.note(s, "authorization status afterwards", a.Status)
	}

	// Full release: the path that guarantees the buyer is never charged.
	o2, err := r.c.CreateOrder(r.ctx, paypal.CreateOrderParams{
		Intent: "AUTHORIZE", Amount: usd("5.00"), ReferenceID: "spike-s1b", RequestID: r.id("s1b-order"),
		NoShipping: true, ReturnURL: "https://example.com/return", CancelURL: "https://example.com/cancel",
	})
	if !r.record(s, "second order", err, "") {
		return
	}
	if err := r.approve(o2); !r.record(s, "second buyer approval", err, "") {
		return
	}
	o2, err = r.c.AuthorizeOrder(r.ctx, o2.ID, r.id("s1b-auth"))
	if !r.record(s, "second authorize", err, "") {
		return
	}
	a2 := o2.Authorization()
	if a2 == nil {
		r.record(s, "second authorization present", errors.New("missing"), "")
		return
	}
	err = r.c.Void(r.ctx, a2.ID, r.id("s1b-void"))
	if r.record(s, "void the whole authorization", err, "") {
		if a, gerr := r.c.GetAuthorization(r.ctx, a2.ID); gerr == nil {
			r.record(s, "status is VOIDED (buyer never charged)", boolErr(strings.EqualFold(a.Status, "VOIDED"), "status was "+a.Status), "status="+a.Status)
		}
	}
}

func boolErr(ok bool, msg string) error {
	if ok {
		return nil
	}
	return errors.New(msg)
}

// ------------------------------------------------------------------ S2

func (r *runner) s2() {
	const s = "S2"
	fmt.Fprintln(r.out, "\n--- S2: vaulted buyer, no redirect ---")
	src := r.opts.vaultSource
	if src == "" {
		if r.fake != nil {
			src = `{"paypal":{"vault_id":"VAULT-1"}}`
		} else {
			r.note(s, "skipped", "no -vault-source given. Create a vaulted PayPal payment method for your sandbox buyer (see PayPal's Vault / save-payment-method docs, verify the current flow) and pass its payment_source JSON. Until then the documented fallback is the step-up approval popup.")
			return
		}
	}
	var ps map[string]any
	if err := jsonUnmarshal(src, &ps); err != nil {
		r.record(s, "parse -vault-source", err, "")
		return
	}
	order, err := r.c.CreateOrder(r.ctx, paypal.CreateOrderParams{
		Intent: "AUTHORIZE", Amount: usd("5.00"), ReferenceID: "spike-s2", PaymentSource: ps, RequestID: r.id("s2-order"),
	})
	if !r.record(s, "create order with payment_source", err, "") {
		return
	}
	r.note(s, "order status", fmt.Sprintf("status=%s approve_link=%v authorization_present=%v", order.Status, order.ApproveURL() != "", order.Authorization() != nil))
	auth := order.Authorization()
	if auth == nil && order.Status == "APPROVED" {
		order, err = r.c.AuthorizeOrder(r.ctx, order.ID, r.id("s2-auth"))
		if !r.record(s, "authorize without a redirect", err, "") {
			return
		}
		auth = order.Authorization()
	}
	r.record(s, "agent flow needs no human redirect", boolErr(auth != nil, "no authorization: the buyer must approve in PayPal; use the step-up fallback (ADR)"),
		"hold placed without a redirect")
	if auth != nil {
		r.record(s, "cleanup: void the hold", r.c.Void(r.ctx, auth.ID, r.id("s2-void")), "")
	}
}

// ------------------------------------------------------------------ S3

func (r *runner) s3() {
	const s = "S3"
	fmt.Fprintln(r.out, "\n--- S3: Payouts ---")
	email := r.opts.merchantEmail
	if email == "" {
		if r.fake == nil {
			r.note(s, "skipped", "no -merchant-email given (a sandbox business account email, e.g. your LegitGifts account)")
			return
		}
		email = "legitgifts@sandbox.example"
	}
	b, err := r.c.CreatePayout(r.ctx, paypal.PayoutParams{
		SenderBatchID: r.id("s3-batch"), EmailSubject: "Leash spike payout", RequestID: r.id("s3-payout"),
		Items: []paypal.PayoutItem{{Receiver: email, Amount: usd("1.00"), Note: "spike", SenderItemID: r.id("s3-item")}},
	})
	if !r.record(s, "create payout", err, "") {
		return
	}
	batch := b.BatchHeader.PayoutBatchID
	status := b.BatchHeader.BatchStatus
	for i := 0; i < 8 && (status == "PENDING" || status == "PROCESSING"); i++ {
		r.sleep(2 * time.Second)
		g, gerr := r.c.GetPayout(r.ctx, batch)
		if gerr != nil {
			r.record(s, "poll payout", gerr, "")
			return
		}
		b, status = g, g.BatchHeader.BatchStatus
	}
	r.record(s, "payout batch", boolErr(status == "SUCCESS" || status == "PENDING" || status == "PROCESSING", "batch status "+status),
		fmt.Sprintf("batch=%s status=%s items=%d", batch, status, len(b.Items)))
	if len(b.Items) > 0 {
		it := b.Items[0].TransactionStatus
		okItem := it == "SUCCESS" || it == "PENDING" || it == "ONHOLD"
		r.record(s, "payout item not denied", boolErr(okItem, "item status "+it+": the receiver was refused. Use a DIFFERENT sandbox business account from the one that owns the app (PayPal will not pay an account from itself), and make sure the email is a real sandbox account."), "item status="+it)
	}
	r.note(s, "webhooks", "run `spike s3-webhook -webhook-id ID` behind cloudflared/ngrok, register that URL for PAYMENT.CAPTURE.* and PAYMENT.PAYOUTS-ITEM.* events, then trigger the flows above. Fallback if tunnels fail: poll order and payout status.")
}

// webhookListener verifies the signature of every delivery it receives.
func (r *runner) webhookListener() error {
	if r.opts.webhookID == "" {
		return errors.New("s3-webhook needs -webhook-id")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/webhooks/paypal", func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		ok, verr := r.c.VerifyWebhook(req.Context(), req.Header, body, r.opts.webhookID)
		fmt.Fprintf(r.out, "%s webhook %d bytes: signature valid=%v err=%v\n", time.Now().Format(time.RFC3339), len(body), ok, verr)
		if !ok {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	fmt.Fprintf(r.out, "listening on %s (POST /webhooks/paypal); expose it with cloudflared or ngrok\n", r.opts.listen)
	srv := &http.Server{Addr: r.opts.listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}

// ------------------------------------------------------------------ S4

func (r *runner) s4() {
	const s = "S4"
	fmt.Fprintln(r.out, "\n--- S4: sandbox disputes (manual) ---")
	r.note(s, "manual checklist", "Disputes are normally opened by the buyer in the sandbox Resolution Center, not by API. (1) Complete a captured purchase. (2) As the sandbox buyer, open a dispute on it. (3) Check whether the dispute appears for the merchant account and via the Disputes API and webhooks. (4) Record what you could and could not do here; the fallback in the plan is void/refund plus the evidence bundle.")
}

// ------------------------------------------------------------------ report

func (r *runner) report() {
	pass, fail := 0, 0
	for _, x := range r.res {
		if x.OK {
			pass++
		} else {
			fail++
		}
	}
	fmt.Fprintf(r.out, "\n%d passed, %d failed\n", pass, fail)
}

func (r *runner) appendMarkdown(path, mode string) error {
	var b strings.Builder
	if st, err := os.Stat(path); err != nil || st.Size() == 0 {
		b.WriteString("# PayPal spikes (Gate G1)\n\nResults of `go run ./cmd/spike`. Decisions go in docs/adr/.\n")
	}
	fmt.Fprintf(&b, "\n## Run %s (%s)\n\n| Spike | Check | Result | Detail |\n|---|---|---|---|\n", time.Now().UTC().Format(time.RFC3339), mode)
	for _, x := range r.res {
		res := "PASS"
		if !x.OK {
			res = "FAIL"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", x.Spike, esc(x.Check), res, esc(x.Detail))
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return err
}

func esc(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ").Replace(s)
}

// loadDotEnv reads KEY=VALUE lines without overriding variables already set.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		if _, set := os.LookupEnv(k); !set && k != "" {
			os.Setenv(k, v)
		}
	}
}
