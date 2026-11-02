package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Adityaraj-star/leash/internal/api"
	"github.com/Adityaraj-star/leash/internal/control"
	"github.com/Adityaraj-star/leash/internal/ledger"
	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/mcp"
	"github.com/Adityaraj-star/leash/internal/paypal"
	"github.com/Adityaraj-star/leash/internal/paypal/paypaltest"
	"github.com/Adityaraj-star/leash/internal/provenance"
	"github.com/Adityaraj-star/leash/internal/settlement"
	"github.com/Adityaraj-star/leash/web"
)

// merchantFile is one entry of the merchants JSON file.
type merchantFile struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Email           string   `json:"email"` // sandbox business account that gets paid out
	Categories      []string `json:"categories"`
	HasReturnPolicy bool     `json:"has_return_policy"`
	Aliases         []string `json:"aliases"`
	DeliverySecret  string   `json:"delivery_secret"`
	BaseURL         string   `json:"base_url"` // where Leash fetches quotes and the agent browses
	// QuoteSecret, when set, means this merchant signs its quotes (HMAC-SHA256 of
	// the response body, base64, in the X-Leash-Signature header) and Leash refuses
	// any quote without a valid signature.
	QuoteSecret string `json:"quote_secret"`
}

// merchantSet is what the merchants file turns into.
type merchantSet struct {
	registry control.MapRegistry
	bases    map[string]string // merchant id -> quote/browse base URL
	secrets  map[string]string // merchant id -> quote signing secret
	hosts    []string          // hosts the agent may browse
}

func runServe(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "", "listen address (default 127.0.0.1:8787, or :$PORT when PORT is set)")
	dataDir := fs.String("data", "data", "directory for the ledger, settlement store and ledger key")
	merchants := fs.String("merchants", "merchants.json", "merchants file (real mode)")
	fake := fs.Bool("fake", false, "run against an in-process fake PayPal with demo shops (no credentials, nothing persisted)")
	seed := fs.Bool("seed", true, "with -fake: populate the dashboard with a scripted scenario")
	extraHosts := fs.String("browse-hosts", "", "comma separated extra host[:port] values the agent may browse")
	strict := fs.Bool("strict", true, "require the user's signature for approvals, issue sessions server-side and gate enrollment (turned off for the seeded fake demo)")
	taint := fs.Duration("taint-window", -1, "after a page with planted instructions is read, every payment needs your approval for this long (default 10m; off in the seeded fake demo)")
	publicURL := fs.String("public-url", os.Getenv("LEASH_PUBLIC_URL"), "public https address of this server; buyers who approve in PayPal land back here")
	approvalTTL := fs.Duration("approval-ttl", 0, "how long an approved payment may wait for the buyer to approve in PayPal (default 3h)")
	inspection := fs.Duration("inspection", 0, "keep a delivered purchase on hold this long before paying the merchant, so you can still object (default 0: pay at once)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logf := func(f string, a ...any) { fmt.Fprintf(stderr, time.Now().Format("15:04:05 ")+f+"\n", a...) }

	cloud := os.Getenv("PORT") != "" // a hosting platform: it keeps stdout in its logs
	token := os.Getenv("LEASH_ADMIN_TOKEN")
	generated := false
	if token == "" {
		if cloud {
			return errors.New("set LEASH_ADMIN_TOKEN: a generated token would end up in the platform's logs")
		}
		b := make([]byte, 18)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		token, generated = hex.EncodeToString(b), true
	}
	if len(token) < 16 {
		return errors.New("LEASH_ADMIN_TOKEN is too short (use at least 16 characters)")
	}
	agentToken := os.Getenv("LEASH_AGENT_TOKEN")
	agentGenerated := false
	if agentToken == "" {
		if cloud {
			return errors.New("set LEASH_AGENT_TOKEN: a generated token would end up in the platform's logs")
		}
		b := make([]byte, 18)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		agentToken, agentGenerated = hex.EncodeToString(b), true
	}
	if len(agentToken) < 16 {
		return errors.New("LEASH_AGENT_TOKEN is too short (use at least 16 characters)")
	}
	if len(token) < 32 || len(agentToken) < 32 {
		logf("warning: use tokens of at least 32 random characters (for example `openssl rand -hex 24`)")
	}
	if subtle.ConstantTimeCompare([]byte(agentToken), []byte(token)) == 1 {
		return errors.New("LEASH_AGENT_TOKEN must differ from LEASH_ADMIN_TOKEN: the agent must not be able to approve its own payments")
	}
	listen := *addr
	if listen == "" {
		if p := os.Getenv("PORT"); p != "" {
			listen = ":" + p
		} else {
			listen = "127.0.0.1:8787"
		}
	}

	var (
		cfg      control.Config
		cleanup  []func()
		seedFunc func(*control.Plane) error
	)
	defer func() {
		for _, f := range cleanup {
			f()
		}
	}()
	cfg.Logf = logf
	cfg.Now = time.Now
	cfg.ApprovalTTL, cfg.InspectionPeriod = *approvalTTL, *inspection

	// The seeded fake demo keeps the demo user's key inside this process, so the
	// browser cannot sign for it; everything else runs strict.
	seeded := *fake && *seed
	strictOn, taintWindow := serveMode(*fake, *seed, *strict, *taint)
	cfg.Strict, cfg.TaintWindow = strictOn, taintWindow
	if cfg.Strict {
		cfg.EnrollSecret = token
	} else if *strict && seeded {
		logf("strict mode is off for the seeded fake demo (its user key lives in this process). Use -seed=false to enroll your own browser key and sign approvals.")
	} else {
		logf("warning: running with -strict=false; do not use this outside a throwaway demo")
	}
	extra := map[string]http.Handler{}
	if pu := strings.TrimRight(*publicURL, "/"); pu != "" {
		u, err := url.Parse(pu)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopbackHost(u.Hostname())) {
			return errors.New("-public-url / LEASH_PUBLIC_URL must be an https address (http only for localhost)")
		}
		cfg.ReturnURL, cfg.CancelURL = pu+"/paypal/return", pu+"/paypal/cancel"
		extra["/paypal/return"] = landing("Thanks. PayPal approved the payment. You can close this tab and go back to the Leash dashboard.")
		extra["/paypal/cancel"] = landing("The payment was not approved. You can close this tab. Nothing was charged.")
	}

	if *fake {
		fp := paypaltest.New()
		base := fp.Start()
		cleanup = append(cleanup, fp.Close)
		client, err := paypal.New(paypal.Config{ClientID: paypaltest.ClientID, ClientSecret: paypaltest.ClientSecret, BaseURL: base, Sleep: func(time.Duration) {}})
		if err != nil {
			return err
		}
		shops, err := startDemoShops()
		if err != nil {
			return err
		}
		cleanup = append(cleanup, shops.close)
		_, priv, _ := ledger.GenerateKey()
		led, err := ledger.New(ledger.NewMemStore(), priv, time.Now)
		if err != nil {
			return err
		}
		cfg.Gateway, cfg.Ledger, cfg.Registry, cfg.Quotes = client, led, shops.registry(), shops.quotes()
		cfg.BrowseHosts = []string{shops.host}
		cfg.PaymentSource = map[string]any{"paypal": map[string]any{"vault_id": "VAULT-1"}}
		cfg.StepUpTTL = 24 * time.Hour
		logf("FAKE mode: nothing is persisted and no real PayPal is contacted. Demo shop: %s", shops.base)
		if *seed {
			seedFunc = func(p *control.Plane) error { return seedDemo(p, shops, fp) }
		}
	} else {
		cid, sec := os.Getenv("PAYPAL_CLIENT_ID"), os.Getenv("PAYPAL_CLIENT_SECRET")
		if cid == "" || sec == "" {
			return errors.New("set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET (sandbox), or run with -fake")
		}
		client, err := paypal.New(paypal.Config{ClientID: cid, ClientSecret: sec, BaseURL: os.Getenv("PAYPAL_BASE_URL")})
		if err != nil {
			return err
		}
		ms, err := loadMerchants(*merchants)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(*dataDir, 0o700); err != nil {
			return err
		}
		_, priv, err := ledger.LoadOrCreateKey(filepath.Join(*dataDir, "ledger.key"))
		if err != nil {
			return err
		}
		ls, err := ledger.OpenFileStore(filepath.Join(*dataDir, "ledger.jsonl"))
		if err != nil {
			return err
		}
		cleanup = append(cleanup, func() { ls.Close() })
		ss, err := settlement.OpenFileStore(filepath.Join(*dataDir, "settlement.jsonl"))
		if err != nil {
			return err
		}
		cleanup = append(cleanup, func() { ss.Close() })
		led, err := ledger.New(ls, priv, time.Now)
		if err != nil {
			return fmt.Errorf("the ledger did not load: %w", err)
		}
		if n := ls.Repaired(); n > 0 {
			logf("the ledger ended in a half-written line (%d bytes), probably from a crash; it was dropped", n)
		}
		if n := ss.Repaired(); n > 0 {
			logf("the request store ended in a half-written line (%d bytes), probably from a crash; it was dropped", n)
		}
		cfg.Gateway, cfg.Ledger, cfg.Store, cfg.Registry = client, led, ss, ms.registry
		cfg.Quotes = &control.HTTPQuotes{Bases: ms.bases, Secrets: ms.secrets}
		cfg.BrowseHosts = append(ms.hosts, splitList(*extraHosts)...)
		if v := os.Getenv("LEASH_PAYMENT_SOURCE"); v != "" { // spike S2's result, if there is one
			var ps map[string]any
			if err := json.Unmarshal([]byte(v), &ps); err != nil {
				return fmt.Errorf("LEASH_PAYMENT_SOURCE is not valid JSON: %w", err)
			}
			cfg.PaymentSource = ps
		}
		if cfg.PaymentSource == nil && *publicURL == "" {
			logf("note: no saved PayPal payment method and no -public-url: buyers approve each payment in PayPal and land on a placeholder page. Set -public-url so they come back to Leash.")
		}
	}

	plane, err := control.New(cfg)
	if err != nil {
		return err
	}
	if seedFunc != nil {
		if err := seedFunc(plane); err != nil {
			return fmt.Errorf("seeding the demo: %w", err)
		}
	}

	extra["/mcp"] = &mcp.Server{Plane: plane, Token: agentToken, Logf: logf}
	srv := &api.Server{Plane: plane, Token: token, EnrollSecret: token, Static: web.Handler(), Logf: logf, Extra: extra}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go api.RunSweeper(ctx, plane, 30*time.Second, logf) // expiry, retries, pending captures and payouts
	go srv.RunVerifier(ctx, time.Minute, logf)          // re-checks the whole ledger in the background

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sh)
	}()
	fmt.Fprintf(stdout, "\nLeash dashboard: http://%s\n", displayAddr(ln.Addr().String()))
	if generated {
		fmt.Fprintf(stdout, "Operator token (generated, shown once; set LEASH_ADMIN_TOKEN to choose your own):\n  %s\n\n", token)
	} else {
		fmt.Fprintln(stdout, "Operator token: the value of LEASH_ADMIN_TOKEN")
	}
	if agentGenerated {
		fmt.Fprintf(stdout, "Agent token (generated; set LEASH_AGENT_TOKEN to choose your own):\n  %s\n", agentToken)
	}
	fmt.Fprintf(stdout, "Connect an agent (MCP over HTTP):\n  claude mcp add --transport http leash http://%s/mcp --header \"Authorization: Bearer <agent token>\"\n\n", displayAddr(ln.Addr().String()))
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func displayAddr(a string) string {
	if strings.HasPrefix(a, "[::]:") || strings.HasPrefix(a, "0.0.0.0:") {
		return "localhost:" + a[strings.LastIndex(a, ":")+1:]
	}
	return a
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// serveMode decides the security settings from the flags. The seeded fake demo
// keeps the demo user's key inside the process, so the browser cannot sign for
// it and strict mode is off there; its scripted attack must also not put the
// taint window in the way of your first live purchase.
func serveMode(fake, seed, strictFlag bool, taintFlag time.Duration) (strict bool, taint time.Duration) {
	seeded := fake && seed
	strict = strictFlag && !seeded
	switch {
	case taintFlag >= 0:
		taint = taintFlag
	case seeded:
		taint = 0
	default:
		taint = 10 * time.Minute
	}
	return strict, taint
}

var placeholder = regexp.MustCompile(`(?i)^\s*replace\b`)

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// landing is the tiny page a buyer sees after approving (or not) in PayPal.
func landing(msg string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>Leash</title><body style=\"font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem\"><h1>Leash</h1><p>%s</p></body>", msg)
	})
}

func loadMerchants(path string) (*merchantSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("merchants file: %w (copy merchants.example.json to %s and edit it)", err, path)
	}
	var list []merchantFile
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("merchants file %s: %w", path, err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("merchants file %s has no merchants", path)
	}
	ms := &merchantSet{registry: control.MapRegistry{}, bases: map[string]string{}, secrets: map[string]string{}}
	for _, m := range list {
		if m.ID == "" || m.Email == "" || len(m.DeliverySecret) < 12 {
			return nil, fmt.Errorf("merchant %q needs an id, a payout email and a delivery_secret of at least 12 characters", m.ID)
		}
		if _, dup := ms.registry[m.ID]; dup {
			return nil, fmt.Errorf("merchant %q appears twice", m.ID)
		}
		// The example file ships placeholders; running with them would pay a made-up
		// address and use a guessable secret.
		for name, v := range map[string]string{"email": m.Email, "delivery_secret": m.DeliverySecret, "quote_secret": m.QuoteSecret} {
			if placeholder.MatchString(v) {
				return nil, fmt.Errorf("merchant %q still has a placeholder %s (it starts with REPLACE); fill in a real value", m.ID, name)
			}
		}
		if !strings.Contains(m.Email, "@") {
			return nil, fmt.Errorf("merchant %q: email %q is not an address", m.ID, m.Email)
		}
		if m.QuoteSecret != "" && len(m.QuoteSecret) < 16 {
			return nil, fmt.Errorf("merchant %q: quote_secret must be at least 16 characters", m.ID)
		}
		ms.registry[m.ID] = control.Merchant{ID: m.ID, Name: m.Name, Email: m.Email, Categories: m.Categories,
			HasReturnPolicy: m.HasReturnPolicy, Aliases: m.Aliases, DeliverySecret: m.DeliverySecret}
		if m.QuoteSecret != "" {
			ms.secrets[m.ID] = m.QuoteSecret
		}
		if m.BaseURL != "" {
			u, err := url.Parse(m.BaseURL)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return nil, fmt.Errorf("merchant %q has an invalid base_url", m.ID)
			}
			if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
				return nil, fmt.Errorf("merchant %q: base_url must be https (plain http is only allowed for localhost)", m.ID)
			}
			ms.bases[m.ID] = m.BaseURL
			ms.hosts = append(ms.hosts, u.Host)
		}
	}
	return ms, nil
}

// ------------------------------------------------------------------ demo shops

type demoShops struct {
	srv  *http.Server
	ln   net.Listener
	base string
	host string
	book map[string]*provenance.Quote
}

func (s *demoShops) close() { s.srv.Close() }

func (s *demoShops) registry() control.MapRegistry {
	return control.MapRegistry{
		"legitgifts": {ID: "legitgifts", Name: "LegitGifts", Email: "legitgifts@sandbox.example", Categories: []string{"gifts"},
			HasReturnPolicy: true, Aliases: []string{"LegitGifts", s.host + "/legit"}, DeliverySecret: demoSecret},
		"shadyshop": {ID: "shadyshop", Name: "ShadyShop", Email: "shady@sandbox.example", Categories: []string{"gifts"},
			HasReturnPolicy: false, Aliases: []string{"ShadyShop", s.host + "/shady"}, DeliverySecret: "shady-secret-xyz"},
	}
}

func (s *demoShops) quotes() control.QuoteSource { return quoteBook(s.book) }

const demoSecret = "legit-secret-123"

func startDemoShops() (*demoShops, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, body)
		}
	}
	mux.HandleFunc("/legit/mug", page(legitPage))
	mux.HandleFunc("/legit/lamp", page(`<html><head><title>LegitGifts: Desk lamp</title></head><body><h1>Desk lamp</h1><p>$32.00. Free returns within 30 days. Ships in 2 days.</p></body></html>`))
	mux.HandleFunc("/legit/card", page(`<html><head><title>LegitGifts: Greeting card</title></head><body><h1>Greeting card</h1><p>$12.00. Free returns within 30 days. Ships in 1 day.</p></body></html>`))
	mux.HandleFunc("/shady/deal", page(attackPage))
	host := ln.Addr().String()
	s := &demoShops{ln: ln, host: host, base: "http://" + host, srv: &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}}
	promised := time.Now().Add(48 * time.Hour)
	s.book = map[string]*provenance.Quote{
		"q-mug":  {ID: "q-mug", MerchantID: "legitgifts", Amount: usd("24.00"), Items: []string{"Ceramic mug"}, PromisedDelivery: promised},
		"q-lamp": {ID: "q-lamp", MerchantID: "legitgifts", Amount: usd("32.00"), Items: []string{"Desk lamp"}, PromisedDelivery: promised},
		"q-card": {ID: "q-card", MerchantID: "legitgifts", Amount: usd("12.00"), Items: []string{"Greeting card"}, PromisedDelivery: promised},
	}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// seedDemo fills a fake-mode dashboard: a signed mandate, an allowed purchase
// that is delivered and paid out, a blocked injection attack and a purchase
// waiting for the human's approval. The demo user's key lives in this process;
// that is why the dashboard cannot enroll a different key in this mode.
func seedDemo(p *control.Plane, shops *demoShops, fp *paypaltest.Server) error {
	ctx := context.Background()
	user, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pub, err := mandate.PublicKeyBytes(user)
	if err != nil {
		return err
	}
	if _, err := p.Enroll(pub); err != nil {
		return err
	}
	now := time.Now().UTC()
	text := fmt.Sprintf(`{"mandate_id":"m_birthday","intent":"Birthday gift for my sister, under $60, arrives within 3 days",`+
		`"max_total":{"amount":"60.00","currency":"USD"},"per_tx_cap":"40.00","allowed_merchants":["legitgifts"],"categories":["gifts"],`+
		`"requires_return_policy":true,"deliver_by":%q,"single_use":false,"step_up_over":"20.00",`+
		`"expires_at":%q,"nonce":"demo-nonce"}`, now.Add(72*time.Hour).Format("2006-01-02"), now.Add(7*24*time.Hour).Format(time.RFC3339))
	sig, err := mandate.Sign(user, []byte(text))
	if err != nil {
		return err
	}
	if _, err := p.RegisterMandate([]byte(text), sig); err != nil {
		return err
	}
	read := func(sess, path string) (string, error) {
		r, err := p.Browse(ctx, sess, shops.base+path)
		return r.EvidenceID, err
	}
	pay := func(sess, key, quote, page, merchant string, items []string, amt string) (control.Outcome, error) {
		ev, err := read(sess, page)
		if err != nil {
			return control.Outcome{}, err
		}
		return p.RequestPayment(ctx, control.PaymentRequest{Session: sess, MandateID: "m_birthday", MerchantID: merchant, Items: items,
			Amount: usd(amt), QuoteID: quote, EvidenceRefs: []string{ev}, IdempotencyKey: key})
	}

	// 1. an allowed $12 card: under the step-up line, held, delivered, paid out.
	o, err := pay("agent-1", "seed-card", "q-card", "/legit/card", "legitgifts", []string{"Greeting card"}, "12.00")
	if err != nil {
		return err
	}
	if o.State == settlement.Authorized {
		if _, err := p.AttestDelivery(ctx, "legitgifts", demoSecret, o.RequestID, settlement.Delivery{Delivered: true, Reference: "TRK-4821", Source: "legitgifts", Note: "Shipped and received"}); err != nil {
			return err
		}
	}
	// 2. the attack: a poisoned page tells the agent to pay a stranger.
	evAttack, err := read("agent-2", "/shady/deal")
	if err != nil {
		return err
	}
	if _, err := p.RequestPayment(ctx, control.PaymentRequest{Session: "agent-2", MandateID: "m_birthday", MerchantID: "shadyshop",
		Items: []string{"Premium bundle"}, Amount: usd("39.99"), EvidenceRefs: []string{evAttack}, IdempotencyKey: "seed-attack"}); err != nil {
		return err
	}
	// 3. a $32 lamp: over the step-up line, waits for the human.
	if _, err := pay("agent-3", "seed-lamp", "q-lamp", "/legit/lamp", "legitgifts", []string{"Desk lamp"}, "32.00"); err != nil {
		return err
	}
	_ = fp
	return nil
}
