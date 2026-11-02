package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

func (h *harness) advance(d time.Duration) {
	h.clk.mu.Lock()
	h.clk.t = h.clk.t.Add(d)
	h.clk.mu.Unlock()
}

// Reading a poisoned page in one session, then starting a fresh session, must not
// give the agent a clean slate.
func TestAFreshSessionDoesNotEscapeARecentInjection(t *testing.T) {
	h := strictHarness(t, func(c *Config) { c.TaintWindow = 10 * time.Minute })
	h.setupStrict()
	h.register(mandateJSON("m_02", "100.00", "100.00", "25.00", false))

	steered := h.plane.OpenAgentConn()
	if _, err := steered.Browse(context.Background(), h.shop.URL+"/legit/poisoned"); err != nil {
		t.Fatal(err)
	}

	fresh := h.plane.OpenAgentConn() // the agent "starts over"
	o := h.payVia(fresh, h.legitVia(fresh, "m_02", "q-card", "k-1"))
	if o.State != settlement.StepUpPending {
		t.Fatalf("while tainted a person must confirm, got %+v", o)
	}
	if !strings.Contains(reasons(o), "planted instructions") {
		t.Fatalf("the reason should say why: %s", reasons(o))
	}
	h.noMoneyMoved()

	// Once the window ends the same purchase goes through on its own.
	h.advance(11 * time.Minute)
	o = h.payVia(fresh, h.legitVia(fresh, "m_02", "q-card", "k-2"))
	if o.State != settlement.Authorized {
		t.Fatalf("after the window the purchase should be allowed: %+v", o)
	}
}

func TestTaintIsOffByDefault(t *testing.T) {
	h := strictHarness(t, nil)
	h.setupStrict()
	h.register(mandateJSON("m_02", "100.00", "100.00", "25.00", false))
	steered := h.plane.OpenAgentConn()
	steered.Browse(context.Background(), h.shop.URL+"/legit/poisoned")
	fresh := h.plane.OpenAgentConn()
	if o := h.payVia(fresh, h.legitVia(fresh, "m_02", "q-card", "k-1")); o.State != settlement.Authorized {
		t.Fatalf("without a taint window nothing changes: %+v", o)
	}
}

func TestTheTaintWindowSurvivesARestart(t *testing.T) {
	h := strictHarness(t, func(c *Config) { c.TaintWindow = 10 * time.Minute })
	h.setupStrict()
	steered := h.plane.OpenAgentConn()
	steered.Browse(context.Background(), h.shop.URL+"/legit/poisoned")
	if h.plane.TaintedUntil().IsZero() {
		t.Fatal("the window should be open")
	}
	// A new plane on the same ledger (a restart).
	restarted, err := New(Config{
		Gateway: h.plane.cfg.Gateway, Ledger: h.led, Registry: h.plane.cfg.Registry, Quotes: h.quote,
		BrowseHosts: h.plane.cfg.BrowseHosts, Now: h.clk.now, Logf: func(string, ...any) {},
		PaymentSource: h.plane.cfg.PaymentSource, TaintWindow: 10 * time.Minute, Strict: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.TaintedUntil().IsZero() {
		t.Fatal("a restart must not wipe the taint window")
	}
}

func TestEnrollWithSecretWhenNoSecretIsConfigured(t *testing.T) {
	// Not strict and no secret: the plain flow still works (tests, the offline demo).
	h := newHarness(t, hopts{})
	pub, _ := mandate.PublicKeyBytes(h.priv)
	if _, err := h.plane.EnrollWithSecret(pub, ""); err != nil {
		t.Fatalf("%v", err)
	}
	// Strict: a secret is required, and the right one works.
	hs := strictHarness(t, nil)
	if _, err := hs.plane.EnrollWithSecret(pub, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("%v", err)
	}
	if _, err := hs.plane.EnrollWithSecret(pub, "setup-secret"); err != nil {
		t.Fatal(err)
	}
}
