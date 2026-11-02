package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/control"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

func payMug(c *client, ev, key string) (map[string]any, string, bool) {
	return c.call("leash_request_payment", map[string]any{
		"mandate_id": "m1", "merchant_id": "legitgifts", "items": []string{"Mug"}, "amount": "12.00",
		"quote_id": "q-mug", "evidence_refs": []string{ev}, "idempotency_key": key,
	})
}

// Starting a new MCP session used to wipe the slate: a poisoned page read in one
// session was forgotten by the next.
func TestANewMCPSessionDoesNotEscapeARecentInjection(t *testing.T) {
	// Without a taint window the loophole is open: this documents why it exists.
	open := newRig(t)
	a := open.newClient()
	a.browse("/evil")
	b := open.newClient()
	if out, txt, _ := payMug(b, b.browse("/mug"), "k1"); out["state"] != "AUTHORIZED" {
		t.Fatalf("baseline: %s", txt)
	}

	tuneConfig = func(c *control.Config) { c.TaintWindow = 10 * time.Minute }
	t.Cleanup(func() { tuneConfig = nil })
	r := newRig(t)
	steered, fresh := r.newClient(), r.newClient()
	steered.browse("/evil")
	out, txt, isErr := payMug(fresh, fresh.browse("/mug"), "k1")
	if isErr || out["state"] != "STEP_UP_PENDING" || !strings.Contains(txt, "planted instructions") {
		t.Fatalf("a recent injection must make every session wait for the user: %s", txt)
	}
	if st := r.fake.Stats(); st.HeldMinor != 0 {
		t.Fatalf("money moved: %+v", st)
	}
}

func TestReportProblemCannotTouchMoneyThatWasTaken(t *testing.T) {
	r := newRig(t)
	c := r.newClient()
	ev := c.browse("/mug")

	// Before the money is taken the agent can release the hold.
	first, txt, _ := payMug(c, ev, "k1")
	if first["state"] != "AUTHORIZED" {
		t.Fatalf("%s", txt)
	}
	rel, txt, isErr := c.call("leash_report_problem", map[string]any{"request_id": first["request_id"], "reason": "changed my mind"})
	if isErr || rel["state"] != "VOIDED" {
		t.Fatalf("a hold can be released: %s", txt)
	}

	// After the merchant was paid, only the user can act, and the agent is told so.
	second, txt, _ := payMug(c, ev, "k2")
	id := second["request_id"].(string)
	if second["state"] != "AUTHORIZED" {
		t.Fatalf("%s", txt)
	}
	if _, err := r.plane.AttestDelivery(context.Background(), "legitgifts", "s3cret-s3cret", id, settlement.Delivery{Delivered: true}); err != nil {
		t.Fatal(err)
	}
	_, txt, isErr = c.call("leash_report_problem", map[string]any{"request_id": id, "reason": "please refund me"})
	if !isErr || !strings.Contains(txt, "only the user can") {
		t.Fatalf("the agent must be told this is the user's call: %s", txt)
	}
	if st, _, _ := c.call("leash_status", map[string]any{"request_id": id}); st["state"] != "PAID_OUT" {
		t.Fatalf("nothing may change: %v", st["state"])
	}
}

func TestToolTextMatchesWhatTheServerDoes(t *testing.T) {
	for _, d := range toolDefs {
		if d.Name != "leash_report_problem" {
			continue
		}
		lower := strings.ToLower(d.Description)
		if strings.Contains(lower, "refunded") || strings.Contains(lower, "flagged for dispute") {
			t.Fatalf("the agent must not be promised a refund it cannot get: %s", d.Description)
		}
		if !strings.Contains(lower, "only the user can") {
			t.Fatalf("the description should say who handles captured money: %s", d.Description)
		}
		return
	}
	t.Fatal("leash_report_problem is not in the tool list")
}

func TestIdleSessionsAreForgotten(t *testing.T) {
	r := newRig(t)
	clk := now()
	s := &Server{Plane: r.plane, Token: agentToken, Now: func() time.Time { return clk }}
	id, _ := s.newSession()
	if s.get(id) == nil {
		t.Fatal("a new session must be usable")
	}
	clk = clk.Add(time.Hour + 30*time.Minute)
	if s.get(id) == nil { // 1.5h idle is fine, and using it resets the idle clock
		t.Fatal("an active session must not expire early")
	}
	clk = clk.Add(time.Hour + 30*time.Minute)
	if s.get(id) == nil {
		t.Fatal("the idle clock should have been reset by the last use")
	}
	clk = clk.Add(3 * time.Hour)
	if s.get(id) != nil {
		t.Fatal("a session unused for hours must be forgotten")
	}
}
