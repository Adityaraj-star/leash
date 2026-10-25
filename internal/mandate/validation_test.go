package mandate

import (
	"strings"
	"testing"
)

func TestInconsistentCapsAreRejected(t *testing.T) {
	cases := map[string]struct{ old, new, want string }{
		"per-transaction cap above the total": {`"per_tx_cap": "40.00"`, `"per_tx_cap": "90.00"`, "per_tx_cap cannot exceed max_total"},
		"step-up line above the cap":          {`"step_up_over": "25.00"`, `"step_up_over": "50.00"`, "step_up_over cannot exceed per_tx_cap"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			raw := strings.Replace(sample, c.old, c.new, 1)
			if raw == sample {
				t.Fatal("test setup: nothing was replaced")
			}
			if _, err := Parse([]byte(raw)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
	// Equal values are fine, and step-up may be disabled.
	if _, err := Parse([]byte(sample)); err != nil {
		t.Fatalf("the sample mandate must stay valid: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(sample, `"step_up_over": "25.00"`, `"step_up_over": "0.00"`, 1))); err != nil {
		t.Fatalf("a zero step-up line means disabled: %v", err)
	}
}
