package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeMerchants(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "merchants.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodMerchant = `{"id":"legitgifts","name":"LegitGifts","email":"legit@sandbox.example","delivery_secret":"a-long-delivery-secret","base_url":"%s"}`

func merchantJSON(base string) string {
	return "[" + strings.Replace(goodMerchant, "%s", base, 1) + "]"
}

func TestTheExampleMerchantsFileCannotRunUnedited(t *testing.T) {
	_, err := loadMerchants("../../merchants.example.json")
	if err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Fatalf("the example file must be refused until it is edited: %v", err)
	}
}

func TestMerchantsFileValidation(t *testing.T) {
	ok := writeMerchants(t, merchantJSON("https://merchant.example.test"))
	ms, err := loadMerchants(ok)
	if err != nil || ms.registry["legitgifts"].Email != "legit@sandbox.example" || ms.hosts[0] != "merchant.example.test" {
		t.Fatalf("a good file must load: %v %+v", err, ms)
	}
	if _, err := loadMerchants(writeMerchants(t, merchantJSON("http://localhost:9001"))); err != nil {
		t.Fatalf("plain http to localhost is allowed: %v", err)
	}

	bad := map[string]string{
		"remote http":        merchantJSON("http://merchant.example.test"),
		"short secret":       `[{"id":"a","email":"a@b.c","delivery_secret":"short"}]`,
		"no @ in email":      `[{"id":"a","email":"nobody","delivery_secret":"a-long-delivery-secret"}]`,
		"short quote secret": `[{"id":"a","email":"a@b.c","delivery_secret":"a-long-delivery-secret","quote_secret":"tiny"}]`,
		"duplicate id":       `[{"id":"a","email":"a@b.c","delivery_secret":"a-long-delivery-secret"},{"id":"a","email":"c@d.e","delivery_secret":"another-long-secret-1"}]`,
		"placeholder email":  `[{"id":"a","email":"REPLACE-me@x.y","delivery_secret":"a-long-delivery-secret"}]`,
		"empty list":         `[]`,
	}
	for name, body := range bad {
		if _, err := loadMerchants(writeMerchants(t, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A quote secret is carried through when it is valid.
	withSecret := `[{"id":"a","email":"a@b.c","delivery_secret":"a-long-delivery-secret","quote_secret":"sixteen-chars-ok!!"}]`
	if ms, err := loadMerchants(writeMerchants(t, withSecret)); err != nil || ms.secrets["a"] == "" {
		t.Fatalf("%v %+v", err, ms)
	}
}

func TestSecuritySettingsFollowTheFlags(t *testing.T) {
	cases := []struct {
		name               string
		fake, seed, strict bool
		taint              time.Duration
		wantStrict         bool
		wantTaint          time.Duration
	}{
		{"real mode defaults", false, true, true, -1, true, 10 * time.Minute},
		{"seeded fake demo", true, true, true, -1, false, 0},
		{"fake without seeding is strict", true, false, true, -1, true, 10 * time.Minute},
		{"explicit taint window wins", true, true, true, 5 * time.Minute, false, 5 * time.Minute},
		{"taint can be switched off", false, true, true, 0, true, 0},
		{"strict can be switched off", false, true, false, -1, false, 10 * time.Minute},
	}
	for _, c := range cases {
		gotStrict, gotTaint := serveMode(c.fake, c.seed, c.strict, c.taint)
		if gotStrict != c.wantStrict || gotTaint != c.wantTaint {
			t.Errorf("%s: strict=%v taint=%v, want %v %v", c.name, gotStrict, gotTaint, c.wantStrict, c.wantTaint)
		}
	}
}

func TestAHostingPlatformMustSetTheTokens(t *testing.T) {
	t.Setenv("PORT", "10000")
	t.Setenv("LEASH_ADMIN_TOKEN", "")
	t.Setenv("LEASH_AGENT_TOKEN", "")
	var out, errb bytes.Buffer
	err := runServe([]string{"-fake"}, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "LEASH_ADMIN_TOKEN") {
		t.Fatalf("a generated token would land in the platform's logs: %v", err)
	}
	t.Setenv("LEASH_ADMIN_TOKEN", strings.Repeat("a", 32))
	err = runServe([]string{"-fake"}, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "LEASH_AGENT_TOKEN") {
		t.Fatalf("%v", err)
	}
	t.Setenv("LEASH_AGENT_TOKEN", strings.Repeat("a", 32))
	if err = runServe([]string{"-fake"}, &out, &errb); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("the agent token may not equal the operator token: %v", err)
	}
}

func TestLandingPageHasNoScript(t *testing.T) {
	rec := httptest.NewRecorder()
	landing("Thanks.").ServeHTTP(rec, httptest.NewRequest("GET", "/paypal/return", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "Thanks.") || strings.Contains(strings.ToLower(body), "<script") {
		t.Fatalf("%s", body)
	}
}
