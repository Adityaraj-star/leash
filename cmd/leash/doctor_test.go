package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctor(t *testing.T) {
	pp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); r.URL.Path != "/v1/oauth2/token" || u != "id" || p != "secret" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"access_token":"x"}`))
	}))
	defer pp.Close()
	shop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	defer shop.Close()

	dir := t.TempDir()
	mf := filepath.Join(dir, "merchants.json")
	os.WriteFile(mf, []byte(`[{"id":"legitgifts","name":"LegitGifts","email":"legit@sandbox.example","delivery_secret":"a-long-delivery-secret","base_url":"`+shop.URL+`"}]`), 0o600)
	env := map[string]string{
		"LEASH_ADMIN_TOKEN": strings.Repeat("a", 32), "LEASH_AGENT_TOKEN": strings.Repeat("b", 32),
		"PAYPAL_CLIENT_ID": "id", "PAYPAL_CLIENT_SECRET": "secret", "PAYPAL_BASE_URL": pp.URL,
	}
	run := func(env map[string]string) (string, error) {
		var out bytes.Buffer
		err := runDoctor([]string{"-merchants", mf, "-data", filepath.Join(dir, "data")}, func(k string) string { return env[k] }, &out)
		return out.String(), err
	}
	if out, err := run(env); err != nil || !strings.Contains(out, "all required checks passed") {
		t.Fatalf("a good setup failed: %v\n%s", err, out)
	}
	bad := map[string]string{}
	for k, v := range env {
		bad[k] = v
	}
	bad["PAYPAL_CLIENT_SECRET"] = "wrong"
	bad["LEASH_AGENT_TOKEN"] = bad["LEASH_ADMIN_TOKEN"]
	out, err := run(bad)
	if err == nil || !strings.Contains(out, "FAIL  PayPal login") || !strings.Contains(out, "must be different") {
		t.Fatalf("a bad setup passed: %v\n%s", err, out)
	}
}
