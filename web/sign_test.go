package web

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The signing script has its own unit tests, written for Node's built-in test
// runner. They run here when Node is installed (CI has it) and are skipped
// otherwise, so `go test ./...` still works on a machine without Node.
func TestSigningScriptUnitTests(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; skipping the signing script tests")
	}
	cmd := exec.Command(node, "--test", "sign.test.mjs")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node --test failed:\n%s", out)
	}
	if !strings.Contains(string(out), "pass 7") {
		t.Fatalf("expected 7 passing tests:\n%s", out)
	}
}

// Everything the dashboard needs to sign with is shipped, loaded before app.js,
// and the private key is never made extractable.
func TestSigningScriptIsWiredInSafely(t *testing.T) {
	index, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	sign, app := strings.Index(html, `src="sign.js"`), strings.Index(html, `src="app.js"`)
	if sign < 0 || app < 0 || sign > app {
		t.Fatal("index.html must load sign.js before app.js")
	}
	if strings.Contains(html, "<script>") || strings.Contains(strings.ToLower(html), " onclick=") {
		t.Error("index.html must not contain inline scripts (the content security policy forbids them)")
	}
	js, err := os.ReadFile("static/sign.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)
	if strings.Contains(src, "innerHTML") {
		t.Error("sign.js must not use innerHTML")
	}
	if !strings.Contains(src, "generateKey(ALG, false,") {
		t.Error("the signing key must be generated non-extractable")
	}
	if strings.Contains(src, `"pkcs8"`) || strings.Contains(src, `"jwk"`) {
		t.Error("sign.js must never export the private key")
	}
}
