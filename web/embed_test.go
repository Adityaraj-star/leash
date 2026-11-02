package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// external matches a src or href that points off-site (an XML namespace inside a
// data: URI is not a fetch).
var external = regexp.MustCompile(`(?i)(src|href)\s*=\s*["\x27]https?://`)

// The binary must be self-contained: every file the page needs is embedded, and
// nothing in the page points at a third-party host (the CSP would block it).
func TestDashboardIsSelfContained(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	get := func(p string) (int, string) {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := new(strings.Builder)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp.StatusCode, b.String()
	}
	code, index := get("/")
	if code != 200 || !strings.Contains(index, "Flight recorder") {
		t.Fatalf("index: %d", code)
	}
	for _, p := range []string{"/app.js", "/sign.js", "/app.css", "/vendor/ag-grid-community.min.js", "/vendor/AG-GRID-LICENSE.txt", "/fonts/schibsted-grotesk-latin-wght-normal.woff2"} {
		if c, body := get(p); c != 200 || len(body) < 100 {
			t.Errorf("%s: %d (%d bytes)", p, c, len(body))
		}
	}
	if external.MatchString(index) {
		t.Error("index.html loads something from an external host")
	}
	if _, js := get("/app.js"); strings.Contains(js, "innerHTML") {
		t.Error("app.js uses innerHTML; agent-written text must only ever be set as text")
	}
}
