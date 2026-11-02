package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/provenance"
)

func goodQuote(id string) provenance.Quote {
	return provenance.Quote{ID: id, MerchantID: "legitgifts", Amount: usd("24.00"), Items: []string{"Mug"}}
}

func TestQuotesRefuseRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(goodQuote("q1"))
	}))
	defer target.Close()
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/quotes/q1", http.StatusFound)
	}))
	defer hop.Close()
	hq := &HTTPQuotes{Bases: map[string]string{"legitgifts": hop.URL}}
	if q, err := hq.Quote(context.Background(), "legitgifts", "q1"); err == nil {
		t.Fatalf("a redirect must not be followed, got %+v", q)
	}
}

func TestQuotesNeedHTTPSExceptOnLoopback(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		json.NewEncoder(w).Encode(goodQuote("q1"))
	}))
	defer srv.Close()
	// Loopback over http is fine (local development).
	if _, err := (&HTTPQuotes{Bases: map[string]string{"legitgifts": srv.URL}}).Quote(context.Background(), "legitgifts", "q1"); err != nil || !called {
		t.Fatalf("loopback http: %v", err)
	}
	// A remote host over plain http is refused before any request is made.
	hq := &HTTPQuotes{Bases: map[string]string{"legitgifts": "http://merchant.example.test"}}
	if _, err := hq.Quote(context.Background(), "legitgifts", "q1"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http to a remote host must be refused: %v", err)
	}
}

func TestSignedQuotes(t *testing.T) {
	const secret = "quote-secret-0123456789"
	var sign, tamper bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, _ := json.Marshal(goodQuote("q1"))
		if sign {
			w.Header().Set(QuoteSignatureHeader, base64.StdEncoding.EncodeToString(SignQuote(secret, body)))
		}
		if tamper { // the price changes on the way
			body = []byte(strings.Replace(string(body), "2400", "1", 1))
		}
		w.Write(body)
	}))
	defer srv.Close()
	hq := &HTTPQuotes{Bases: map[string]string{"legitgifts": srv.URL}, Secrets: map[string]string{"legitgifts": secret}, Client: srv.Client()}
	ctx := context.Background()

	sign = true
	if q, err := hq.Quote(ctx, "legitgifts", "q1"); err != nil || q.Amount.Minor != 2400 {
		t.Fatalf("a correctly signed quote must be accepted: %+v %v", q, err)
	}
	sign, tamper = true, true
	if _, err := hq.Quote(ctx, "legitgifts", "q1"); err == nil {
		t.Fatal("a quote changed after signing must be refused")
	}
	sign, tamper = false, false
	if _, err := hq.Quote(ctx, "legitgifts", "q1"); err == nil {
		t.Fatal("a missing signature must be refused when a secret is configured")
	}
	// No secret configured for the merchant: unsigned quotes are still accepted.
	plain := &HTTPQuotes{Bases: map[string]string{"legitgifts": srv.URL}, Client: srv.Client()}
	if _, err := plain.Quote(ctx, "legitgifts", "q1"); err != nil {
		t.Fatalf("unsigned quotes stay valid without a secret: %v", err)
	}
}

func TestQuotesAreValidated(t *testing.T) {
	cases := map[string]provenance.Quote{
		"bad currency":   {ID: "q1", MerchantID: "legitgifts", Amount: money.Amount{Minor: 100, Currency: "usdx"}, Items: []string{"Mug"}},
		"no items":       {ID: "q1", MerchantID: "legitgifts", Amount: usd("1.00")},
		"blank item":     {ID: "q1", MerchantID: "legitgifts", Amount: usd("1.00"), Items: []string{"  "}},
		"huge item":      {ID: "q1", MerchantID: "legitgifts", Amount: usd("1.00"), Items: []string{strings.Repeat("x", 201)}},
		"too many items": {ID: "q1", MerchantID: "legitgifts", Amount: usd("1.00"), Items: make([]string, 21)},
	}
	for name, q := range cases {
		q := q
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(q) }))
			defer srv.Close()
			if got, err := (&HTTPQuotes{Bases: map[string]string{"legitgifts": srv.URL}}).Quote(context.Background(), "legitgifts", "q1"); err == nil {
				t.Fatalf("expected an error, got %+v", got)
			}
		})
	}
	// An oversized body is refused.
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(strings.Repeat(" ", maxQuoteBody+10))) }))
	defer big.Close()
	if _, err := (&HTTPQuotes{Bases: map[string]string{"legitgifts": big.URL}}).Quote(context.Background(), "legitgifts", "q1"); err == nil {
		t.Fatal("an oversized quote must be refused")
	}
}
