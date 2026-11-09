package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Adityaraj-star/leash/internal/provenance"
)

func TestHTTPQuotes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/quotes/q1", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(provenance.Quote{ID: "q1", MerchantID: "legitgifts", Amount: usd("24.00"), Items: []string{"Mug"}})
	})
	mux.HandleFunc("/quotes/liar", func(w http.ResponseWriter, _ *http.Request) { // quotes for someone else
		json.NewEncoder(w).Encode(provenance.Quote{ID: "liar", MerchantID: "shadyshop", Amount: usd("1.00")})
	})
	mux.HandleFunc("/quotes/wrongid", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(provenance.Quote{ID: "other", MerchantID: "legitgifts", Amount: usd("1.00")})
	})
	mux.HandleFunc("/quotes/zero", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(provenance.Quote{ID: "zero", MerchantID: "legitgifts"})
	})
	mux.HandleFunc("/quotes/junk", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<html>")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	hq := &HTTPQuotes{Bases: map[string]string{"legitgifts": srv.URL + "/"}}
	ctx := context.Background()

	q, err := hq.Quote(ctx, "legitgifts", "q1")
	if err != nil || q.Amount.Minor != 2400 {
		t.Fatalf("good quote: %+v, %v", q, err)
	}
	for _, c := range []struct{ merchant, id string }{
		{"legitgifts", "liar"}, {"legitgifts", "wrongid"}, {"legitgifts", "zero"}, {"legitgifts", "junk"},
		{"legitgifts", "missing"}, {"unknown", "q1"}, {"legitgifts", "../etc"}, {"legitgifts", strings.Repeat("a", 200)},
	} {
		if q, err := hq.Quote(ctx, c.merchant, c.id); err == nil {
			t.Errorf("Quote(%s,%s) = %+v, want an error", c.merchant, c.id, q)
		}
	}
}
