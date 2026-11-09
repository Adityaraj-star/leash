// Command shops runs the two demo merchants (an honest one and an attacker)
// as standalone servers, to be used with `leash serve` in real mode.
//
//	go run ./cmd/shops
//
// Each shop has a storefront, a /quote endpoint Leash fetches server-to-server,
// and a password-protected back office where you mark an order delivered.
// The delivery secrets must match delivery_secret in merchants.json.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Adityaraj-star/leash/internal/shops"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// display turns ":9001" into "http://localhost:9001".
func display(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "http://localhost" + addr
	}
	return "http://" + addr
}

func main() {
	legitAddr := flag.String("legit-addr", ":9001", "listen address for LegitGifts")
	shadyAddr := flag.String("shady-addr", ":9002", "listen address for ShadyShop")
	leashURL := flag.String("leash", "http://127.0.0.1:8787", "base URL of the Leash server")
	flag.Parse()

	legitSecret := env("LEGIT_SECRET", "legit-secret-123")
	shadySecret := env("SHADY_SECRET", "shady-secret-123")
	legitPass := env("LEGIT_ADMIN_PASSWORD", shops.NewAdminPassword())
	shadyPass := env("SHADY_ADMIN_PASSWORD", shops.NewAdminPassword())

	legit := shops.Legit(*leashURL, legitSecret, legitPass)
	shady := shops.Shady(*leashURL, shadySecret, shadyPass)

	fmt.Printf("LegitGifts  %s   back office: /admin   password: %s\n", display(*legitAddr), legitPass)
	fmt.Printf("ShadyShop   %s   back office: /admin   password: %s\n", display(*shadyAddr), shadyPass)
	fmt.Printf("Leash at %s. Delivery secrets come from LEGIT_SECRET / SHADY_SECRET (demo defaults if unset).\n", *leashURL)

	errc := make(chan error, 2)
	for _, s := range []struct {
		addr string
		h    http.Handler
	}{{*legitAddr, legit.Handler()}, {*shadyAddr, shady.Handler()}} {
		srv := &http.Server{Addr: s.addr, Handler: s.h, ReadHeaderTimeout: 5 * time.Second}
		go func() { errc <- srv.ListenAndServe() }()
	}
	log.Fatal(<-errc)
}
