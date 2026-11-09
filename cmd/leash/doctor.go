package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Adityaraj-star/leash/internal/llm"
)

// runDoctor checks everything a real run depends on, before the first real run:
// tokens, the merchants file, the PayPal sandbox login, the merchants' pages and
// the optional model key. It prints one line per check and fails if any is FAIL.
func runDoctor(args []string, getenv func(string) string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(out)
	merchantsPath := fs.String("merchants", "merchants.json", "merchants file")
	dataDir := fs.String("data", "data", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fails := 0
	report := func(level, name, detail string) {
		if level == "FAIL" {
			fails++
		}
		fmt.Fprintf(out, "%-5s %-22s %s\n", level, name, detail)
	}

	admin, agent := getenv("LEASH_ADMIN_TOKEN"), getenv("LEASH_AGENT_TOKEN")
	switch {
	case len(admin) < 32:
		report("FAIL", "LEASH_ADMIN_TOKEN", "missing or shorter than 32 characters")
	case len(agent) < 32:
		report("FAIL", "LEASH_AGENT_TOKEN", "missing or shorter than 32 characters")
	case admin == agent:
		report("FAIL", "tokens", "the admin and agent tokens must be different")
	default:
		report("ok", "tokens", "admin and agent tokens are set, long enough and different")
	}

	ms, err := loadMerchants(*merchantsPath)
	if err != nil {
		report("FAIL", "merchants file", err.Error())
	} else {
		report("ok", "merchants file", fmt.Sprintf("%d merchant(s), no placeholders left", len(ms.registry)))
	}

	base := getenv("PAYPAL_BASE_URL")
	if base == "" {
		base = "https://api-m.sandbox.paypal.com"
	}
	cid, sec := getenv("PAYPAL_CLIENT_ID"), getenv("PAYPAL_CLIENT_SECRET")
	switch {
	case !strings.Contains(base, "sandbox") && !strings.HasPrefix(base, "http://127.0.0.1") && !strings.HasPrefix(base, "http://localhost"):
		report("FAIL", "PayPal", "PAYPAL_BASE_URL is not the sandbox: "+base)
	case cid == "" || sec == "":
		report("FAIL", "PayPal", "PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET is not set")
	default:
		if err := paypalLogin(base, cid, sec); err != nil {
			report("FAIL", "PayPal login", err.Error())
		} else {
			report("ok", "PayPal login", "the sandbox accepted the client id and secret")
		}
	}

	if ms != nil {
		for id, b := range ms.bases {
			code, err := head(b)
			switch {
			case err != nil:
				report("FAIL", "merchant "+id, "cannot reach "+b+": "+err.Error())
			case code >= 500:
				report("FAIL", "merchant "+id, fmt.Sprintf("%s answered HTTP %d", b, code))
			default:
				report("ok", "merchant "+id, b+" is reachable")
			}
		}
		if len(ms.bases) == 0 {
			report("WARN", "merchant pages", "no merchant has a base_url, so quotes cannot be fetched and no payment can be approved")
		}
	}

	if pu := getenv("LEASH_PUBLIC_URL"); pu == "" {
		report("WARN", "LEASH_PUBLIC_URL", "not set: buyers will not be sent back to Leash after approving in PayPal")
	} else if u, err := url.Parse(pu); err != nil || u.Scheme != "https" {
		report("WARN", "LEASH_PUBLIC_URL", "should be the public https address of this server")
	} else {
		report("ok", "LEASH_PUBLIC_URL", pu)
	}

	if mc, err := llm.FromEnv(getenv, ""); err != nil {
		report("WARN", "AI model", err.Error())
	} else if mc == nil {
		report("WARN", "AI model", "no key set (GROQ_API_KEY for the free tier, or ANTHROPIC_API_KEY): the AI judge is off (the rules still decide) and the attack lab cannot run for real")
	} else {
		report("ok", "AI model", mc.Describe()+": the AI judge will be on")
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		report("FAIL", "data directory", err.Error())
	} else if f, err := os.CreateTemp(*dataDir, ".doctor-*"); err != nil {
		report("FAIL", "data directory", "not writable: "+err.Error())
	} else {
		f.Close()
		os.Remove(filepath.Join(*dataDir, filepath.Base(f.Name())))
		report("ok", "data directory", *dataDir+" is writable")
	}

	if fails > 0 {
		return fmt.Errorf("%d check(s) failed", fails)
	}
	fmt.Fprintln(out, "all required checks passed")
	return nil
}

func paypalLogin(base, id, secret string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/v1/oauth2/token", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return err
	}
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from PayPal: check the client id and secret are the sandbox ones", resp.StatusCode)
	}
	return nil
}

func head(u string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
