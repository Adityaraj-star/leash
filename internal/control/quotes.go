package control

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/provenance"
)

// QuoteSignatureHeader carries base64(HMAC-SHA256(secret, response body)).
const QuoteSignatureHeader = "X-Leash-Signature"

const maxQuoteBody = 64 << 10

// HTTPQuotes fetches quotes from merchants over HTTP, server to server:
//
//	GET {base_url}/quotes/{quote_id}  ->  provenance.Quote as JSON
//
// The agent only ever supplies an opaque quote id; the price, items and
// delivery promise come from this response, so an agent cannot invent them. That
// makes the quote the anchor of trust for an amount, so the fetch is strict:
//   - https only, except for a loopback address (local development);
//   - redirects are refused, so a merchant cannot bounce the request elsewhere;
//   - when a Secret is configured for the merchant, the body must carry a valid
//     HMAC, so nobody on the path can change the price;
//   - the quote must be for the merchant and id asked for, with a valid currency,
//     a positive amount and at least one item.
type HTTPQuotes struct {
	// Bases maps a merchant id to its base URL (scheme://host[:port][/prefix]).
	Bases map[string]string
	// Secrets maps a merchant id to a shared secret used to sign quotes. Merchants
	// without one are accepted unsigned.
	Secrets map[string]string
	Client  *http.Client
	// AllowInsecure permits plain http to a non-loopback host. Never in production.
	AllowInsecure bool
}

var errQuote = errors.New("quote not available")

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (h *HTTPQuotes) Quote(ctx context.Context, merchantID, quoteID string) (*provenance.Quote, error) {
	base, ok := h.Bases[merchantID]
	if !ok {
		return nil, fmt.Errorf("%w: merchant %q has no quote endpoint", errQuote, merchantID)
	}
	if !idRe.MatchString(quoteID) {
		return nil, fmt.Errorf("%w: malformed quote id", errQuote)
	}
	bu, err := url.Parse(base)
	if err != nil || bu.Host == "" {
		return nil, fmt.Errorf("%w: merchant %q has an invalid base url", errQuote, merchantID)
	}
	if bu.Scheme != "https" && !(bu.Scheme == "http" && (isLoopback(bu.Hostname()) || h.AllowInsecure)) {
		return nil, fmt.Errorf("%w: quotes must be fetched over https (merchant %q)", errQuote, merchantID)
	}

	cl := &http.Client{Timeout: 8 * time.Second}
	if h.Client != nil {
		c := *h.Client
		cl = &c
	}
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/quotes/"+url.PathEscape(quoteID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errQuote, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%w: merchant answered %d", errQuote, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxQuoteBody+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errQuote, err)
	}
	if len(body) > maxQuoteBody {
		return nil, fmt.Errorf("%w: the quote is too large", errQuote)
	}

	if secret := h.Secrets[merchantID]; secret != "" {
		got, derr := base64.StdEncoding.DecodeString(resp.Header.Get(QuoteSignatureHeader))
		if derr != nil || !hmac.Equal(got, SignQuote(secret, body)) {
			return nil, fmt.Errorf("%w: the quote is not signed by the merchant", errQuote)
		}
	}

	var q provenance.Quote
	if err := json.Unmarshal(body, &q); err != nil {
		return nil, fmt.Errorf("%w: unreadable quote: %v", errQuote, err)
	}
	// A merchant may only quote for itself, and the quote must be the one asked for.
	if q.ID != quoteID || q.MerchantID != merchantID {
		return nil, fmt.Errorf("%w: the quote does not match the request", errQuote)
	}
	if q.Amount.Minor <= 0 || !money.ValidCurrency(q.Amount.Currency) {
		return nil, fmt.Errorf("%w: the quote has no valid amount", errQuote)
	}
	if len(q.Items) == 0 || len(q.Items) > 20 {
		return nil, fmt.Errorf("%w: the quote must list between 1 and 20 items", errQuote)
	}
	for _, it := range q.Items {
		if strings.TrimSpace(it) == "" || len(it) > 200 {
			return nil, fmt.Errorf("%w: the quote has an empty or oversized item", errQuote)
		}
	}
	return &q, nil
}

// SignQuote returns the signature a merchant puts in QuoteSignatureHeader
// (base64 of this value) for a quote body. Merchants and tests use it.
func SignQuote(secret string, body []byte) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return m.Sum(nil)
}
