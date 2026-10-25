// Package paypal is a thin hand-written client for the PayPal REST APIs Leash
// needs: Orders v2 (AUTHORIZE), Payments v2 (capture, void, refund), Payouts
// v1 and webhook signature verification. PayPal has no official Go SDK.
//
// Safety properties:
//   - Sandbox only by default. Pointing at the live API requires AllowLive.
//   - Every mutating call requires a caller-supplied PayPal-Request-Id so a
//     retry can never double-charge; those calls (and GETs) retry on 429/5xx.
//   - Amounts are integer minor units (internal/money) converted to PayPal's
//     decimal strings only here, at the edge.
//
// Endpoint shapes follow PayPal's public docs; re-verify them against the
// sandbox with cmd/spike before relying on them (see docs/spikes.md).
package paypal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SandboxBaseURL is the default API host.
const SandboxBaseURL = "https://api-m.sandbox.paypal.com"

const maxBody = 4 << 20

// Config configures a Client.
type Config struct {
	ClientID     string
	ClientSecret string
	BaseURL      string // default SandboxBaseURL
	AllowLive    bool   // must be true to use api-m.paypal.com / api.paypal.com
	HTTPClient   *http.Client
	Now          func() time.Time    // injectable for tests
	Sleep        func(time.Duration) // injectable for tests
	MaxRetries   int                 // 0 = default (2); negative = never retry
}

// Client talks to PayPal. It is safe for concurrent use.
type Client struct {
	cfg      Config
	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("paypal: client id and secret are required")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = SandboxBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("paypal: bad base URL %q", cfg.BaseURL)
	}
	host := u.Hostname()
	local := host == "127.0.0.1" || host == "localhost" || host == "::1"
	if u.Scheme != "https" && !local {
		return nil, errors.New("paypal: base URL must be https")
	}
	if (host == "api-m.paypal.com" || host == "api.paypal.com") && !cfg.AllowLive {
		return nil, errors.New("paypal: refusing to use the LIVE API (sandbox only; no real money)")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = time.Sleep
	}
	switch {
	case cfg.MaxRetries == 0:
		cfg.MaxRetries = 2
	case cfg.MaxRetries < 0:
		cfg.MaxRetries = 0
	}
	return &Client{cfg: cfg}, nil
}

// APIError is a non-2xx response from PayPal.
type APIError struct {
	Status  int
	Name    string
	Message string
	DebugID string
	Details json.RawMessage
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("paypal: HTTP %d", e.Status)
	if e.Name != "" {
		s += " " + e.Name
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	if e.DebugID != "" {
		s += " (debug_id " + e.DebugID + ")"
	}
	return s
}

func parseAPIError(status int, header http.Header, body []byte) *APIError {
	e := &APIError{Status: status, DebugID: header.Get("Paypal-Debug-Id")}
	var p struct {
		Name             string          `json:"name"`
		Message          string          `json:"message"`
		DebugID          string          `json:"debug_id"`
		Details          json.RawMessage `json:"details"`
		Error            string          `json:"error"`
		ErrorDescription string          `json:"error_description"`
	}
	if json.Unmarshal(body, &p) == nil {
		e.Name = p.Name
		e.Message = p.Message
		e.Details = p.Details
		if p.DebugID != "" {
			e.DebugID = p.DebugID
		}
		if e.Name == "" {
			e.Name = p.Error
		}
		if e.Message == "" {
			e.Message = p.ErrorDescription
		}
	}
	return e
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.cfg.Now().Before(c.tokenExp) {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/v1/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("paypal: token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode != http.StatusOK {
		return "", parseAPIError(resp.StatusCode, resp.Header, body)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("paypal: malformed token response")
	}
	c.token = tr.AccessToken
	ttl := time.Duration(tr.ExpiresIn)*time.Second - time.Minute // refresh a minute early
	if ttl < 0 {
		ttl = 0
	}
	c.tokenExp = c.cfg.Now().Add(ttl)
	return c.token, nil
}

func (c *Client) invalidateToken() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

// rawBody is sent byte-for-byte (json.Marshal would re-escape a RawMessage,
// which must not happen for webhook verification).
type rawBody []byte

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status == 500 || status == 502 || status == 503 || status == 504
}

func (c *Client) backoff(attempt int) {
	c.cfg.Sleep(time.Duration(250*(1<<attempt)) * time.Millisecond)
}

// do performs an authenticated request. requestID, when set, is sent as
// PayPal-Request-Id and makes the call safe to retry.
func (c *Client) do(ctx context.Context, method, path string, in, out any, requestID string) error {
	var payload []byte
	switch v := in.(type) {
	case nil:
	case rawBody:
		payload = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("paypal: marshal request: %w", err)
		}
		payload = b
	}
	idempotent := method == http.MethodGet || requestID != ""
	attempt, refreshed := 0, false
	for {
		tok, err := c.accessToken(ctx)
		if err != nil {
			return err
		}
		var rdr io.Reader
		if payload != nil {
			rdr = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, rdr)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		if requestID != "" {
			req.Header.Set("PayPal-Request-Id", requestID)
		}
		resp, err := c.cfg.HTTPClient.Do(req)
		if err != nil {
			if idempotent && attempt < c.cfg.MaxRetries && ctx.Err() == nil {
				c.backoff(attempt)
				attempt++
				continue
			}
			return fmt.Errorf("paypal: %s %s: %w", method, path, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			if out != nil && len(bytes.TrimSpace(body)) > 0 {
				if err := json.Unmarshal(body, out); err != nil {
					return fmt.Errorf("paypal: decoding %s %s response: %w", method, path, err)
				}
			}
			return nil
		case resp.StatusCode == http.StatusUnauthorized && !refreshed:
			c.invalidateToken() // token may have been revoked; retry once with a fresh one
			refreshed = true
			continue
		case retryable(resp.StatusCode) && idempotent && attempt < c.cfg.MaxRetries:
			c.backoff(attempt)
			attempt++
			continue
		default:
			return parseAPIError(resp.StatusCode, resp.Header, body)
		}
	}
}

func requireID(requestID string) error {
	if strings.TrimSpace(requestID) == "" {
		return errors.New("paypal: a PayPal-Request-Id (idempotency key) is required for this call")
	}
	return nil
}
