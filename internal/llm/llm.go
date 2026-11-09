// Package llm is a small model client written against the standard library only
// (the project avoids third-party dependencies). It supports what Leash needs: a
// system prompt, tool definitions, tool_use and tool_result blocks, retries on
// overload, and a hard spend cap.
//
// Two wire formats are supported behind the same Complete call: Anthropic's
// Messages API (the default) and the OpenAI-style chat-completions format that
// Groq, OpenRouter and many other providers speak (Provider: ProviderOpenAI, see
// openai.go). FromEnv (env.go) picks one from environment variables.
//
// Model names change often: check the provider's current documentation before a long run.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultBaseURL = "https://api.anthropic.com"
	APIVersion     = "2023-06-01"
	DefaultModel   = "claude-sonnet-5-5"

	// ProviderAnthropic is the zero value's meaning: Anthropic's Messages API.
	ProviderAnthropic = "anthropic"
	// ProviderOpenAI selects the OpenAI-style chat-completions format.
	ProviderOpenAI = "openai"

	// GroqBaseURL and GroqDefaultModel are the defaults used when GROQ_API_KEY is set.
	// The model must support tool calling; override it with LEASH_MODEL.
	GroqBaseURL      = "https://api.groq.com/openai/v1"
	GroqDefaultModel = "llama-3.3-70b-versatile"
)

// Block is one piece of message content: text, a tool call, or a tool result.
type Block struct {
	Type string `json:"type"`
	// text
	Text string `json:"text,omitempty"`
	// tool_use
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	// tool_result
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
}

type Message struct {
	Role    string  `json:"role"` // "user" or "assistant"
	Content []Block `json:"content"`
}

// Tool describes a function the model may call. InputSchema is a JSON Schema object.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type Request struct {
	System      string
	Messages    []Message
	Tools       []Tool
	MaxTokens   int
	Temperature *float64
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type Response struct {
	Content    []Block `json:"content"`
	StopReason string  `json:"stop_reason"`
	Model      string  `json:"model"`
	Usage      Usage   `json:"usage"`
}

// Text joins the text blocks of a response.
func (r *Response) Text() string {
	var parts []string
	for _, b := range r.Content {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// ToolUses returns the tool calls in a response.
func (r *Response) ToolUses() []Block {
	var out []Block
	for _, b := range r.Content {
		if b.Type == "tool_use" {
			out = append(out, b)
		}
	}
	return out
}

// APIError is an error answer from the API.
type APIError struct {
	Status  int
	Type    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("llm: HTTP %d %s: %s", e.Status, e.Type, e.Message)
}

// ErrBudget means the spend cap was reached; nothing more is sent.
var ErrBudget = errors.New("llm: spend cap reached")

// Budget is a hard cap on what a run may use. A zero limit means no limit for
// that dimension. It is safe for concurrent use.
type Budget struct {
	MaxCalls        int
	MaxInputTokens  int
	MaxOutputTokens int

	mu             sync.Mutex
	calls, in, out int
}

func (b *Budget) allow() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if (b.MaxCalls > 0 && b.calls >= b.MaxCalls) ||
		(b.MaxInputTokens > 0 && b.in >= b.MaxInputTokens) ||
		(b.MaxOutputTokens > 0 && b.out >= b.MaxOutputTokens) {
		return ErrBudget
	}
	b.calls++
	return nil
}

func (b *Budget) add(u Usage) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.in += u.InputTokens
	b.out += u.OutputTokens
	b.mu.Unlock()
}

// Used reports what has been spent so far.
func (b *Budget) Used() (calls, in, out int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, b.in, b.out
}

type Client struct {
	// Provider is ProviderAnthropic (or empty) or ProviderOpenAI.
	Provider string
	// Name is only used in messages, for example "groq".
	Name       string
	APIKey     string
	BaseURL    string
	Model      string
	HTTP       *http.Client
	MaxRetries int // default 4
	Budget     *Budget
	Sleep      func(time.Duration) // tests
}

// Describe says which provider and model this client talks to, for logs and doctor.
func (c *Client) Describe() string {
	name := c.Name
	if name == "" {
		name = c.Provider
	}
	if name == "" {
		name = ProviderAnthropic
	}
	m := c.Model
	if m == "" && c.Provider != ProviderOpenAI {
		m = DefaultModel
	}
	return name + " " + m
}

func (c *Client) label() string {
	if c.Name != "" {
		return c.Name
	}
	if c.openAI() {
		return "llm"
	}
	return "anthropic"
}

func (c *Client) openAI() bool { return c.Provider == ProviderOpenAI }

func (c *Client) base() string {
	if c.BaseURL == "" {
		return DefaultBaseURL
	}
	return strings.TrimRight(c.BaseURL, "/")
}

type wireRequest struct {
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens"`
	System      string    `json:"system,omitempty"`
	Messages    []Message `json:"messages"`
	Tools       []Tool    `json:"tools,omitempty"`
	Temperature *float64  `json:"temperature,omitempty"`
}

// Complete sends one request and returns the model's answer. It retries overloads
// and rate limits with backoff (honoring Retry-After) and never exceeds the Budget.
func (c *Client) Complete(ctx context.Context, r Request) (*Response, error) {
	if err := c.Budget.allow(); err != nil {
		return nil, err
	}
	model := c.Model
	if model == "" {
		model = DefaultModel
	}
	max := r.MaxTokens
	if max <= 0 {
		max = 1024
	}
	var body []byte
	var err error
	if c.openAI() {
		body, err = marshalOpenAI(model, max, r)
	} else {
		body, err = json.Marshal(wireRequest{Model: model, MaxTokens: max, System: r.System, Messages: r.Messages, Tools: r.Tools, Temperature: r.Temperature})
	}
	if err != nil {
		return nil, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 120 * time.Second}
	}
	sleep := c.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	retries := c.MaxRetries
	if retries == 0 {
		retries = 4
	}

	var last error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			wait := time.Duration(1<<uint(attempt-1)) * time.Second
			if ra, ok := last.(*retryAfter); ok && ra.d > 0 {
				wait = ra.d
			}
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
			sleep(wait)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		path := "/v1/messages"
		if c.openAI() {
			path = "/chat/completions" // the base URL carries the /v1 part
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if c.openAI() {
			req.Header.Set("Authorization", "Bearer "+c.APIKey)
		} else {
			req.Header.Set("x-api-key", c.APIKey)
			req.Header.Set("anthropic-version", APIVersion)
		}
		req.Header.Set("content-type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			last = err
			continue // network trouble: retry
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if rerr != nil {
			last = rerr
			continue
		}
		if resp.StatusCode == http.StatusOK {
			var out Response
			if c.openAI() {
				o, err := decodeOpenAI(data)
				if err != nil {
					return nil, fmt.Errorf("%s: unreadable response: %w", c.label(), err)
				}
				out = *o
			} else if err := json.Unmarshal(data, &out); err != nil {
				return nil, fmt.Errorf("%s: unreadable response: %w", c.label(), err)
			}
			c.Budget.add(out.Usage)
			return &out, nil
		}
		ae := parseError(resp.StatusCode, data)
		switch resp.StatusCode {
		case 429, 500, 502, 503, 504, 529:
			secs, _ := strconv.Atoi(resp.Header.Get("retry-after"))
			last = &retryAfter{err: ae, d: time.Duration(secs) * time.Second}
			continue
		}
		return nil, ae // 400, 401, 403, 404: retrying cannot help
	}
	if ra, ok := last.(*retryAfter); ok {
		return nil, ra.err
	}
	return nil, last
}

type retryAfter struct {
	err *APIError
	d   time.Duration
}

func (r *retryAfter) Error() string { return r.err.Error() }

func parseError(status int, data []byte) *APIError {
	var e struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	ae := &APIError{Status: status}
	if json.Unmarshal(data, &e) == nil && e.Error.Type != "" {
		ae.Type, ae.Message = e.Error.Type, e.Error.Message
	} else {
		ae.Message = strings.TrimSpace(string(data))
		if len(ae.Message) > 200 {
			ae.Message = ae.Message[:200]
		}
	}
	return ae
}
