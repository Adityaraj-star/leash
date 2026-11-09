package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(h http.HandlerFunc) (*Client, *httptest.Server, *[]time.Duration) {
	srv := httptest.NewServer(h)
	var sleeps []time.Duration
	return &Client{APIKey: "k-test", BaseURL: srv.URL, Model: "m-test", Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }}, srv, &sleeps
}

const okBody = `{"content":[{"type":"text","text":"hello"},{"type":"tool_use","id":"tu_1","name":"browse","input":{"url":"http://x"}}],"stop_reason":"tool_use","model":"m-test","usage":{"input_tokens":11,"output_tokens":7}}`

func TestRequestShapeAndResponseParsing(t *testing.T) {
	var got map[string]any
	var hdr http.Header
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		if r.URL.Path != "/v1/messages" || r.Method != "POST" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		io.WriteString(w, okBody)
	})
	defer srv.Close()
	temp := 0.0
	resp, err := c.Complete(context.Background(), Request{
		System: "be brief", MaxTokens: 300, Temperature: &temp,
		Messages: []Message{{Role: "user", Content: []Block{{Type: "text", Text: "hi"}}}},
		Tools:    []Tool{{Name: "browse", Description: "fetch", InputSchema: json.RawMessage(`{"type":"object"}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Get("x-api-key") != "k-test" || hdr.Get("anthropic-version") != APIVersion || hdr.Get("content-type") != "application/json" {
		t.Fatalf("headers: %v", hdr)
	}
	if got["model"] != "m-test" || got["system"] != "be brief" || got["max_tokens"].(float64) != 300 {
		t.Fatalf("body: %v", got)
	}
	if tools := got["tools"].([]any); len(tools) != 1 || tools[0].(map[string]any)["input_schema"] == nil {
		t.Fatalf("tools: %v", got["tools"])
	}
	if resp.Text() != "hello" || len(resp.ToolUses()) != 1 || resp.ToolUses()[0].Name != "browse" || string(resp.ToolUses()[0].Input) != `{"url":"http://x"}` {
		t.Fatalf("response: %+v", resp)
	}
	if resp.Usage.InputTokens != 11 || resp.Usage.OutputTokens != 7 {
		t.Fatalf("usage: %+v", resp.Usage)
	}
}

func TestToolResultsAreSentBack(t *testing.T) {
	var got struct {
		Messages []Message `json:"messages"`
	}
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		io.WriteString(w, `{"content":[{"type":"text","text":"done"}],"stop_reason":"end_turn","usage":{}}`)
	})
	defer srv.Close()
	_, err := c.Complete(context.Background(), Request{Messages: []Message{
		{Role: "user", Content: []Block{{Type: "text", Text: "go"}}},
		{Role: "assistant", Content: []Block{{Type: "tool_use", ID: "tu_1", Name: "browse", Input: json.RawMessage(`{}`)}}},
		{Role: "user", Content: []Block{{Type: "tool_result", ToolUseID: "tu_1", Content: "page text", IsError: true}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tr := got.Messages[2].Content[0]
	if tr.Type != "tool_result" || tr.ToolUseID != "tu_1" || tr.Content != "page text" || !tr.IsError {
		t.Fatalf("tool result: %+v", tr)
	}
	if string(got.Messages[1].Content[0].Input) != `{}` {
		t.Fatalf("an empty tool input must still be sent: %+v", got.Messages[1].Content[0])
	}
}

func TestOverloadIsRetriedWithBackoff(t *testing.T) {
	var n int32
	c, srv, sleeps := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.Header().Set("retry-after", "2")
			w.WriteHeader(529)
			io.WriteString(w, `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`)
			return
		}
		io.WriteString(w, okBody)
	})
	defer srv.Close()
	if _, err := c.Complete(context.Background(), Request{}); err != nil {
		t.Fatal(err)
	}
	if n != 3 || len(*sleeps) != 2 || (*sleeps)[0] != 2*time.Second {
		t.Fatalf("attempts=%d sleeps=%v (Retry-After must be honored)", n, *sleeps)
	}
}

func TestClientErrorsAreNotRetried(t *testing.T) {
	var n int32
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
	})
	defer srv.Close()
	_, err := c.Complete(context.Background(), Request{})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 401 || ae.Type != "authentication_error" || !strings.Contains(ae.Message, "x-api-key") {
		t.Fatalf("%v", err)
	}
	if n != 1 {
		t.Fatalf("a 401 must not be retried (%d attempts)", n)
	}
}

func TestGivesUpAfterTheRetriesAndReportsTheAPIError(t *testing.T) {
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		io.WriteString(w, `{"type":"error","error":{"type":"api_error","message":"down"}}`)
	})
	defer srv.Close()
	c.MaxRetries = 2
	_, err := c.Complete(context.Background(), Request{})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 503 {
		t.Fatalf("%v", err)
	}
}

func TestTheSpendCapStopsTheRun(t *testing.T) {
	var n int32
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		io.WriteString(w, okBody)
	})
	defer srv.Close()
	c.Budget = &Budget{MaxCalls: 2}
	for i := 0; i < 2; i++ {
		if _, err := c.Complete(context.Background(), Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Complete(context.Background(), Request{}); !errors.Is(err, ErrBudget) {
		t.Fatalf("the third call must be refused: %v", err)
	}
	if n != 2 {
		t.Fatalf("the refused call must not reach the API (%d calls)", n)
	}

	c2, srv2, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, okBody) })
	defer srv2.Close()
	c2.Budget = &Budget{MaxOutputTokens: 10}
	c2.Complete(context.Background(), Request{})
	c2.Complete(context.Background(), Request{}) // 14 output tokens used now
	if _, err := c2.Complete(context.Background(), Request{}); !errors.Is(err, ErrBudget) {
		t.Fatalf("%v", err)
	}
	if calls, in, out := c2.Budget.Used(); calls != 2 || in != 22 || out != 14 {
		t.Fatalf("used: %d %d %d", calls, in, out)
	}
}

func TestAContextCancelStopsRetrying(t *testing.T) {
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(529) })
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	c.Sleep = func(time.Duration) { cancel() }
	if _, err := c.Complete(ctx, Request{}); err == nil {
		t.Fatal("expected an error after cancellation")
	}
}
