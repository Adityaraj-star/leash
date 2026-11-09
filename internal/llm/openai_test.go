package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func oaClient(h http.HandlerFunc) (*Client, *httptest.Server) {
	srv := httptest.NewServer(h)
	return &Client{Provider: ProviderOpenAI, Name: "groq", APIKey: "gsk-test", BaseURL: srv.URL + "/v1", Model: "m-test",
		Sleep: func(time.Duration) {}, Budget: &Budget{MaxCalls: 50}}, srv
}

const oaToolBody = `{"model":"m-test","choices":[{"message":{"content":null,"tool_calls":[{"id":"call_9","type":"function","function":{"name":"browse","arguments":"{\"url\":\"http://x\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":21,"completion_tokens":5}}`

func TestOpenAIRequestShape(t *testing.T) {
	var got map[string]any
	var path, auth string
	c, srv := oaClient(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		w.Write([]byte(oaToolBody))
	})
	defer srv.Close()
	_, err := c.Complete(context.Background(), Request{
		System:    "be careful",
		MaxTokens: 300,
		Tools:     []Tool{{Name: "browse", Description: "read a page", InputSchema: json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"}}}`)}},
		Messages: []Message{
			{Role: "user", Content: []Block{{Type: "text", Text: "buy a card"}}},
			{Role: "assistant", Content: []Block{{Type: "tool_use", ID: "call_1", Name: "browse", Input: json.RawMessage(`{"url":"http://shop"}`)}}},
			{Role: "user", Content: []Block{{Type: "tool_result", ToolUseID: "call_1", Content: "page text"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/v1/chat/completions" || auth != "Bearer gsk-test" {
		t.Fatalf("path %q auth %q", path, auth)
	}
	msgs := got["messages"].([]any)
	roles := []string{}
	for _, m := range msgs {
		roles = append(roles, m.(map[string]any)["role"].(string))
	}
	if strings.Join(roles, ",") != "system,user,assistant,tool" {
		t.Fatalf("roles %v", roles)
	}
	asst := msgs[2].(map[string]any)
	tc := asst["tool_calls"].([]any)[0].(map[string]any)
	fn := tc["function"].(map[string]any)
	if asst["content"] != nil || tc["id"] != "call_1" || fn["name"] != "browse" || fn["arguments"] != `{"url":"http://shop"}` {
		t.Fatalf("assistant message %v", asst)
	}
	tool := msgs[3].(map[string]any)
	if tool["tool_call_id"] != "call_1" || tool["content"] != "page text" {
		t.Fatalf("tool message %v", tool)
	}
	tools := got["tools"].([]any)[0].(map[string]any)
	if tools["type"] != "function" || tools["function"].(map[string]any)["name"] != "browse" {
		t.Fatalf("tools %v", tools)
	}
	if got["max_tokens"].(float64) != 300 || got["model"] != "m-test" {
		t.Fatalf("body %v", got)
	}
}

func TestOpenAIResponseBecomesLeashBlocks(t *testing.T) {
	c, srv := oaClient(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(oaToolBody)) })
	defer srv.Close()
	resp, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Content: []Block{{Type: "text", Text: "hi"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	uses := resp.ToolUses()
	if len(uses) != 1 || uses[0].ID != "call_9" || uses[0].Name != "browse" || string(uses[0].Input) != `{"url":"http://x"}` {
		t.Fatalf("tool uses %+v", uses)
	}
	if resp.StopReason != "tool_use" || resp.Usage.InputTokens != 21 || resp.Usage.OutputTokens != 5 {
		t.Fatalf("response %+v", resp)
	}
	if func() int { n, _, _ := c.Budget.Used(); return n }() != 1 {
		t.Errorf("the call was not counted against the budget")
	}
}

func TestOpenAITextAnswerAndBrokenArguments(t *testing.T) {
	r1, err := decodeOpenAI([]byte(`{"choices":[{"message":{"content":"Done."},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`))
	if err != nil || r1.Text() != "Done." || r1.StopReason != "end_turn" || len(r1.ToolUses()) != 0 {
		t.Fatalf("%+v %v", r1, err)
	}
	r2, err := decodeOpenAI([]byte(`{"choices":[{"message":{"tool_calls":[{"function":{"name":"pay","arguments":"{not json"}},{"function":{"name":"x","arguments":""}}]},"finish_reason":"tool_calls"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	u := r2.ToolUses()
	if len(u) != 2 || u[0].ID != "call_0" || !strings.Contains(string(u[0].Input), "_unparsed_arguments") || string(u[1].Input) != "{}" {
		t.Fatalf("%+v", u)
	}
	if _, err := decodeOpenAI([]byte(`{"choices":[]}`)); err == nil {
		t.Error("an answer with no choices should be an error")
	}
	r3, _ := decodeOpenAI([]byte(`{"choices":[{"message":{"content":"cut"},"finish_reason":"length"}]}`))
	if r3.StopReason != "max_tokens" {
		t.Errorf("stop reason %q", r3.StopReason)
	}
}

func TestOpenAIRateLimitIsRetried(t *testing.T) {
	n := 0
	c, srv := oaClient(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("retry-after", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":{"type":"tokens","message":"slow down"}}`))
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`))
	})
	defer srv.Close()
	resp, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Content: []Block{{Type: "text", Text: "hi"}}}}})
	if err != nil || resp.Text() != "ok" || n != 2 {
		t.Fatalf("%v %v calls=%d", resp, err, n)
	}
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if c, err := FromEnv(env(nil), ""); c != nil || err != nil {
		t.Fatalf("no key should give nil, nil: %v %v", c, err)
	}
	c, err := FromEnv(env(map[string]string{"GROQ_API_KEY": "g"}), "")
	if err != nil || c.Provider != ProviderOpenAI || c.Model != GroqDefaultModel || c.BaseURL != GroqBaseURL || c.Describe() != "groq "+GroqDefaultModel {
		t.Fatalf("groq: %+v %v", c, err)
	}
	c, _ = FromEnv(env(map[string]string{"GROQ_API_KEY": "g", "LEASH_MODEL": "other"}), "")
	if c.Model != "other" {
		t.Errorf("LEASH_MODEL ignored: %s", c.Model)
	}
	c, _ = FromEnv(env(map[string]string{"GROQ_API_KEY": "g"}), "flagmodel")
	if c.Model != "flagmodel" {
		t.Errorf("the argument should win: %s", c.Model)
	}
	c, err = FromEnv(env(map[string]string{"ANTHROPIC_API_KEY": "a"}), "")
	if err != nil || c.Provider != ProviderAnthropic || c.Model != "" || !strings.HasPrefix(c.Describe(), "anthropic claude") {
		t.Fatalf("anthropic: %+v %v", c, err)
	}
	if _, err := FromEnv(env(map[string]string{"LEASH_LLM_PROVIDER": "openai", "LEASH_LLM_API_KEY": "k", "LEASH_LLM_BASE_URL": "https://x/v1"}), ""); err == nil {
		t.Error("a generic OpenAI-compatible API needs a model")
	}
	if _, err := FromEnv(env(map[string]string{"LEASH_LLM_PROVIDER": "nope", "GROQ_API_KEY": "g"}), ""); err == nil {
		t.Error("an unknown provider should be an error")
	}
	if _, err := FromEnv(env(map[string]string{"LEASH_LLM_PROVIDER": "groq"}), ""); err == nil {
		t.Error("groq without a key should be an error")
	}
}
