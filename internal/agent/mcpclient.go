package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Adityaraj-star/leash/internal/llm"
)

// MCPClient speaks MCP's streamable HTTP transport (JSON responses) to a Leash
// server with the agent token.
type MCPClient struct {
	URL     string // e.g. http://127.0.0.1:8787/mcp
	Token   string
	HTTP    *http.Client
	session string
	id      int
}

func (m *MCPClient) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (m *MCPClient) rpc(ctx context.Context, method string, params any) (json.RawMessage, error) {
	m.id++
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+m.Token)
	if m.session != "" {
		req.Header.Set("Mcp-Session-Id", m.session)
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("the server refused the agent token")
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		m.session = sid
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("unreadable MCP response (HTTP %d): %.120s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out.Error != nil {
		return nil, fmt.Errorf("MCP error %d: %s", out.Error.Code, out.Error.Message)
	}
	return out.Result, nil
}

func (m *MCPClient) Initialize(ctx context.Context) error {
	_, err := m.rpc(ctx, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "leash-attacklab", "version": "1"}})
	return err
}

func (m *MCPClient) ListTools(ctx context.Context) ([]llm.Tool, error) {
	raw, err := m.rpc(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var res struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	tools := make([]llm.Tool, 0, len(res.Tools))
	for _, t := range res.Tools {
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		tools = append(tools, llm.Tool{Name: t.Name, Description: t.Description, InputSchema: schema})
	}
	return tools, nil
}

// CallTool runs one tool and returns its text and whether the server marked it an error.
func (m *MCPClient) CallTool(ctx context.Context, name string, args json.RawMessage) (string, bool, error) {
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	raw, err := m.rpc(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return "", false, err
	}
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", false, err
	}
	var parts []string
	for _, c := range res.Content {
		if c.Type == "text" {
			parts = append(parts, c.Text)
		}
	}
	return strings.Join(parts, "\n"), res.IsError, nil
}

type mcpTool struct {
	c   *MCPClient
	def llm.Tool
}

func (t mcpTool) Def() llm.Tool { return t.def }
func (t mcpTool) Call(ctx context.Context, in json.RawMessage) (string, bool) {
	out, isErr, err := t.c.CallTool(ctx, t.def.Name, in)
	if err != nil {
		return "error: " + err.Error(), true
	}
	return out, isErr
}

// MCPTools connects to a Leash MCP endpoint and exposes its tools to the model.
func MCPTools(ctx context.Context, url, token string, hc *http.Client) ([]Tool, error) {
	c := &MCPClient{URL: url, Token: token, HTTP: hc}
	if err := c.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("mcp initialize: %w", err)
	}
	defs, err := c.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("mcp tools/list: %w", err)
	}
	tools := make([]Tool, len(defs))
	for i, d := range defs {
		tools[i] = mcpTool{c: c, def: d}
	}
	return tools, nil
}
