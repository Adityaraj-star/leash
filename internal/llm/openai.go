package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// This file translates between Leash's message types (which follow Anthropic's
// shape: content blocks of type text, tool_use and tool_result) and the
// OpenAI-style chat-completions format spoken by Groq, OpenRouter and others.
//
//	Leash                                  chat completions
//	assistant text block                   message.content
//	assistant tool_use block               message.tool_calls[] (arguments is a JSON string)
//	user tool_result block                 a separate message with role "tool"
//	Tool.InputSchema                       tools[].function.parameters

type oaToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaMessage struct {
	Role       string       `json:"role"`
	Content    *string      `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type oaRequest struct {
	Model       string      `json:"model"`
	Messages    []oaMessage `json:"messages"`
	Tools       []oaTool    `json:"tools,omitempty"`
	MaxTokens   int         `json:"max_tokens"`
	Temperature *float64    `json:"temperature,omitempty"`
}

func strp(s string) *string { return &s }

func marshalOpenAI(model string, maxTokens int, r Request) ([]byte, error) {
	req := oaRequest{Model: model, MaxTokens: maxTokens, Temperature: r.Temperature}
	if r.System != "" {
		req.Messages = append(req.Messages, oaMessage{Role: "system", Content: strp(r.System)})
	}
	for _, m := range r.Messages {
		switch m.Role {
		case "assistant":
			var text []string
			am := oaMessage{Role: "assistant"}
			for _, b := range m.Content {
				switch b.Type {
				case "text":
					if b.Text != "" {
						text = append(text, b.Text)
					}
				case "tool_use":
					tc := oaToolCall{ID: b.ID, Type: "function"}
					tc.Function.Name = b.Name
					tc.Function.Arguments = string(b.Input)
					if strings.TrimSpace(tc.Function.Arguments) == "" {
						tc.Function.Arguments = "{}"
					}
					am.ToolCalls = append(am.ToolCalls, tc)
				}
			}
			if len(text) > 0 {
				am.Content = strp(strings.Join(text, "\n"))
			}
			req.Messages = append(req.Messages, am)
		default: // user
			var text []string
			// Tool results answer the assistant's tool calls, so they come first.
			for _, b := range m.Content {
				switch b.Type {
				case "tool_result":
					c := b.Content
					if c == "" {
						c = "(empty)"
					}
					if b.IsError {
						c = "Error: " + c
					}
					req.Messages = append(req.Messages, oaMessage{Role: "tool", ToolCallID: b.ToolUseID, Content: strp(c)})
				case "text":
					if b.Text != "" {
						text = append(text, b.Text)
					}
				}
			}
			if len(text) > 0 {
				req.Messages = append(req.Messages, oaMessage{Role: "user", Content: strp(strings.Join(text, "\n"))})
			}
		}
	}
	for _, t := range r.Tools {
		ot := oaTool{Type: "function"}
		ot.Function.Name, ot.Function.Description = t.Name, t.Description
		ot.Function.Parameters = t.InputSchema
		if len(ot.Function.Parameters) == 0 {
			ot.Function.Parameters = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		req.Tools = append(req.Tools, ot)
	}
	return json.Marshal(req)
}

type oaResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content   *string      `json:"content"`
			ToolCalls []oaToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func decodeOpenAI(data []byte) (*Response, error) {
	var in oaResponse
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	if len(in.Choices) == 0 {
		return nil, errors.New("the answer has no choices")
	}
	ch := in.Choices[0]
	out := &Response{
		Model: in.Model,
		Usage: Usage{InputTokens: in.Usage.PromptTokens, OutputTokens: in.Usage.CompletionTokens},
	}
	if ch.Message.Content != nil && strings.TrimSpace(*ch.Message.Content) != "" {
		out.Content = append(out.Content, Block{Type: "text", Text: *ch.Message.Content})
	}
	for i, tc := range ch.Message.ToolCalls {
		id := tc.ID
		if id == "" {
			id = fmt.Sprintf("call_%d", i)
		}
		args := strings.TrimSpace(tc.Function.Arguments)
		var input json.RawMessage
		switch {
		case args == "":
			input = json.RawMessage(`{}`)
		case json.Valid([]byte(args)):
			input = json.RawMessage(args)
		default:
			// Models sometimes emit broken JSON. Keep the text so the tool can say what
			// was wrong and the model can try again.
			b, _ := json.Marshal(map[string]string{"_unparsed_arguments": args})
			input = b
		}
		out.Content = append(out.Content, Block{Type: "tool_use", ID: id, Name: tc.Function.Name, Input: input})
	}
	switch {
	case len(ch.Message.ToolCalls) > 0 || ch.FinishReason == "tool_calls":
		out.StopReason = "tool_use"
	case ch.FinishReason == "length":
		out.StopReason = "max_tokens"
	default:
		out.StopReason = "end_turn"
	}
	return out, nil
}
