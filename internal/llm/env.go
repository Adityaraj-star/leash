package llm

import (
	"fmt"
	"strings"
)

// FromEnv builds a model client from environment variables. It returns (nil, nil)
// when no key is configured, so callers can decide whether that is an error.
//
// Provider choice, first match wins:
//
//	LEASH_LLM_PROVIDER = groq | openai | anthropic   (explicit)
//	GROQ_API_KEY set                                  -> groq
//	LEASH_LLM_BASE_URL and LEASH_LLM_API_KEY set      -> openai (any OpenAI-compatible API)
//	ANTHROPIC_API_KEY set                             -> anthropic
//
// The model is the argument if given, else LEASH_MODEL, else the provider's default
// (groq and anthropic only: for a generic OpenAI-compatible API you must name one).
func FromEnv(getenv func(string) string, model string) (*Client, error) {
	choice := strings.ToLower(strings.TrimSpace(getenv("LEASH_LLM_PROVIDER")))
	if choice == "" {
		switch {
		case getenv("GROQ_API_KEY") != "":
			choice = "groq"
		case getenv("LEASH_LLM_API_KEY") != "" && getenv("LEASH_LLM_BASE_URL") != "":
			choice = "openai"
		case getenv("ANTHROPIC_API_KEY") != "":
			choice = "anthropic"
		default:
			return nil, nil
		}
	}
	if model == "" {
		model = getenv("LEASH_MODEL")
	}
	switch choice {
	case "groq":
		key := getenv("GROQ_API_KEY")
		if key == "" {
			return nil, fmt.Errorf("LEASH_LLM_PROVIDER is groq but GROQ_API_KEY is not set")
		}
		if model == "" {
			model = GroqDefaultModel
		}
		// Free tiers have low per-minute limits, so wait and retry more than for a paid API.
		return &Client{Provider: ProviderOpenAI, Name: "groq", BaseURL: GroqBaseURL, APIKey: key, Model: model, MaxRetries: 6}, nil
	case "openai":
		key, base := getenv("LEASH_LLM_API_KEY"), getenv("LEASH_LLM_BASE_URL")
		if key == "" || base == "" {
			return nil, fmt.Errorf("provider openai needs LEASH_LLM_BASE_URL (including /v1) and LEASH_LLM_API_KEY")
		}
		if model == "" {
			return nil, fmt.Errorf("provider openai needs a model: set LEASH_MODEL")
		}
		return &Client{Provider: ProviderOpenAI, Name: "openai-compatible", BaseURL: base, APIKey: key, Model: model, MaxRetries: 6}, nil
	case "anthropic":
		key := getenv("ANTHROPIC_API_KEY")
		if key == "" {
			return nil, fmt.Errorf("LEASH_LLM_PROVIDER is anthropic but ANTHROPIC_API_KEY is not set")
		}
		return &Client{Provider: ProviderAnthropic, Name: "anthropic", APIKey: key, Model: model}, nil
	}
	return nil, fmt.Errorf("LEASH_LLM_PROVIDER must be groq, openai or anthropic, not %q", choice)
}
