package llm

import (
	"testing"
)

// fakeEnv builds a getenv function from a map.
func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestAutoSelect_AnthropicCanonical(t *testing.T) {
	c := AutoSelect("", fakeEnv(map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-xxx",
	}))
	if c == nil {
		t.Fatal("expected classifier")
	}
	if c.Provider() != "anthropic" {
		t.Errorf("Provider = %q", c.Provider())
	}
}

func TestAutoSelect_SITEGENAnthropicAlias(t *testing.T) {
	c := AutoSelect("", fakeEnv(map[string]string{
		"SITEGEN_ANTHROPIC_KEY": "sk-ant-xxx",
	}))
	if c == nil {
		t.Fatal("expected classifier from SITEGEN_ANTHROPIC_KEY alias")
	}
	if c.Provider() != "anthropic" {
		t.Errorf("Provider = %q, want anthropic", c.Provider())
	}
}

func TestAutoSelect_ClaudeApiKeyAlias(t *testing.T) {
	c := AutoSelect("", fakeEnv(map[string]string{
		"CLAUDE_API_KEY": "sk-ant-xxx",
	}))
	if c == nil {
		t.Fatal("expected classifier from CLAUDE_API_KEY alias")
	}
	if c.Provider() != "anthropic" {
		t.Errorf("Provider = %q", c.Provider())
	}
}

func TestAutoSelect_PreferenceOrderAnthropicFirst(t *testing.T) {
	c := AutoSelect("anthropic", fakeEnv(map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-xxx",
		"GEMINI_API_KEY":    "gemini-yyy",
	}))
	if c == nil || c.Provider() != "anthropic" {
		t.Errorf("anthropic should win; got %v", c)
	}
}

func TestAutoSelect_PreferenceOrderGeminiFirst(t *testing.T) {
	c := AutoSelect("gemini", fakeEnv(map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-xxx",
		"GEMINI_API_KEY":    "gemini-yyy",
	}))
	if c == nil || c.Provider() != "gemini" {
		t.Errorf("gemini should win when preferred; got %v", c)
	}
}

func TestAutoSelect_AnthropicPreferredButOnlyGeminiAvailable(t *testing.T) {
	c := AutoSelect("anthropic", fakeEnv(map[string]string{
		"GEMINI_API_KEY": "gemini-yyy",
	}))
	if c == nil || c.Provider() != "gemini" {
		t.Errorf("should fall back to gemini; got %v", c)
	}
}

func TestAutoSelect_NoKeysReturnsNil(t *testing.T) {
	c := AutoSelect("", fakeEnv(nil))
	if c != nil {
		t.Errorf("expected nil when no keys; got %v", c)
	}
}

func TestAutoSelect_EarlierAliasWins(t *testing.T) {
	// ANTHROPIC_API_KEY is first in the list — it should win over a later alias.
	c := AutoSelect("", fakeEnv(map[string]string{
		"ANTHROPIC_API_KEY":     "first",
		"SITEGEN_ANTHROPIC_KEY": "second",
	}))
	if c == nil {
		t.Fatal("expected classifier")
	}
	ac, ok := c.(*AnthropicClassifier)
	if !ok {
		t.Fatalf("expected AnthropicClassifier; got %T", c)
	}
	if ac.APIKey != "first" {
		t.Errorf("expected canonical key to win; got %q", ac.APIKey)
	}
}
