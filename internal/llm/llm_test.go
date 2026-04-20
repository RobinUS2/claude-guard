package llm

import (
	"strings"
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

// --- buildUserMessage with file content ---

func TestBuildUserMessage_WithFileContent(t *testing.T) {
	in := ClassifyInput{
		Command:     "go run /tmp/test.go",
		Description: "Run test file",
		CWD:         "/home/user",
		FileContent: "package main\nfunc main() {}\n",
		FilePath:    "/tmp/test.go",
	}
	msg := buildUserMessage(in)
	if !strings.Contains(msg, "REFERENCED FILE") {
		t.Error("message should contain REFERENCED FILE section")
	}
	if !strings.Contains(msg, "/tmp/test.go") {
		t.Error("message should contain file path")
	}
	if !strings.Contains(msg, "package main") {
		t.Error("message should contain file content")
	}
}

func TestBuildUserMessage_WithoutFileContent(t *testing.T) {
	in := ClassifyInput{
		Command: "git status",
		CWD:     "/home/user",
	}
	msg := buildUserMessage(in)
	if strings.Contains(msg, "REFERENCED FILE") {
		t.Error("message should NOT contain REFERENCED FILE when no file content")
	}
}

func TestBuildUserMessage_WithTrustedPrograms(t *testing.T) {
	in := ClassifyInput{
		Command: "for id in 19 20 21; do taufinity datasheet get $id; done",
		CWD:     "/home/user",
		TrustedPrograms: []string{
			"gcloud", "git", "ls", "taufinity",
		},
	}
	msg := buildUserMessage(in)
	if !strings.Contains(msg, "OPERATOR-TRUSTED PROGRAMS") {
		t.Error("message should contain OPERATOR-TRUSTED PROGRAMS section")
	}
	if !strings.Contains(msg, "taufinity") {
		t.Error("trusted program name should appear in the prompt")
	}
	if !strings.Contains(msg, "LOOP COST") {
		t.Error("LOOP COST guidance should appear when trusted programs are present")
	}
}

func TestBuildUserMessage_WithoutTrustedPrograms(t *testing.T) {
	in := ClassifyInput{
		Command: "git status",
		CWD:     "/home/user",
	}
	msg := buildUserMessage(in)
	if strings.Contains(msg, "OPERATOR-TRUSTED PROGRAMS") {
		t.Error("message should NOT contain OPERATOR-TRUSTED PROGRAMS when list is empty")
	}
	if strings.Contains(msg, "LOOP COST") {
		t.Error("message should NOT contain LOOP COST when no trusted-program context")
	}
}

// --- ParseError diagnostics ---

func TestExtractDecision_TruncatedResponseIsStructured(t *testing.T) {
	// Real-world case: Gemini ran out of tokens mid-reason.
	raw := `{"decision":"safe","reason":"The command queries a BigQuery database and writes the output to a file in /tmp, which is a safe`
	_, err := extractDecision(raw)
	if err == nil {
		t.Fatal("expected parse error for truncated JSON")
	}
	var pe *ParseError
	if !errorsAs(err, &pe) {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if pe.RawLength != len(raw) {
		t.Errorf("RawLength = %d, want %d", pe.RawLength, len(raw))
	}
	if !pe.LooksTruncated {
		t.Error("LooksTruncated should be true for mid-value cutoff")
	}
	if pe.RawResponse != raw {
		t.Error("RawResponse should carry the full text the engine can log")
	}
}

func TestExtractDecision_ProseReturnsParseError_NotTruncated(t *testing.T) {
	// Model returned prose, not JSON — not the same failure mode as
	// a truncated response.
	_, err := extractDecision("I cannot help with that request.")
	var pe *ParseError
	if !errorsAs(err, &pe) {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if pe.LooksTruncated {
		t.Error("prose without JSON should NOT be flagged as truncated")
	}
}

func TestExtractDecision_WellFormedJSONParses(t *testing.T) {
	dec, err := extractDecision(`{"decision":"safe","reason":"ok","scope":"project"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Verdict != VerdictSafe {
		t.Errorf("Verdict = %q", dec.Verdict)
	}
}

// errorsAs is a tiny helper to avoid adding another import just for this test file.
func errorsAs(err error, target any) bool {
	for err != nil {
		if pe, ok := err.(*ParseError); ok {
			if tgt, ok := target.(**ParseError); ok {
				*tgt = pe
				return true
			}
		}
		type wrapper interface{ Unwrap() error }
		if w, ok := err.(wrapper); ok {
			err = w.Unwrap()
			continue
		}
		return false
	}
	return false
}
