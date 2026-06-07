package stop

import (
	"net/http"
	"testing"
	"time"
)

func TestParseStopDecision_Valid(t *testing.T) {
	raw := `{"complete":false,"confidence":"high","inject":"Run go test to verify.","skip_reason":""}`
	dec, err := parseStopDecision(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if dec.Complete {
		t.Error("want complete=false")
	}
	if dec.Confidence != "high" {
		t.Errorf("confidence = %q, want high", dec.Confidence)
	}
	if dec.Inject != "Run go test to verify." {
		t.Errorf("inject = %q", dec.Inject)
	}
}

func TestParseStopDecision_CodeFence(t *testing.T) {
	raw := "```json\n{\"complete\":true,\"confidence\":\"high\",\"inject\":\"\",\"skip_reason\":\"done\"}\n```"
	dec, err := parseStopDecision(raw)
	if err != nil {
		t.Fatalf("parse with code fence: %v", err)
	}
	if !dec.Complete {
		t.Error("want complete=true")
	}
}

func TestParseStopDecision_Invalid(t *testing.T) {
	_, err := parseStopDecision("not json")
	if err == nil {
		t.Error("expected parse error for invalid JSON")
	}
}

func TestLLMStopRule_NilSafe(t *testing.T) {
	var r *LLMStopRule
	ok, msg := r.Eval(Transcript{TurnCount: 5, LastAssistantText: "done"}, nil)
	if ok || msg != "" {
		t.Error("nil LLMStopRule should return (false, '')")
	}
}

func TestLLMStopRule_TooFewTurns(t *testing.T) {
	r := &LLMStopRule{apiKey: "test", model: "m", timeout: time.Second, client: http.DefaultClient}
	ok, _ := r.Eval(Transcript{TurnCount: 1, LastAssistantText: "done"}, nil)
	if ok {
		t.Error("should not inject for < 2 turn sessions")
	}
}

func TestLLMStopRule_HighConfidenceDecision(t *testing.T) {
	// Test the decision evaluation logic directly.
	dec := &LLMReviewDecision{
		Complete:   false,
		Confidence: "high",
		Inject:     "Run the tests.",
	}
	// Decision should trigger injection.
	shouldInject := !dec.Complete && dec.Confidence == "high" && dec.Inject != ""
	if !shouldInject {
		t.Error("high confidence incomplete should trigger injection")
	}

	// Verify nil rule is safe.
	tr := Transcript{
		TurnCount:         4,
		FirstUserText:     "Add tests for the new function",
		LastAssistantText: "I implemented the function in main.go",
		BashCalls:         []string{"go build ./..."},
	}
	var nilRule *LLMStopRule
	ok, msg := nilRule.Eval(tr, nil)
	if ok || msg != "" {
		t.Error("nil rule should not inject")
	}
}

func TestLLMStopRule_MediumConfidence_NoInject(t *testing.T) {
	// Even if incomplete, medium confidence should NOT inject (CTO feedback: conservative).
	dec := &LLMReviewDecision{
		Complete:   false,
		Confidence: "medium",
		Inject:     "You might want to check X",
	}
	// Simulate the decision logic from Eval.
	shouldInject := !dec.Complete && dec.Confidence == "high" && dec.Inject != ""
	if shouldInject {
		t.Error("medium confidence should not trigger injection")
	}
}

func TestBuildStopReviewPrompt_Truncation(t *testing.T) {
	longText := make([]byte, 500)
	for i := range longText {
		longText[i] = 'a'
	}
	tr := Transcript{
		FirstUserText:     string(longText),
		LastAssistantText: string(longText),
		BashCalls:         make([]string, 15), // more than the 8-cap
		TurnCount:         10,
	}
	for i := range tr.BashCalls {
		tr.BashCalls[i] = "git status"
	}
	prompt := buildStopReviewPrompt(tr)
	// Verify truncation occurred.
	if len(prompt) > 5000 {
		t.Errorf("prompt too long: %d chars", len(prompt))
	}
	// Verify the "and N more" truncation appears.
	if len(tr.BashCalls) > 8 && !testContains(prompt, "more") {
		t.Error("expected truncation indicator for >8 bash calls")
	}
}

func testContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
