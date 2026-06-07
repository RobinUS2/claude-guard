package stop

// LLMStopRule is a semantic completeness reviewer that runs AFTER all
// deterministic rules. It calls a fast LLM (Haiku) to decide whether
// the session's last turn represents a genuine task completion.
//
// Fires at most once per session (MaxContinues = 1) via the existing
// session fire-count tracking — no separate state needed.
//
// Only injects on HIGH confidence that something concrete was missed.
// Medium/low confidence → no injection (conservative by design).
//
// Rate limiting: 2-second timeout hard cap. If LLM is unavailable or
// slow, the hook returns immediately with no injection — Claude stops.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/llm"
)

// LLMReviewDecision is the parsed JSON response from the stop-hook LLM call.
type LLMReviewDecision struct {
	Complete   bool   `json:"complete"`
	Confidence string `json:"confidence"` // "high" | "medium" | "low"
	Inject     string `json:"inject"`     // message to inject if not complete
	SkipReason string `json:"skip_reason"`
}

// LLMStopRule implements StopRule using a fast LLM for semantic review.
// Instantiate with NewLLMStopRule; nil is safe (rule returns false always).
type LLMStopRule struct {
	apiKey  string
	model   string
	timeout time.Duration
	client  *http.Client
}

// NewLLMStopRule returns a configured LLMStopRule using the first Anthropic
// API key found in the environment, or nil if no key is set.
// Use nil safely — nil LLMStopRule implements StopRule as a no-op.
func NewLLMStopRule() *LLMStopRule {
	key := ""
	for _, env := range llm.AnthropicEnvKeys {
		if v := os.Getenv(env); v != "" {
			key = v
			break
		}
	}
	if key == "" {
		return nil
	}
	return &LLMStopRule{
		apiKey:  key,
		model:   "claude-haiku-4-5-20251001",
		timeout: 2 * time.Second,
		client:  &http.Client{Timeout: 3 * time.Second}, // slightly above to catch slow starts
	}
}

func (r *LLMStopRule) Name() string { return "llm-semantic-review" }

// HighConfidence returns true so this rule runs even when stop_hook_active=true.
// The LLM provides semantic analysis that deterministic rules can't — it should
// always be available as a safety net even in high-confidence mode.
func (r *LLMStopRule) HighConfidence() bool { return true }

// MaxContinues = 1 means the session fire-count system caps this rule at one
// injection per session without any additional state management needed.
func (r *LLMStopRule) MaxContinues() int { return 1 }

// TextPreFilter: no pre-filter — the LLM can decide to skip based on content.
func (r *LLMStopRule) TextPreFilter() string { return "" }

func (r *LLMStopRule) Eval(t Transcript, _ ShellContext) (bool, string) {
	if r == nil {
		return false, ""
	}

	// Skip if this is a very short session (< 2 turns) — not enough context.
	if t.TurnCount < 2 {
		return false, ""
	}

	// Skip if the last assistant message is empty — nothing to review.
	if strings.TrimSpace(t.LastAssistantText) == "" {
		return false, ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	dec, err := r.classify(ctx, t)
	if err != nil || dec == nil {
		// Fail open — don't block Claude on LLM errors.
		return false, ""
	}

	// Only inject on HIGH confidence + explicitly incomplete task.
	if dec.Complete || dec.Confidence != "high" || strings.TrimSpace(dec.Inject) == "" {
		return false, ""
	}

	return true, dec.Inject
}

// classify calls the Anthropic messages API and parses the decision.
func (r *LLMStopRule) classify(ctx context.Context, t Transcript) (*LLMReviewDecision, error) {
	userMsg := buildStopReviewPrompt(t)

	reqBody := map[string]any{
		"model":      r.model,
		"max_tokens": 150,
		"system":     stopReviewSystemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": userMsg},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", r.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic stop review: status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}

	// Parse Anthropic messages response.
	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &apiResp); err != nil || len(apiResp.Content) == 0 {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return parseStopDecision(apiResp.Content[0].Text)
}

// parseStopDecision extracts JSON from the model response.
// Handles cases where the model wraps JSON in a code block.
func parseStopDecision(text string) (*LLMReviewDecision, error) {
	text = strings.TrimSpace(text)
	// Strip markdown code fences if present.
	if strings.HasPrefix(text, "```") {
		lines := strings.SplitN(text, "\n", 2)
		if len(lines) > 1 {
			text = lines[1]
		}
		if idx := strings.LastIndex(text, "```"); idx >= 0 {
			text = text[:idx]
		}
		text = strings.TrimSpace(text)
	}

	var dec LLMReviewDecision
	if err := json.Unmarshal([]byte(text), &dec); err != nil {
		return nil, fmt.Errorf("parse decision JSON: %w", err)
	}
	return &dec, nil
}

// buildStopReviewPrompt assembles a compact prompt from the transcript.
// Hard-capped to keep tokens low — Haiku is fast but still costs.
func buildStopReviewPrompt(t Transcript) string {
	var b strings.Builder

	b.WriteString("USER REQUEST:\n")
	first := t.FirstUserText
	if len(first) > 300 {
		first = first[:297] + "..."
	}
	b.WriteString(first)
	b.WriteString("\n\nASSISTANT'S LAST RESPONSE:\n")
	last := t.LastAssistantText
	if len(last) > 300 {
		last = last[:297] + "..."
	}
	b.WriteString(last)

	if len(t.BashCalls) > 0 {
		b.WriteString("\n\nACTIONS TAKEN (bash calls this session):\n")
		for i, call := range t.BashCalls {
			if i >= 8 { // cap at 8 to keep prompt small
				fmt.Fprintf(&b, "  ... and %d more\n", len(t.BashCalls)-8)
				break
			}
			c := call
			if len(c) > 100 {
				c = c[:97] + "..."
			}
			fmt.Fprintf(&b, "  • %s\n", c)
		}
	}

	if t.HasTodoWrite && len(t.LastTodoItems) > 0 {
		b.WriteString("\nOPEN TODO ITEMS:\n")
		for _, item := range t.LastTodoItems {
			if item.Status == "pending" || item.Status == "in_progress" {
				fmt.Fprintf(&b, "  [%s] %s\n", item.Status, item.Content)
			}
		}
	}

	b.WriteString("\nAnswer in JSON only.")
	return b.String()
}

const stopReviewSystemPrompt = `You are a task-completion checker for an AI coding assistant.
Determine if the assistant's last response represents a genuinely COMPLETE handoff to the user.

Answer ONLY in JSON:
{
  "complete": true | false,
  "confidence": "high" | "medium" | "low",
  "inject": "one concrete sentence to inject if NOT complete (empty string if complete)",
  "skip_reason": "brief reason for skipping injection (if complete)"
}

Rules:
- complete=false ONLY when you are HIGH confidence something CONCRETE was missed
  (e.g. "tests mentioned but not run", "file described but not committed")
- When in doubt → complete=true (Claude likely finished, just phrased oddly)
- inject must be 1 sentence, specific, actionable ("Run go test to verify" not "check your work")
- Do NOT inject for: style improvements, "could be better", vague concerns
- Do NOT inject if todo items are all "completed"
- Respond with raw JSON only, no markdown`
