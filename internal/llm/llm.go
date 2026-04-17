// Package llm classifies shell commands as safe / unsafe / unsure via
// a fast LLM (Anthropic Haiku or Gemini Flash). The classifier is
// APPROVE-ONLY: an "unsafe" verdict falls through to the next tier
// rather than blocking, because the LLM's prompt is influenced by
// attacker-controlled command text (prompt injection) and we never
// want a misclassification to silently block legitimate work.
//
// Provider-agnostic via the Classifier interface. Two implementations
// are provided:
//
//   - AnthropicClassifier — POST /v1/messages, Haiku 4.5 by default
//   - GeminiClassifier    — POST /v1beta/models/{model}:generateContent
//
// Both share:
//   - Inline retry policy (1 retry on 5xx after 200ms, 1 retry on
//     brief 429)
//   - Breaker error types (RateLimitError, ServerError, TimeoutError)
//   - Strict JSON response parsing
//   - The same default system prompt (classifier.md)
//
// Tier 0 (secret redaction) lives in internal/redact and runs BEFORE
// any classifier call. The engine passes the redacted command text
// here; raw secrets never reach the network.
package llm

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
)

//go:embed classifier.md
var defaultSystemPrompt string

// DefaultSystemPrompt returns the embedded classifier prompt.
// Both providers use this as the default.
func DefaultSystemPrompt() string { return defaultSystemPrompt }

// Verdict is the classifier's final answer.
type Verdict string

const (
	// VerdictSafe means the engine may auto-approve this command.
	VerdictSafe Verdict = "safe"
	// VerdictUnsafe means the LLM thinks the command is dangerous.
	// The engine still does NOT block — it falls through. Blocks come
	// only from deterministic tier 1 rules. This avoids prompt-injection
	// vulnerabilities.
	VerdictUnsafe Verdict = "unsafe"
	// VerdictUnsure means the LLM cannot decide. Engine falls through.
	VerdictUnsure Verdict = "unsure"
)

// Scope describes how broadly an "allow" verdict should be cached.
//
// Some commands (`git status`, `ls`, `cat /etc/hosts`) are safe in
// every context — they get cached globally and a hit from any cwd
// short-circuits the LLM tier. Others (`npm run build`, `make deploy`,
// `./scripts/foo.sh`) execute project-specific code that's safe in
// THIS project but possibly different elsewhere — they get cached
// per-cwd. The classifier returns one of these scopes alongside the
// verdict.
type Scope string

const (
	// ScopeGlobal: the verdict applies to this command anywhere on
	// disk. Cache key omits cwd + git branch.
	ScopeGlobal Scope = "global"
	// ScopeProject: the verdict applies only to the same cwd
	// (project-relative commands like npm/make scripts). Cache key
	// includes cwd hash + git branch.
	ScopeProject Scope = "project"
)

// Decision is the parsed JSON response from the classifier.
type Decision struct {
	Verdict  Verdict `json:"decision"`
	Category string  `json:"category,omitempty"`
	Reason   string  `json:"reason,omitempty"`
	// Scope determines how broadly an allow verdict can be cached.
	// Empty string is treated as ScopeProject (the safer default).
	Scope Scope `json:"scope,omitempty"`
	// VariableSlots is an optional list of "tokens that don't affect
	// the safety verdict" the model identified. The engine uses it to
	// build a canonical form of the command for cache amplification:
	// different concrete commands whose varying tokens are all in the
	// same slot types share one cached verdict.
	//
	// Slot types are a closed vocabulary (see internal/normalize).
	// Unknown types are dropped at engine time. The LLM cannot author
	// regex; it only names slot POSITIONS and TYPES.
	VariableSlots []VariableSlot `json:"variable_slots,omitempty"`
}

// VariableSlot is a single "this token at this position doesn't
// affect the verdict" entry in the classifier response.
type VariableSlot struct {
	Position string `json:"position"` // arg1, arg2, ..., tail_flag
	Type     string `json:"type"`     // one of normalize.SlotType
}

// ClassifyInput is what the engine passes per call.
type ClassifyInput struct {
	Command     string // already redacted by tier 0
	Description string // Claude Code's tool_input.description
	CWD         string
	GitBranch   string
	// ProjectContext is a small pre-built block of project-relevant
	// information (e.g. matching package.json scripts, makefile
	// targets) that helps the LLM reason about what the command will
	// actually do. Already capped in size by internal/projectctx.
	ProjectContext string
}

// Classifier is the provider-agnostic interface. AnthropicClassifier and
// GeminiClassifier both implement it. The engine and tests target this
// interface so providers can be swapped without touching orchestration.
type Classifier interface {
	// Classify sends the input to the underlying LLM and returns the
	// parsed Decision. Inline retries on transient errors are handled
	// internally; cross-invocation breaker recovery is the engine's job.
	Classify(ctx context.Context, in ClassifyInput) (*Decision, error)

	// Provider returns a stable identifier for logs and stats
	// ("anthropic", "gemini").
	Provider() string

	// Model returns the configured model identifier.
	Model() string
}

// AnthropicEnvKeys is the ordered list of environment variables claude-guard
// checks for an Anthropic API key. The first one set wins. The list includes
// project-specific aliases so a user with a key configured for another tool
// (e.g. ai-site-gen's SITEGEN_ANTHROPIC_KEY) doesn't have to duplicate it.
var AnthropicEnvKeys = []string{
	"ANTHROPIC_API_KEY",     // canonical
	"CLAUDE_API_KEY",        // common alias
	"SITEGEN_ANTHROPIC_KEY", // ai-site-gen / Taufinity Studio
}

// GeminiEnvKeys is the ordered list of environment variables claude-guard
// checks for a Gemini / Google AI key.
var GeminiEnvKeys = []string{
	"GEMINI_API_KEY",
	"GOOGLE_AI_API_KEY",
	"GOOGLE_API_KEY",
}

// AutoSelect picks a classifier based on environment variables, in
// priority order:
//
//  1. ANTHROPIC_API_KEY (and aliases in AnthropicEnvKeys) → AnthropicClassifier
//  2. GEMINI_API_KEY (and aliases in GeminiEnvKeys)       → GeminiClassifier
//
// Returns nil when no key is present (LLM tier disabled). The caller
// can pass an explicit preference via the prefer argument: "anthropic"
// or "gemini".
func AutoSelect(prefer string, getenv func(string) string) Classifier {
	if getenv == nil {
		getenv = func(k string) string { return "" }
	}
	tryAnthropic := func() Classifier {
		for _, k := range AnthropicEnvKeys {
			if v := getenv(k); v != "" {
				return NewAnthropic(v, DefaultAnthropicModel)
			}
		}
		// Last resort: try token-vault. Bounded timeout; silent on miss.
		if v := LookupTokenVaultAnthropic(); v != "" {
			return NewAnthropic(v, DefaultAnthropicModel)
		}
		return nil
	}
	tryGemini := func() Classifier {
		for _, k := range GeminiEnvKeys {
			if v := getenv(k); v != "" {
				return NewGemini(v, DefaultGeminiModel)
			}
		}
		return nil
	}

	switch strings.ToLower(prefer) {
	case "gemini":
		if c := tryGemini(); c != nil {
			return c
		}
		return tryAnthropic()
	case "anthropic", "":
		if c := tryAnthropic(); c != nil {
			return c
		}
		return tryGemini()
	default:
		// Unknown preference — fall back to default order.
		if c := tryAnthropic(); c != nil {
			return c
		}
		return tryGemini()
	}
}

// --- shared helpers ---

// shouldRetry inspects an error and reports whether to retry inline,
// and how long to wait. Used by both providers.
func shouldRetry(err error) (retry bool, wait time.Duration) {
	switch e := err.(type) {
	case *breaker.ServerError:
		// 5xx → 1 retry after 200ms
		return true, 200 * time.Millisecond
	case *breaker.RateLimitError:
		// 429 → only retry if retry-after is < 500ms away
		now := time.Now()
		if e.RetryAfter.IsZero() {
			return false, 0
		}
		delay := e.RetryAfter.Sub(now)
		if delay < 500*time.Millisecond {
			if delay < 0 {
				delay = 0
			}
			return true, delay
		}
		return false, 0
	default:
		return false, 0
	}
}

// buildUserMessage assembles the user-turn content with the command
// and contextual hints. Both providers reuse this.
func buildUserMessage(in ClassifyInput) string {
	var b strings.Builder
	b.WriteString("Classify this Bash command:\n\n")
	b.WriteString("COMMAND:\n")
	b.WriteString(in.Command)
	b.WriteString("\n\n")
	if in.Description != "" {
		b.WriteString("INTENT (from the AI assistant calling the tool):\n")
		b.WriteString(in.Description)
		b.WriteString("\n\n")
	}
	if in.CWD != "" {
		b.WriteString("CWD: ")
		b.WriteString(in.CWD)
		b.WriteString("\n")
	}
	if in.GitBranch != "" {
		b.WriteString("GIT_BRANCH: ")
		b.WriteString(in.GitBranch)
		b.WriteString("\n")
	}
	if in.ProjectContext != "" {
		b.WriteString("\nPROJECT CONTEXT (for commands that execute project-defined scripts):\n")
		b.WriteString(in.ProjectContext)
		b.WriteString("\n")
	}
	b.WriteString("\nReturn JSON only with these fields:\n")
	b.WriteString(`  decision: "safe" | "unsafe" | "unsure"
  category: short tag (read_only_query | file_read | file_write_scoped | external_write | destructive | exfil | unknown)
  scope:    "global" | "project"
            "global"  → safe in every cwd (e.g. ls, cat, git status)
            "project" → safe only in this specific project (e.g. npm run build, make test, ./scripts/foo.sh)
            When in doubt, prefer "project" — it's the safer default.
  reason:   1-2 sentence plain-English explanation
  variable_slots: OPTIONAL list. Each entry names a token in the command that does NOT affect
            the safety verdict. Used to amplify the cache so similar commands share one entry.
            { "position": "arg1" | "arg2" | ... | "tail_flag", "type": "<slot type>" }
            Allowed slot types (closed vocabulary — anything else is dropped):
              domain, ipv4, url_path_segment, uuid, integer, hex_hash,
              filepath_tmp, filepath_cache, quoted_string, dns_record_type, http_method
            Example for 'dig example.com A':
              [{"position":"arg1","type":"domain"}, {"position":"arg2","type":"dns_record_type"}]
            Do not include slots for tokens whose value DOES affect safety (e.g. don't mark
            a filepath as variable unless it's under /tmp or ~/.cache).
            When in doubt, omit variable_slots.`)
	return b.String()
}

// ParseError is returned by extractDecision when the model's response
// cannot be interpreted as a valid classifier Decision. It carries the
// raw response (truncated to a readable cap) plus diagnostic fields so
// the engine can log structured data for debugging truncation vs
// corruption vs schema violations.
type ParseError struct {
	// RawResponse is the model's text output, clipped to parseErrorRawCap.
	RawResponse string
	// RawLength is the original length before clipping — a value near
	// the provider's max_tokens strongly suggests MAX_TOKENS truncation.
	RawLength int
	// LooksTruncated is true when the response doesn't end with `}`
	// (or a markdown fence) — a reliable heuristic for mid-JSON cutoff.
	LooksTruncated bool
}

// parseErrorRawCap bounds how much of the bad response we embed in the
// error message. Large enough to show WHERE the model cut off, small
// enough to keep app.jsonl lines readable.
const parseErrorRawCap = 1500

func (e *ParseError) Error() string {
	hint := ""
	if e.LooksTruncated {
		hint = " [truncated mid-response]"
	}
	return fmt.Sprintf("classifier output not JSON (len=%d%s): %q",
		e.RawLength, hint, truncate(e.RawResponse, parseErrorRawCap))
}

// extractDecision parses the model's text output into a Decision.
// Handles raw JSON, JSON wrapped in markdown fences, and JSON embedded
// in prose.
func extractDecision(text string) (*Decision, error) {
	if dec, ok := tryParseJSON(text); ok {
		return dec, nil
	}
	if start := strings.Index(text, "{"); start >= 0 {
		end := strings.LastIndex(text, "}")
		if end > start {
			if dec, ok := tryParseJSON(text[start : end+1]); ok {
				return dec, nil
			}
		}
	}
	return nil, &ParseError{
		RawResponse:    text,
		RawLength:      len(text),
		LooksTruncated: looksTruncated(text),
	}
}

// looksTruncated returns true when the response STARTED valid JSON (or
// a fenced JSON block) but never reached a closing brace. Almost every
// MAX_TOKENS cutoff we've seen in app.jsonl stops mid-value, so this
// pattern reliably distinguishes truncation from "model returned prose
// instead of JSON" — which has its own failure signature (no `{` at all).
func looksTruncated(text string) bool {
	s := strings.TrimSpace(text)
	if s == "" {
		return false
	}
	// Strip a leading markdown fence ("```json\n" or "```\n") if present.
	if strings.HasPrefix(s, "```") {
		if nl := strings.IndexByte(s, '\n'); nl > 0 {
			s = strings.TrimSpace(s[nl+1:])
		}
	}
	if !strings.HasPrefix(s, "{") {
		return false // never started JSON — a different failure mode
	}
	last := s[len(s)-1]
	return last != '}' && last != '`'
}

func tryParseJSON(s string) (*Decision, bool) {
	var d Decision
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &d); err != nil {
		return nil, false
	}
	if d.Verdict != VerdictSafe && d.Verdict != VerdictUnsafe && d.Verdict != VerdictUnsure {
		return nil, false
	}
	return &d, true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
