package stop

import (
	"regexp"
	"time"
)

// Transcript is the parsed content of a Stop hook session.
type Transcript struct {
	LastAssistantText string // joined text blocks of last assistant message
	FirstUserText     string // first user message content
	BashCalls         []string
	HasTodoWrite      bool
	LastTodoItems     []TodoItem
}

// TodoItem represents a single todo entry.
// JSON tags must match Claude Code's TodoWrite input schema.
type TodoItem struct {
	Content string `json:"content"`
	Status  string `json:"status"` // "pending", "in_progress", "completed"
}

// StopRule evaluates whether the session is truly complete.
type StopRule interface {
	Name() string
	// HighConfidence rules may fire even when stop_hook_active is true.
	// Only rules with shell-verified evidence should return true.
	HighConfidence() bool
	// TextPreFilter is a regex applied to LastAssistantText before Eval.
	// Return "" to skip text pre-filtering (use for transcript-only checks).
	// Shell checks never run unless this matches — key performance gate.
	TextPreFilter() string
	// Eval is called only when TextPreFilter matched (or was "").
	Eval(t Transcript, sh ShellContext) (shouldContinue bool, reason string)
}

// Evaluate runs all rules against the transcript and returns the first
// continue-message that fires, or "" if Claude should stop.
// sessionDir is used for the per-session state file (usually os.TempDir()).
func Evaluate(sessionID, sessionDir string, stopHookActive bool, t Transcript, rules []StopRule, shellTimeout time.Duration) string {
	sess := newSession(sessionID, sessionDir)
	sh := newShellContext(shellTimeout)

	for _, rule := range rules {
		// When stop_hook_active, only high-confidence rules may fire.
		if stopHookActive && !rule.HighConfidence() {
			continue
		}

		// Text pre-filter gate — must match before any shell check runs.
		if pf := rule.TextPreFilter(); pf != "" {
			re, err := regexp.Compile(`(?i)` + pf)
			if err != nil || !re.MatchString(t.LastAssistantText) {
				continue
			}
		}

		// Cool-down: if rule already fired this session with the same shell
		// state, skip it.
		if sess.hasFired(rule.Name()) {
			continue
		}

		ok, reason := rule.Eval(t, sh)
		if !ok {
			continue
		}

		// Check continue cap before injecting.
		_, withinCap := sess.increment()
		if !withinCap {
			return "" // hard cap reached, let Claude stop
		}

		sess.markFired(rule.Name(), shellHash(reason))
		return reason
	}
	return ""
}
