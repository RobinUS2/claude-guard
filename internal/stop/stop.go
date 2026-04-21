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
	TurnCount         int // total number of turns in the transcript
	TranscriptBytes   int // approximate raw size of the transcript JSON
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
	// MaxContinues returns the per-rule continue cap. 0 means use the
	// global session cap (default 3). Rules like feature-branch-left
	// should fire at most once; uncommitted-changes can fire all 3 times.
	MaxContinues() int
	// TextPreFilter is a regex applied to LastAssistantText before Eval.
	// Return "" to skip text pre-filtering (use for transcript-only checks).
	// Shell checks never run unless this matches — key performance gate.
	TextPreFilter() string
	// Eval is called only when TextPreFilter matched (or was "").
	Eval(t Transcript, sh ShellContext) (shouldContinue bool, reason string)
}

// Result describes the outcome of a stop evaluation. Message is the
// user-visible continue string ("" = let Claude stop). The remaining
// fields are for logging / explainability.
type Result struct {
	Message       string // continue message, "" if no rule fired or cap reached
	Rule          string // name of the rule that fired, "" otherwise
	CapReached    bool   // true when a rule would have fired but the session cap was hit
	RulesSeen     int    // how many rules were evaluated (not skipped by gates)
	ContinueCount int    // total continues this session after this evaluation
}

// Evaluate runs all rules against the transcript and returns the first
// continue-message that fires, or "" if Claude should stop.
// sessionDir is used for the per-session state file (usually os.TempDir()).
func Evaluate(sessionID, sessionDir string, stopHookActive bool, t Transcript, rules []StopRule, shellTimeout time.Duration) string {
	return EvaluateResult(sessionID, sessionDir, stopHookActive, t, rules, shellTimeout).Message
}

// EvaluateResult is the full-information variant of Evaluate. Callers
// that log the decision should use this and propagate Result fields.
func EvaluateResult(sessionID, sessionDir string, stopHookActive bool, t Transcript, rules []StopRule, shellTimeout time.Duration) Result {
	sess := newSession(sessionID, sessionDir)
	sh := newShellContext(shellTimeout)

	res := Result{}

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

		// Per-rule continue cap: if the rule has a MaxContinues() > 0 and
		// has already fired that many times, skip it.
		if mc := rule.MaxContinues(); mc > 0 && sess.ruleFireCount(rule.Name()) >= mc {
			continue
		}

		res.RulesSeen++

		ok, reason := rule.Eval(t, sh)
		if !ok {
			continue
		}

		// Check continue cap before injecting.
		count, withinCap := sess.increment()
		res.ContinueCount = count
		if !withinCap {
			res.CapReached = true
			res.Rule = rule.Name()
			return res // hard cap reached, let Claude stop
		}

		sess.markFired(rule.Name(), shellHash(reason))
		res.Rule = rule.Name()
		res.Message = reason
		return res
	}
	// No rule fired — report the current continue count so logging
	// reflects session state even for "stop allowed" events.
	res.ContinueCount = sess.load().Continues
	return res
}
