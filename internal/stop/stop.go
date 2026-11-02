package stop

import (
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"regexp"
	"strings"
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

	BackgroundTasks int  // still-running background tasks, shells and subagents
	SessionCrons    int  // scheduled wake-ups for this session
	RunningKnown    bool // true only when the input carried background_tasks or session_crons

	// TranscriptBlind is true when neither an inline transcript nor a
	// readable transcript file supplied BashCalls, todo items and TurnCount.
	// Rules in transcriptRules are then skipped rather than evaluated on
	// empty data.
	TranscriptBlind bool
}

// transcriptRules lists the rules that read BashCalls, todo items, the first
// user message or the turn count. They cannot be judged without a transcript.
var transcriptRules = map[string]bool{
	"open-todo-items":         true,
	"pr-created-not-verified": true,
	"failing-tests":           true,
	"context-monitor":         true,
	"install-not-run":         true,
	"proposed-test-not-run":   true,
	"completion-quality":      true,
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
	Message       string   // continue message, "" if no rule fired or cap reached
	Rule          string   // name of the rule that fired, "" otherwise
	CapReached    bool     // true when a rule would have fired but the session cap was hit
	WouldBlock    []string // log-mode rules that matched; they did not block
	Blind         []string // transcript rules skipped because no transcript data was available
	RulesSeen     int      // how many rules were evaluated (not skipped by gates)
	ContinueCount int      // total continues this session after this evaluation
}

// Evaluate runs all rules against the transcript and returns the first
// continue-message that fires, or "" if Claude should stop.
// sessionDir is used for the per-session state file (usually os.TempDir()).
func Evaluate(sessionID, sessionDir string, stopHookActive bool, t Transcript, rules []StopRule, shellTimeout time.Duration) string {
	return EvaluateResult(sessionID, sessionDir, stopHookActive, t, rules, shellTimeout).Message
}

// Rule modes. An enforced rule sends the session back to work; a log-mode
// rule only reports that it would have, and lets the session stop.
const (
	ModeEnforce = "enforce"
	ModeLog     = "log"
)

// DefaultMode is the built-in mode for a rule: log for everything except
// waiting-nothing-running.
func DefaultMode(rule string) string {
	if rule == "waiting-nothing-running" {
		return ModeEnforce
	}
	return ModeLog
}

// RuleMode resolves the mode of a rule from the config overrides, falling
// back to DefaultMode. Unknown override values are ignored.
func RuleMode(rule string, overrides map[string]string) string {
	if m := strings.ToLower(strings.TrimSpace(overrides[rule])); m == ModeEnforce || m == ModeLog {
		return m
	}
	return DefaultMode(rule)
}

// EvaluateResult runs every rule in enforce mode. It is the full-information
// variant of Evaluate; hook code that honours the per-rule switch uses
// EvaluateModes.
func EvaluateResult(sessionID, sessionDir string, stopHookActive bool, t Transcript, rules []StopRule, shellTimeout time.Duration) Result {
	return evaluate(sessionID, sessionDir, stopHookActive, t, rules, shellTimeout, func(string) string { return ModeEnforce })
}

// EvaluateModes is EvaluateResult with per-rule modes from the config
// overrides (see RuleMode). Log-mode rules that match are listed in
// Result.WouldBlock and never block or consume the session continue cap.
func EvaluateModes(sessionID, sessionDir string, stopHookActive bool, t Transcript, rules []StopRule, shellTimeout time.Duration, modes map[string]string) Result {
	return evaluate(sessionID, sessionDir, stopHookActive, t, rules, shellTimeout, func(name string) string { return RuleMode(name, modes) })
}

func evaluate(sessionID, sessionDir string, stopHookActive bool, t Transcript, rules []StopRule, shellTimeout time.Duration, modeOf func(string) string) Result {
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

		// Transcript rules cannot be judged without transcript data: skip
		// them and report them as blind.
		if t.TranscriptBlind && transcriptRules[rule.Name()] {
			res.Blind = append(res.Blind, rule.Name())
			continue
		}

		res.RulesSeen++

		ok, reason := rule.Eval(t, sh)
		if !ok {
			continue
		}

		// Log mode: record the match, never block, keep evaluating so every
		// rule gets its numbers.
		if modeOf(rule.Name()) == ModeLog {
			res.WouldBlock = append(res.WouldBlock, rule.Name())
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

// RecordWouldBlock writes one "would block" record (rule, session id, time)
// to the decision log for every log-mode rule that matched, and one "blind"
// record for every rule skipped for lack of transcript data.
func RecordWouldBlock(dlog *clog.DecisionLogger, sessionID string, res Result) {
	for _, name := range res.WouldBlock {
		dlog.StopWouldBlock(clog.StopWouldBlockRecord{SessionID: sessionID, Rule: name})
	}
	for _, name := range res.Blind {
		dlog.StopBlind(clog.StopWouldBlockRecord{SessionID: sessionID, Rule: name})
	}
}
