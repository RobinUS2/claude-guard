package stop

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// uncommittedChangesRule fires when Claude stops but git status shows
// staged or unstaged changes. No text pre-filter — always checks git
// status (~5ms) because Claude often stops without explicit completion
// words, especially when the last turn ends with a tool_use block.
type uncommittedChangesRule struct{}

func (r *uncommittedChangesRule) Name() string          { return "uncommitted-changes" }
func (r *uncommittedChangesRule) HighConfidence() bool  { return true }
func (r *uncommittedChangesRule) TextPreFilter() string { return "" }

func (r *uncommittedChangesRule) Eval(_ Transcript, sh ShellContext) (bool, string) {
	out, err := sh.Run("git status --short")
	if err != nil || strings.TrimSpace(out) == "" {
		return false, ""
	}
	return true, fmt.Sprintf(
		"There are uncommitted or staged changes:\n%s\nPlease commit, stash, or explain before finishing.",
		strings.TrimSpace(out),
	)
}

// proposedTestNotRunRule fires when the last assistant message mentions a test
// command but no matching Bash call occurred in the session.
type proposedTestNotRunRule struct{}

func (r *proposedTestNotRunRule) Name() string         { return "proposed-test-not-run" }
func (r *proposedTestNotRunRule) HighConfidence() bool { return false }
func (r *proposedTestNotRunRule) TextPreFilter() string {
	return `\b(go test|npm test|make test|pytest|cargo test)\b`
}

func (r *proposedTestNotRunRule) Eval(t Transcript, _ ShellContext) (bool, string) {
	testPatterns := []string{"go test", "npm test", "make test", "pytest", "cargo test"}
	for _, bash := range t.BashCalls {
		for _, pat := range testPatterns {
			if strings.Contains(bash, pat) {
				return false, ""
			}
		}
	}
	return true, "You mentioned a test command but I don't see it in the session's tool calls. Run the tests to verify, or confirm they were run in a prior session."
}

// installNotRunRule fires when the user asked for "install" but make install
// never ran in the session.
type installNotRunRule struct{}

func (r *installNotRunRule) Name() string         { return "install-not-run" }
func (r *installNotRunRule) HighConfidence() bool { return false }
func (r *installNotRunRule) TextPreFilter() string {
	return `\b(make install|install)\b`
}

func (r *installNotRunRule) Eval(t Transcript, _ ShellContext) (bool, string) {
	if !strings.Contains(strings.ToLower(t.FirstUserText), "install") {
		return false, ""
	}
	for _, bash := range t.BashCalls {
		if strings.Contains(bash, "make install") {
			return false, ""
		}
	}
	return true, "The task asked for 'install' but make install hasn't run yet. Run `make install` to complete the deployment."
}

// openTodoItemsRule fires when the last TodoWrite call in the session has
// items still pending or in_progress.
type openTodoItemsRule struct{}

func (r *openTodoItemsRule) Name() string          { return "open-todo-items" }
func (r *openTodoItemsRule) HighConfidence() bool  { return true }
func (r *openTodoItemsRule) TextPreFilter() string { return "" }

func (r *openTodoItemsRule) Eval(t Transcript, _ ShellContext) (bool, string) {
	if !t.HasTodoWrite {
		return false, ""
	}
	var pending []string
	for _, item := range t.LastTodoItems {
		if item.Status == "pending" || item.Status == "in_progress" {
			pending = append(pending, "- ["+item.Status+"] "+item.Content)
		}
	}
	if len(pending) == 0 {
		return false, ""
	}
	return true, fmt.Sprintf(
		"There are still unchecked items in the todo list:\n%s\nContinue until all tasks are completed, or explicitly say which to defer.",
		strings.Join(pending, "\n"),
	)
}

// prCreatedNotVerifiedRule fires when a PR was created in the session but
// CI status was never checked.
type prCreatedNotVerifiedRule struct{}

func (r *prCreatedNotVerifiedRule) Name() string          { return "pr-created-not-verified" }
func (r *prCreatedNotVerifiedRule) HighConfidence() bool  { return false }
func (r *prCreatedNotVerifiedRule) TextPreFilter() string { return "" }

func (r *prCreatedNotVerifiedRule) Eval(t Transcript, _ ShellContext) (bool, string) {
	prCreated := false
	for _, bash := range t.BashCalls {
		if strings.Contains(bash, "gh pr create") {
			prCreated = true
		}
	}
	if !prCreated {
		return false, ""
	}
	for _, bash := range t.BashCalls {
		if strings.Contains(bash, "gh pr checks") ||
			strings.Contains(bash, "gh pr view") ||
			strings.Contains(bash, "gh pr status") {
			return false, ""
		}
	}
	return true, "A PR was created but CI status wasn't checked. Run `gh pr checks <num>` to verify, or note the PR number for manual follow-up."
}

// committedNotPushedRule fires when there are local commits not pushed
// to the remote tracking branch.
type committedNotPushedRule struct{}

func (r *committedNotPushedRule) Name() string          { return "committed-not-pushed" }
func (r *committedNotPushedRule) HighConfidence() bool  { return true }
func (r *committedNotPushedRule) TextPreFilter() string { return "" }

func (r *committedNotPushedRule) Eval(_ Transcript, sh ShellContext) (bool, string) {
	out, err := sh.Run("git log --oneline @{u}..HEAD 2>/dev/null")
	if err != nil || strings.TrimSpace(out) == "" {
		return false, ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return true, fmt.Sprintf(
		"There are %d unpushed commit(s):\n%s\nPush to remote, or confirm you intend to keep these local.",
		len(lines), strings.TrimSpace(out),
	)
}

// failingTestsRule fires when a test command was run in the session
// and the last assistant text mentions failures or errors.
type failingTestsRule struct{}

func (r *failingTestsRule) Name() string         { return "failing-tests" }
func (r *failingTestsRule) HighConfidence() bool { return false }
func (r *failingTestsRule) TextPreFilter() string {
	return `(?i)\b(FAIL|FAILED|ERROR|panic|test.*fail)`
}

func (r *failingTestsRule) Eval(t Transcript, _ ShellContext) (bool, string) {
	// Only fire if tests were actually run in this session.
	testPatterns := []string{"go test", "npm test", "make test", "pytest", "cargo test", "jest", "vitest"}
	ran := false
	for _, bash := range t.BashCalls {
		for _, pat := range testPatterns {
			if strings.Contains(bash, pat) {
				ran = true
				break
			}
		}
		if ran {
			break
		}
	}
	if !ran {
		return false, ""
	}
	return true, "Tests appear to have failures. Review the output and fix before finishing, or confirm the failures are expected."
}

// featureBranchLeftRule fires when Claude stops on a feature branch
// (not main/master) — a reminder to merge, PR, or note the branch.
type featureBranchLeftRule struct{}

func (r *featureBranchLeftRule) Name() string          { return "feature-branch-left" }
func (r *featureBranchLeftRule) HighConfidence() bool  { return false }
func (r *featureBranchLeftRule) TextPreFilter() string { return "" }

func (r *featureBranchLeftRule) Eval(_ Transcript, sh ShellContext) (bool, string) {
	branch, err := sh.Run("git branch --show-current 2>/dev/null")
	if err != nil {
		return false, ""
	}
	branch = strings.TrimSpace(branch)
	if branch == "" || branch == "main" || branch == "master" || branch == "develop" {
		return false, ""
	}
	return true, fmt.Sprintf(
		"Still on branch '%s'. Merge to main, create a PR, or note the branch name before finishing.",
		branch,
	)
}

// worktreeLeftOpenRule fires when there are active git worktrees
// under .claude/worktrees/.
type worktreeLeftOpenRule struct{}

func (r *worktreeLeftOpenRule) Name() string          { return "worktree-left-open" }
func (r *worktreeLeftOpenRule) HighConfidence() bool  { return false }
func (r *worktreeLeftOpenRule) TextPreFilter() string { return "" }

func (r *worktreeLeftOpenRule) Eval(_ Transcript, sh ShellContext) (bool, string) {
	out, err := sh.Run("git worktree list --porcelain 2>/dev/null")
	if err != nil {
		return false, ""
	}
	// Count worktrees — first one is always the main worktree.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	worktrees := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "worktree ") {
			worktrees++
		}
	}
	if worktrees <= 1 {
		return false, "" // only the main worktree
	}
	return true, fmt.Sprintf(
		"There are %d git worktrees active (including main). Clean up finished worktrees, or note them for follow-up.",
		worktrees,
	)
}

// stopPhraseGuardRule catches premature stopping phrases across multiple
// categories. Based on anthropics/claude-code#42796.
type stopPhraseGuardRule struct{}

func (r *stopPhraseGuardRule) Name() string          { return "stop-phrase-guard" }
func (r *stopPhraseGuardRule) HighConfidence() bool  { return false }
func (r *stopPhraseGuardRule) TextPreFilter() string { return "" } // check all text

// stopPhraseCategories maps category labels to their pattern strings.
var stopPhraseCategories = []struct {
	name     string
	patterns []string
}{
	{"ownership dodging", []string{
		`not caused by my changes`,
		`existing issue`,
		`pre-existing`,
		`was already broken`,
	}},
	{"permission-seeking", []string{
		`should I continue`,
		`want me to keep going`,
		`would you like me to`,
		`shall I proceed`,
		`do you want me to`,
	}},
	{"premature stopping", []string{
		`good stopping point`,
		`natural checkpoint`,
		`leaving off here`,
		`pick this up later`,
		`continue in a new session`,
		`getting long`,
		`good place to pause`,
	}},
	{"known-limitation labeling", []string{
		`known limitation`,
		`future work`,
		`out of scope for now`,
		`beyond the scope`,
		`left as an exercise`,
	}},
	{"session-length excuses", []string{
		`continue in a new session`,
		`context is getting long`,
		`running out of context`,
		`pick up later`,
	}},
}

// stopPhraseCategoryRegexes holds compiled regexes per category, built once.
var stopPhraseCategoryRegexes []struct {
	name string
	re   *regexp.Regexp
}

func init() {
	for _, cat := range stopPhraseCategories {
		combined := `(?i)(?:` + strings.Join(cat.patterns, `|`) + `)`
		stopPhraseCategoryRegexes = append(stopPhraseCategoryRegexes, struct {
			name string
			re   *regexp.Regexp
		}{cat.name, regexp.MustCompile(combined)})
	}
}

func (r *stopPhraseGuardRule) Eval(t Transcript, _ ShellContext) (bool, string) {
	for _, cat := range stopPhraseCategoryRegexes {
		if cat.re.MatchString(t.LastAssistantText) {
			return true, fmt.Sprintf(
				"Premature stop detected: %s. Continue with the task — don't stop at checkpoints.",
				cat.name,
			)
		}
	}
	return false, ""
}

// noAskHumanRule catches "Should I...?" patterns in autonomous sessions.
type noAskHumanRule struct{}

func (r *noAskHumanRule) Name() string          { return "no-ask-human" }
func (r *noAskHumanRule) HighConfidence() bool  { return false }
func (r *noAskHumanRule) TextPreFilter() string { return `(?i)\b(should I|do you want|would you like|shall I)\b` }

func (r *noAskHumanRule) Eval(_ Transcript, _ ShellContext) (bool, string) {
	v := os.Getenv("CLAUDE_GUARD_AUTONOMOUS")
	if v != "1" && v != "true" {
		return false, ""
	}
	return true, "You're in autonomous mode — decide and act. Don't ask for permission."
}

// DefaultRules returns the built-in rule set in evaluation order.
// Transcript-only rules (no shell cost) run first, then shell-based.
func DefaultRules() []StopRule {
	return []StopRule{
		// Transcript-only (no shell cost).
		&openTodoItemsRule{},
		&prCreatedNotVerifiedRule{},
		&failingTestsRule{},
		&stopPhraseGuardRule{},
		&noAskHumanRule{},
		&installNotRunRule{},
		&proposedTestNotRunRule{},
		// Shell-based (~5ms each).
		&uncommittedChangesRule{},
		&committedNotPushedRule{},
		&featureBranchLeftRule{},
		&worktreeLeftOpenRule{},
	}
}
