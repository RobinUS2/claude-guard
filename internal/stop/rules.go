package stop

import (
	"fmt"
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

// DefaultRules returns the built-in rule set in evaluation order.
// Transcript-only rules (no shell cost) run first.
func DefaultRules() []StopRule {
	return []StopRule{
		&openTodoItemsRule{},        // transcript-only, no shell cost
		&prCreatedNotVerifiedRule{}, // transcript-only
		&uncommittedChangesRule{},   // text pre-filter + git status
		&installNotRunRule{},        // text pre-filter + transcript check
		&proposedTestNotRunRule{},   // text pre-filter + transcript check
	}
}
