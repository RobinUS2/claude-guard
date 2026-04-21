package stop

import (
	"os"
	"testing"
)

type stubShell map[string]string

func (s stubShell) Run(cmd string) (string, error) { return s[cmd], nil }

func TestRuleUncommittedChanges_Fires(t *testing.T) {
	rule := &uncommittedChangesRule{}
	sh := stubShell{"git status --short": " M internal/foo.go\n"}
	tr := Transcript{LastAssistantText: "All done, pushed everything."}
	ok, reason := rule.Eval(tr, sh)
	if !ok {
		t.Error("expected rule to fire on non-empty git status")
	}
	if reason == "" {
		t.Error("reason should not be empty")
	}
}

func TestRuleUncommittedChanges_NoFire(t *testing.T) {
	rule := &uncommittedChangesRule{}
	sh := stubShell{"git status --short": ""}
	ok, _ := rule.Eval(Transcript{}, sh)
	if ok {
		t.Error("should not fire on clean git status")
	}
}

func TestRuleOpenTodoItems_Fires(t *testing.T) {
	rule := &openTodoItemsRule{}
	tr := Transcript{
		HasTodoWrite: true,
		LastTodoItems: []TodoItem{
			{Content: "step 1", Status: "completed"},
			{Content: "step 2", Status: "pending"},
		},
	}
	ok, reason := rule.Eval(tr, stubShell{})
	if !ok {
		t.Error("expected rule to fire with pending items")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestRuleOpenTodoItems_NoFire(t *testing.T) {
	rule := &openTodoItemsRule{}
	tr := Transcript{
		HasTodoWrite: true,
		LastTodoItems: []TodoItem{
			{Content: "step 1", Status: "completed"},
		},
	}
	ok, _ := rule.Eval(tr, stubShell{})
	if ok {
		t.Error("should not fire when all items complete")
	}
}

func TestRuleOpenTodoItems_NoTodoWrite(t *testing.T) {
	rule := &openTodoItemsRule{}
	ok, _ := rule.Eval(Transcript{HasTodoWrite: false}, stubShell{})
	if ok {
		t.Error("should not fire when no TodoWrite in session")
	}
}

func TestRuleInstallNotRun_Fires(t *testing.T) {
	rule := &installNotRunRule{}
	tr := Transcript{
		FirstUserText:     "commit, push, install",
		LastAssistantText: "Done, all pushed.",
		BashCalls:         []string{"git push"},
	}
	ok, reason := rule.Eval(tr, stubShell{})
	if !ok {
		t.Error("expected rule to fire when install asked but not run")
	}
	_ = reason
}

func TestRuleInstallNotRun_NoFireWhenRun(t *testing.T) {
	rule := &installNotRunRule{}
	tr := Transcript{
		FirstUserText: "commit, push, install",
		BashCalls:     []string{"git push", "make install"},
	}
	ok, _ := rule.Eval(tr, stubShell{})
	if ok {
		t.Error("should not fire when make install was run")
	}
}

func TestRuleInstallNotRun_NoFireWhenUserDidNotAsk(t *testing.T) {
	rule := &installNotRunRule{}
	tr := Transcript{
		FirstUserText:     "push the PR",
		LastAssistantText: "Done, install instructions in README.",
	}
	ok, _ := rule.Eval(tr, stubShell{})
	if ok {
		t.Error("should not fire when user did not ask for install")
	}
}

func TestRulePRCreatedNotVerified_Fires(t *testing.T) {
	rule := &prCreatedNotVerifiedRule{}
	tr := Transcript{BashCalls: []string{"gh pr create --title foo"}}
	ok, _ := rule.Eval(tr, stubShell{})
	if !ok {
		t.Error("expected rule to fire when PR created but not checked")
	}
}

func TestRulePRCreatedNotVerified_NoFire(t *testing.T) {
	rule := &prCreatedNotVerifiedRule{}
	tr := Transcript{BashCalls: []string{"gh pr create --title foo", "gh pr checks 42"}}
	ok, _ := rule.Eval(tr, stubShell{})
	if ok {
		t.Error("should not fire when CI was checked")
	}
}

func TestDefaultRules_Length(t *testing.T) {
	rules := DefaultRules()
	if len(rules) != 12 {
		t.Errorf("expected 12 default rules, got %d", len(rules))
	}
}

func TestStopPhraseGuard_Fires(t *testing.T) {
	rule := &stopPhraseGuardRule{}
	cases := []struct {
		text     string
		category string
	}{
		{"This is not caused by my changes, it was there before.", "ownership dodging"},
		{"Should I continue with the next step?", "permission-seeking"},
		{"This is a good stopping point for now.", "premature stopping"},
		{"That's a known limitation of the library.", "known-limitation labeling"},
		{"I think I'm running out of context window space.", "session-length excuses"},
	}
	for _, tc := range cases {
		tr := Transcript{LastAssistantText: tc.text}
		ok, reason := rule.Eval(tr, stubShell{})
		if !ok {
			t.Errorf("expected rule to fire for category %q with text %q", tc.category, tc.text)
			continue
		}
		if reason == "" {
			t.Errorf("expected non-empty reason for category %q", tc.category)
		}
		if !contains(reason, tc.category) {
			t.Errorf("reason %q should mention category %q", reason, tc.category)
		}
	}
}

func TestStopPhraseGuard_NoMatch(t *testing.T) {
	rule := &stopPhraseGuardRule{}
	texts := []string{
		"I've committed the changes and pushed to main.",
		"All tests pass. The implementation is complete.",
		"Here's a summary of what was done in this session.",
		"The function returns an error if the input is invalid.",
	}
	for _, text := range texts {
		tr := Transcript{LastAssistantText: text}
		ok, _ := rule.Eval(tr, stubShell{})
		if ok {
			t.Errorf("rule should NOT fire for normal text %q", text)
		}
	}
}

func TestNoAskHuman_AutonomousMode(t *testing.T) {
	os.Setenv("CLAUDE_GUARD_AUTONOMOUS", "1")
	t.Cleanup(func() { os.Unsetenv("CLAUDE_GUARD_AUTONOMOUS") })

	rule := &noAskHumanRule{}
	tr := Transcript{LastAssistantText: "Should I continue with the refactor?"}
	ok, reason := rule.Eval(tr, stubShell{})
	if !ok {
		t.Error("expected rule to fire in autonomous mode")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestNoAskHuman_AutonomousTrue(t *testing.T) {
	os.Setenv("CLAUDE_GUARD_AUTONOMOUS", "true")
	t.Cleanup(func() { os.Unsetenv("CLAUDE_GUARD_AUTONOMOUS") })

	rule := &noAskHumanRule{}
	tr := Transcript{LastAssistantText: "Would you like me to proceed?"}
	ok, _ := rule.Eval(tr, stubShell{})
	if !ok {
		t.Error("expected rule to fire with CLAUDE_GUARD_AUTONOMOUS=true")
	}
}

func TestNoAskHuman_NormalMode(t *testing.T) {
	os.Unsetenv("CLAUDE_GUARD_AUTONOMOUS")

	rule := &noAskHumanRule{}
	tr := Transcript{LastAssistantText: "Should I continue with the refactor?"}
	ok, _ := rule.Eval(tr, stubShell{})
	if ok {
		t.Error("rule should NOT fire without CLAUDE_GUARD_AUTONOMOUS env var")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
