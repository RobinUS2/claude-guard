package stop

import "testing"

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
	if len(rules) != 5 {
		t.Errorf("expected 5 default rules, got %d", len(rules))
	}
}
