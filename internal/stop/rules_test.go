package stop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if len(rules) != 14 {
		t.Errorf("expected 14 default rules, got %d", len(rules))
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

func TestStopWaiting(t *testing.T) {
	waiting := "PR is open. Waiting for CI to finish, I'll check back."
	eval := func(dir string, tr Transcript) string {
		return Evaluate("waiting-sess", dir, false, tr, []StopRule{&waitingNothingRunningRule{}}, 0)
	}
	t.Run("waiting_nothing_running_blocks", func(t *testing.T) {
		msg := eval(t.TempDir(), Transcript{LastAssistantText: waiting, RunningKnown: true})
		if msg == "" {
			t.Error("expected rule to fire")
		}
	})
	t.Run("waiting_with_background_task_passes", func(t *testing.T) {
		if eval(t.TempDir(), Transcript{LastAssistantText: waiting, RunningKnown: true, BackgroundTasks: 1}) != "" {
			t.Error("should not fire with a background task")
		}
	})
	t.Run("waiting_with_cron_passes", func(t *testing.T) {
		if eval(t.TempDir(), Transcript{LastAssistantText: waiting, RunningKnown: true, SessionCrons: 1}) != "" {
			t.Error("should not fire with a cron")
		}
	})
	t.Run("not_waiting_passes", func(t *testing.T) {
		if eval(t.TempDir(), Transcript{LastAssistantText: "All done, merged.", RunningKnown: true}) != "" {
			t.Error("should not fire when not waiting")
		}
	})
	t.Run("dutch_blocks", func(t *testing.T) {
		if eval(t.TempDir(), Transcript{LastAssistantText: "Ik wacht op de build.", RunningKnown: true}) == "" {
			t.Error("expected Dutch phrasing to fire")
		}
	})
	t.Run("unknown_running_passes", func(t *testing.T) {
		if eval(t.TempDir(), Transcript{LastAssistantText: waiting}) != "" {
			t.Error("should not fire when running state is unknown")
		}
	})
	t.Run("second_stop_passes", func(t *testing.T) {
		dir := t.TempDir()
		tr := Transcript{LastAssistantText: waiting, RunningKnown: true}
		if eval(dir, tr) == "" {
			t.Fatal("first stop should block")
		}
		if eval(dir, tr) != "" {
			t.Error("second stop should pass")
		}
	})
}

func TestStopWaitingPhrases(t *testing.T) {
	fires := func(text string) bool {
		ok, _ := (&waitingNothingRunningRule{}).Eval(Transcript{LastAssistantText: text, RunningKnown: true}, nil)
		return ok
	}
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"waiting_for_ci_matches", "PR is open. Waiting for CI on PR 12.", true},
		{"wacht_op_de_build_matches", "Ik wacht op de build.", true},
		{"waiting_for_your_review_passes", "Waiting for your review of the build before I continue.", false},
		{"blocked_on_owner_approval_passes", "Blocked, waiting on the owner's approval for the deploy.", false},
		{"not_waiting_passes", "I am not waiting for CI, it already passed.", false},
		{"quoted_text_passes", `The log said "waiting for the build to finish" and then failed.`, false},
		{"code_block_passes", "Output:\n```\nwaiting for CI to finish\n```\nDone.", false},
		{"wacht_op_jouw_akkoord_passes", "Ik wacht op jouw akkoord.", false},
		{"single_quoted_passes", "The log said 'waiting for the build to finish' and then failed.", false},
		{"third_person_passes", "The agent is waiting for CI.", false},
		{"first_person_im_matches", "I'm waiting for the deploy to finish.", true},
		{"once_ci_finishes_matches", "I'll check back once CI finishes.", true},
		{"zodra_je_merget_passes", "Zodra je merget, rond ik de release af.", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fires(c.text); got != c.want {
				t.Errorf("fires(%q) = %v, want %v", c.text, got, c.want)
			}
		})
	}
}

func TestStopWaitingClauses(t *testing.T) {
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"comma_clause_fires", "PR #12 is open, waiting for CI.", true},
		{"semicolon_clause_fires", "Pushed the fix; waiting for CI.", true},
		{"dutch_comma_clause_fires", "Gepusht, ik wacht nu op de pipeline.", true},
		{"review_clause_still_passes", "PR #12 is open, waiting for your review.", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sessionWaitsOnMachine(c.text); got != c.want {
				t.Errorf("sessionWaitsOnMachine(%q) = %v, want %v", c.text, got, c.want)
			}
		})
	}
}

func TestProposedTestRun(t *testing.T) {
	var proposed StopRule
	for _, r := range DefaultRules() {
		if r.Name() == "proposed-test-not-run" {
			proposed = r
		}
	}
	parseFixture := func(t *testing.T, name string) Transcript {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		var turns []json.RawMessage
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var entry struct {
				Message json.RawMessage `json:"message"`
			}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatal(err)
			}
			turns = append(turns, entry.Message)
		}
		return ParseTranscript(turns)
	}

	t.Run("ran_in_same_turn_does_not_fire", func(t *testing.T) {
		tr := parseFixture(t, "proposed_test_ran.jsonl")
		if fires, _ := proposed.Eval(tr, nil); fires {
			t.Error("fired although go test ran in the same turn, before the final text")
		}
	})

	t.Run("never_ran_fires", func(t *testing.T) {
		tr := parseFixture(t, "proposed_test_never_ran.jsonl")
		if fires, _ := proposed.Eval(tr, nil); !fires {
			t.Error("did not fire although no test ran")
		}
	})
}
