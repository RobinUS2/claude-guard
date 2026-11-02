package stop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clog "github.com/RobinUS2/claude-guard/internal/log"
)

// mockRule is a StopRule for testing.
type mockRule struct {
	name           string
	highConfidence bool
	preFilter      string
	shouldFire     bool
	reason         string
}

func (m *mockRule) Name() string          { return m.name }
func (m *mockRule) HighConfidence() bool  { return m.highConfidence }
func (m *mockRule) MaxContinues() int     { return 0 }
func (m *mockRule) TextPreFilter() string { return m.preFilter }
func (m *mockRule) Eval(_ Transcript, _ ShellContext) (bool, string) {
	return m.shouldFire, m.reason
}

func TestEvaluate_NoRulesFire(t *testing.T) {
	dir := t.TempDir()
	rules := []StopRule{
		&mockRule{name: "r1", preFilter: `\bnever-matches-xyz\b`, shouldFire: true, reason: "x"},
	}
	msg := Evaluate("sess1", dir, false, Transcript{LastAssistantText: "done"}, rules, 500*time.Millisecond)
	if msg != "" {
		t.Errorf("pre-filter should block; got %q", msg)
	}
}

func TestEvaluate_RuleFires(t *testing.T) {
	dir := t.TempDir()
	rules := []StopRule{
		&mockRule{name: "r1", preFilter: `\bdone\b`, shouldFire: true, reason: "uncommitted stuff"},
	}
	tr := Transcript{LastAssistantText: "Done, all complete."}
	msg := Evaluate("sess1", dir, false, tr, rules, 500*time.Millisecond)
	if msg != "uncommitted stuff" {
		t.Errorf("expected rule to fire; got %q", msg)
	}
}

func TestEvaluate_MaxContinuesCap(t *testing.T) {
	dir := t.TempDir()
	sess := newSession("capped", dir)
	for i := 0; i < maxContinuesPerSession; i++ {
		sess.increment()
	}
	rules := []StopRule{
		&mockRule{name: "r1", preFilter: "", shouldFire: true, reason: "always fires"},
	}
	msg := Evaluate("capped", dir, false, Transcript{}, rules, 500*time.Millisecond)
	if msg != "" {
		t.Errorf("should be suppressed at cap, got %q", msg)
	}
}

func TestEvaluate_StopHookActive_HighConfidenceOnly(t *testing.T) {
	dir := t.TempDir()
	rules := []StopRule{
		&mockRule{name: "low", highConfidence: false, preFilter: "", shouldFire: true, reason: "low conf"},
		&mockRule{name: "high", highConfidence: true, preFilter: "", shouldFire: true, reason: "high conf"},
	}
	msg := Evaluate("sess2", dir, true /* stopHookActive */, Transcript{}, rules, 500*time.Millisecond)
	if msg != "high conf" {
		t.Errorf("only high-confidence should fire; got %q", msg)
	}
}

func TestEvaluate_RuleCoolDown(t *testing.T) {
	dir := t.TempDir()
	sess := newSession("cool", dir)
	sess.markFired("r1", shellHash("some-output"))

	if !sess.hasFired("r1") {
		t.Error("r1 should be marked as fired")
	}
	if sess.shellHashChanged("r1", shellHash("some-output")) {
		t.Error("same shell hash should not trigger re-fire")
	}
	if !sess.shellHashChanged("r1", shellHash("different-output")) {
		t.Error("different shell hash should allow re-fire")
	}
}

func TestEvaluate_CoolDownPreventsRefire(t *testing.T) {
	dir := t.TempDir()
	rules := []StopRule{
		&mockRule{name: "r1", preFilter: "", shouldFire: true, reason: "fires once"},
	}
	tr := Transcript{}

	msg1 := Evaluate("sess-cd", dir, false, tr, rules, 500*time.Millisecond)
	if msg1 == "" {
		t.Error("first evaluation should fire")
	}
	// Second call: rule is marked fired with same reason hash → cool-down
	msg2 := Evaluate("sess-cd", dir, false, tr, rules, 500*time.Millisecond)
	if msg2 != "" {
		t.Errorf("second evaluation should be suppressed by cool-down, got %q", msg2)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestRuleMode(t *testing.T) {
	t.Run("default_only_waiting_enforces", func(t *testing.T) {
		for _, r := range DefaultRules() {
			want := ModeLog
			if r.Name() == "waiting-nothing-running" {
				want = ModeEnforce
			}
			if got := RuleMode(r.Name(), nil); got != want {
				t.Errorf("%s mode = %s, want %s", r.Name(), got, want)
			}
		}
	})
	t.Run("log_mode_records_would_block", func(t *testing.T) {
		dir := t.TempDir()
		rules := []StopRule{&mockRule{name: "some-rule", shouldFire: true, reason: "r"}}
		res := EvaluateModes("sess-log", dir, false, Transcript{}, rules, 0, nil)
		if res.Message != "" || len(res.WouldBlock) != 1 || res.WouldBlock[0] != "some-rule" {
			t.Fatalf("result = %+v, want no message and a would-block for some-rule", res)
		}
		paths := clog.DefaultPaths(filepath.Join(dir, "logs"))
		dl, err := clog.OpenDecisionLogger(paths, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		RecordWouldBlock(dl, "sess-log", res)
		dl.Close()
		b, err := os.ReadFile(paths.Decisions)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"msg":"stop_would_block"`, `"session_id":"sess-log"`, `"rule":"some-rule"`, `"time":`} {
			if !strings.Contains(string(b), want) {
				t.Errorf("log lacks %s: %s", want, b)
			}
		}
	})
	t.Run("config_override_enforces", func(t *testing.T) {
		dir := t.TempDir()
		rules := []StopRule{&mockRule{name: "some-rule", shouldFire: true, reason: "r"}}
		res := EvaluateModes("sess-enf", dir, false, Transcript{}, rules, 0, map[string]string{"some-rule": "enforce"})
		if res.Message != "r" || len(res.WouldBlock) != 0 {
			t.Errorf("result = %+v, want enforced block", res)
		}
		res = EvaluateModes("sess-enf2", dir, false, Transcript{}, rules, 0, map[string]string{"some-rule": "log"})
		if res.Message != "" {
			t.Errorf("log override still blocked: %+v", res)
		}
	})
}
