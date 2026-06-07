package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/legacy"
)

// writeReplayLog writes JSONL decision records to a temp file and returns the path.
func writeReplayLog(t *testing.T, recs []map[string]any) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "decisions*.jsonl")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	return f.Name()
}

func buildReplayEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg := config.Default()
	legacyPath := filepath.Join(t.TempDir(), "legacy.yaml")
	legacyList, _ := legacy.Load(legacyPath) // empty list is fine
	return engine.NewWithOptions(engine.Options{
		Config: cfg,
		Legacy: legacyList,
		// No LLM, no cache, no session store — pure deterministic tiers.
	})
}

func TestRunReplay_Empty(t *testing.T) {
	path := writeReplayLog(t, nil)
	eng := buildReplayEngine(t)
	res := runReplay(path, time.Now().Add(-time.Hour), "", 0, false, eng)
	if res.total != 0 {
		t.Errorf("total = %d, want 0", res.total)
	}
}

func TestRunReplay_AllContinue(t *testing.T) {
	// Records that will remain Continue (unknown command, no rule matches).
	recs := []map[string]any{
		decisionRec("continue", "default", "unknown-tool-xyz --foobar", "Bash"),
		decisionRec("continue", "default", "weird-binary do-something", "Bash"),
	}
	path := writeReplayLog(t, recs)
	eng := buildReplayEngine(t)
	res := runReplay(path, time.Now().Add(-time.Hour), "", 0, false, eng)
	if res.total != 2 {
		t.Errorf("total = %d, want 2", res.total)
	}
	if res.stillCont != 2 {
		t.Errorf("stillCont = %d, want 2", res.stillCont)
	}
	if res.wouldAllow != 0 {
		t.Errorf("wouldAllow = %d, want 0", res.wouldAllow)
	}
}

func TestRunReplay_NowAllowed(t *testing.T) {
	// "git status" was historically a Continue but Tier 2 now allows it.
	recs := []map[string]any{
		decisionRec("continue", "default", "git status", "Bash"),
		decisionRec("continue", "default", "git log --oneline -5", "Bash"),
	}
	path := writeReplayLog(t, recs)
	eng := buildReplayEngine(t)
	res := runReplay(path, time.Now().Add(-time.Hour), "", 0, false, eng)
	if res.total != 2 {
		t.Errorf("total = %d, want 2", res.total)
	}
	if res.wouldAllow != 2 {
		t.Errorf("wouldAllow = %d, want 2 (git commands should hit instant_allow)", res.wouldAllow)
	}
	if res.stillCont != 0 {
		t.Errorf("stillCont = %d, want 0", res.stillCont)
	}
}

func TestRunReplay_Regression(t *testing.T) {
	// "terraform destroy" was a Continue (user prompt) but is now Tier 1 Deny.
	recs := []map[string]any{
		decisionRec("continue", "default", "terraform destroy", "Bash"),
	}
	path := writeReplayLog(t, recs)
	eng := buildReplayEngine(t)
	res := runReplay(path, time.Now().Add(-time.Hour), "", 0, false, eng)
	if res.total != 1 {
		t.Errorf("total = %d, want 1", res.total)
	}
	if res.nowDeny != 1 {
		t.Errorf("nowDeny = %d, want 1 (terraform destroy is now Tier 1)", res.nowDeny)
	}
	if res.wouldAllow != 0 {
		t.Errorf("wouldAllow = %d, want 0", res.wouldAllow)
	}
}

func TestRunReplay_TimeFilter(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	recent := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339Nano)

	recs := []map[string]any{
		{"time": old, "msg": "decision", "tool_name": "Bash", "verdict": "continue", "tier": "default", "command": "git status"},
		{"time": recent, "msg": "decision", "tool_name": "Bash", "verdict": "continue", "tier": "default", "command": "git status"},
	}
	path := writeReplayLog(t, recs)
	eng := buildReplayEngine(t)

	// Only replay last 1 hour — old record should be excluded.
	cutoff := time.Now().Add(-time.Hour)
	res := runReplay(path, cutoff, "", 0, false, eng)
	if res.total != 1 {
		t.Errorf("total = %d, want 1 (only recent record in window)", res.total)
	}
}

func TestRunReplay_SessionFilter(t *testing.T) {
	recs := []map[string]any{
		decisionRecSess("continue", "default", "git status", "Bash", "sess-aaa"),
		decisionRecSess("continue", "default", "git log", "Bash", "sess-bbb"),
	}
	path := writeReplayLog(t, recs)
	eng := buildReplayEngine(t)

	res := runReplay(path, time.Now().Add(-time.Hour), "sess-aaa", 0, false, eng)
	if res.total != 1 {
		t.Errorf("total = %d, want 1 (session filter)", res.total)
	}
}

func TestRunReplay_Limit(t *testing.T) {
	recs := []map[string]any{
		decisionRec("continue", "default", "weird-binary-a", "Bash"),
		decisionRec("continue", "default", "weird-binary-b", "Bash"),
		decisionRec("continue", "default", "weird-binary-c", "Bash"),
	}
	path := writeReplayLog(t, recs)
	eng := buildReplayEngine(t)

	res := runReplay(path, time.Now().Add(-time.Hour), "", 2, false, eng)
	if res.total != 2 {
		t.Errorf("total = %d, want 2 (limit=2)", res.total)
	}
}

func TestRunReplay_SkipsNonContinue(t *testing.T) {
	recs := []map[string]any{
		decisionRec("allow", "instant_allow", "git status", "Bash"),
		decisionRec("deny", "instant_block", "sudo rm -rf /", "Bash"),
		decisionRec("continue", "default", "weird-binary-z", "Bash"),
	}
	path := writeReplayLog(t, recs)
	eng := buildReplayEngine(t)

	res := runReplay(path, time.Now().Add(-time.Hour), "", 0, false, eng)
	// Only the Continue record should be replayed.
	if res.total != 1 {
		t.Errorf("total = %d, want 1 (allow+deny records skipped)", res.total)
	}
}

func TestRunReplay_SkipsNonBash(t *testing.T) {
	recs := []map[string]any{
		// WebFetch Continue — should be skipped (replay is Bash-only for now).
		{"time": recentTime(), "msg": "decision", "tool_name": "WebFetch",
			"verdict": "continue", "tier": "default", "command": "https://example.com"},
		decisionRec("continue", "default", "weird-binary-z", "Bash"),
	}
	path := writeReplayLog(t, recs)
	eng := buildReplayEngine(t)
	res := runReplay(path, time.Now().Add(-time.Hour), "", 0, false, eng)
	if res.total != 1 {
		t.Errorf("total = %d, want 1 (WebFetch skipped)", res.total)
	}
}

// ─── fixtures ────────────────────────────────────────────────────────────────

func decisionRec(verdict, tier, command, toolName string) map[string]any {
	return map[string]any{
		"time":      recentTime(),
		"msg":       "decision",
		"tool_name": toolName,
		"verdict":   verdict,
		"tier":      tier,
		"command":   command,
	}
}

func decisionRecSess(verdict, tier, command, toolName, sessionID string) map[string]any {
	r := decisionRec(verdict, tier, command, toolName)
	r["session_id"] = sessionID
	return r
}

func recentTime() string {
	return time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339Nano)
}
