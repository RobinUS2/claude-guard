package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/legacy"
)

func buildSuggestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg := config.Default()
	legacyPath := filepath.Join(t.TempDir(), "legacy.yaml")
	legacyList, _ := legacy.Load(legacyPath)
	return engine.NewWithOptions(engine.Options{Config: cfg, Legacy: legacyList})
}

func writeSuggestLog(t *testing.T, recs []map[string]any) string {
	t.Helper()
	return writeReplayLog(t, recs) // reuse the replay fixture helper
}

func TestRunSuggest_Empty(t *testing.T) {
	path := writeSuggestLog(t, nil)
	eng := buildSuggestEngine(t)
	candidates := runSuggest(path, time.Now().Add(-time.Hour), 1, eng)
	if len(candidates) != 0 {
		t.Errorf("got %d candidates from empty log, want 0", len(candidates))
	}
}

func TestRunSuggest_BelowMinSessions(t *testing.T) {
	// One unique session → below min_sessions=2, should be excluded.
	recs := []map[string]any{
		decisionRecSess("continue", "default", "git push origin main", "Bash", "sess-a"),
	}
	path := writeSuggestLog(t, recs)
	eng := buildSuggestEngine(t)
	candidates := runSuggest(path, time.Now().Add(-time.Hour), 2, eng)
	if len(candidates) != 0 {
		t.Errorf("got %d candidates, want 0 (below min_sessions=2)", len(candidates))
	}
}

func TestRunSuggest_MultiSession_HighConfidence(t *testing.T) {
	// Same command in two sessions → above min_sessions=2.
	recs := []map[string]any{
		decisionRecSess("continue", "default", "git push origin main", "Bash", "sess-a"),
		decisionRecSess("continue", "default", "git push origin main", "Bash", "sess-b"),
	}
	path := writeSuggestLog(t, recs)
	eng := buildSuggestEngine(t)
	candidates := runSuggest(path, time.Now().Add(-time.Hour), 2, eng)
	// git push: may already be handled by git-push-nonforce (allow) or go to LLM (continue).
	// Either way the function should not crash, and if it produces candidates they should be valid.
	for _, c := range candidates {
		if c.canonical == "" {
			t.Error("candidate has empty canonical")
		}
		if c.ruleType == "" {
			t.Errorf("candidate %q has empty ruleType", c.canonical)
		}
	}
}

func TestRunSuggest_AlreadyBlocked_Skipped(t *testing.T) {
	// terraform destroy is Tier 1 blocked — should appear as already_blocked, not a rule candidate.
	recs := []map[string]any{
		decisionRecSess("continue", "default", "terraform destroy", "Bash", "sess-a"),
		decisionRecSess("continue", "default", "terraform destroy", "Bash", "sess-b"),
	}
	path := writeSuggestLog(t, recs)
	eng := buildSuggestEngine(t)
	candidates := runSuggest(path, time.Now().Add(-time.Hour), 1, eng)
	found := false
	for _, c := range candidates {
		if c.canonical == "terraform destroy" {
			found = true
			if c.ruleType != "already_blocked" {
				t.Errorf("terraform destroy ruleType = %q, want 'already_blocked'", c.ruleType)
			}
		}
	}
	if !found {
		t.Error("terraform destroy should appear in candidates as already_blocked")
	}
}

func TestRunSuggest_SkipsNonBash(t *testing.T) {
	recs := []map[string]any{
		// WebFetch Continue — should be skipped (suggest is Bash-only).
		{"time": recentTime(), "msg": "decision", "tool_name": "WebFetch",
			"verdict": "continue", "tier": "default", "command": "https://example.com",
			"session_id": "sess-x"},
		{"time": recentTime(), "msg": "decision", "tool_name": "WebFetch",
			"verdict": "continue", "tier": "default", "command": "https://example.com",
			"session_id": "sess-y"},
	}
	path := writeSuggestLog(t, recs)
	eng := buildSuggestEngine(t)
	candidates := runSuggest(path, time.Now().Add(-time.Hour), 1, eng)
	if len(candidates) != 0 {
		t.Errorf("got %d candidates from WebFetch-only log, want 0", len(candidates))
	}
}

func TestRunSuggest_SessionDedup(t *testing.T) {
	// Same command 10 times in ONE session — counts as 1 session, below min_sessions=2.
	recs := make([]map[string]any, 10)
	for i := range recs {
		recs[i] = decisionRecSess("continue", "default", "bq query --use_legacy_sql=false 'SELECT 1'", "Bash", "one-session")
	}
	path := writeSuggestLog(t, recs)
	eng := buildSuggestEngine(t)
	candidates := runSuggest(path, time.Now().Add(-time.Hour), 2, eng)
	// bq query: one session (10 occurrences) → below min_sessions=2 → excluded.
	for _, c := range candidates {
		if c.canonical == "bq query" {
			t.Errorf("bq query appeared in candidates despite being in only 1 session")
		}
	}
}

// TestRunSuggest_WriteFile verifies suggest output file path doesn't exist before
// the function runs (not a suggest function test, just ensures os.Create path works).
func TestRunSuggest_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "test-hints.md")

	args := []string{"--no-history", "--output", outPath}
	// cmdHints should create the file.
	code := cmdHints(args)
	if code != 0 {
		t.Errorf("cmdHints returned %d, want 0", code)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}
