package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStopStats(t *testing.T) {
	now := time.Now().UTC()
	line := func(ago time.Duration, msg, extra string) string {
		return `{"time":"` + now.Add(-ago).Format(time.RFC3339Nano) + `","msg":"` + msg + `",` + extra + `}`
	}
	log := strings.Join([]string{
		line(time.Hour, "stop_would_block", `"session_id":"a","rule":"open-todo-items"`),
		line(time.Hour, "stop_would_block", `"session_id":"a","rule":"open-todo-items"`),
		line(time.Hour, "stop_would_block", `"session_id":"b","rule":"open-todo-items"`),
		line(time.Hour, "stop_hook", `"session_id":"c","fired_rule":"waiting-nothing-running","injected":true`),
		line(time.Hour, "stop_hook", `"session_id":"c","fired_rule":"waiting-nothing-running","injected":false`),
		line(time.Hour, "decision", `"session_id":"z","rule":"open-todo-items"`),
		line(10*24*time.Hour, "stop_would_block", `"session_id":"old","rule":"open-todo-items"`),
		"not json",
	}, "\n")
	get := func(since time.Duration) map[string]*stopRuleStat {
		return collectStopStats(strings.NewReader(log), now.Add(-since))
	}
	t.Run("counts_per_rule", func(t *testing.T) {
		s := get(7 * 24 * time.Hour)
		if s["open-todo-items"].WouldBlock != 3 || s["open-todo-items"].Blocked != 0 {
			t.Errorf("open-todo-items = %+v", s["open-todo-items"])
		}
		if s["waiting-nothing-running"].Blocked != 1 || s["waiting-nothing-running"].WouldBlock != 0 {
			t.Errorf("waiting-nothing-running = %+v", s["waiting-nothing-running"])
		}
	})
	t.Run("distinct_sessions", func(t *testing.T) {
		s := get(7 * 24 * time.Hour)
		if n := len(s["open-todo-items"].sessions); n != 2 {
			t.Errorf("sessions = %d, want 2", n)
		}
	})
	t.Run("since_filter", func(t *testing.T) {
		s := get(30 * 24 * time.Hour)
		if s["open-todo-items"].WouldBlock != 4 || len(s["open-todo-items"].sessions) != 3 {
			t.Errorf("30d = %+v", s["open-todo-items"])
		}
		s = get(30 * time.Minute)
		if len(s) != 0 {
			t.Errorf("30m should be empty, got %d rules", len(s))
		}
	})
	t.Run("sessions_exclude_blind", func(t *testing.T) {
		blindLog := strings.Join([]string{
			line(time.Hour, "stop_would_block", `"session_id":"a","rule":"install-not-run"`),
			line(time.Hour, "stop_blind", `"session_id":"b","rule":"install-not-run"`),
			line(time.Hour, "stop_blind", `"session_id":"c","rule":"install-not-run"`),
			line(time.Hour, "stop_blind", `"session_id":"d","rule":"failing-tests"`),
		}, "\n")
		stats := collectStopStats(strings.NewReader(blindLog), now.Add(-24*time.Hour))
		if n := len(stats["install-not-run"].sessions); n != 1 {
			t.Errorf("sessions = %d, want 1 (only the matching session)", n)
		}
		if n := len(stats["failing-tests"].sessions); n != 0 {
			t.Errorf("blind-only rule sessions = %d, want 0", n)
		}
		if stats["install-not-run"].Blind != 2 {
			t.Errorf("Blind = %d, want 2", stats["install-not-run"].Blind)
		}
	})
	t.Run("blind_column_counts", func(t *testing.T) {
		blindLog := line(time.Hour, "stop_blind", `"session_id":"b","rule":"failing-tests"`) + "\n" +
			line(time.Hour, "stop_blind", `"session_id":"c","rule":"failing-tests"`)
		var buf strings.Builder
		path := filepath.Join(t.TempDir(), "d.jsonl")
		if err := os.WriteFile(path, []byte(blindLog), 0o644); err != nil {
			t.Fatal(err)
		}
		if code := cmdStopStats([]string{"--path", path}, &buf); code != 0 {
			t.Fatalf("exit %d", code)
		}
		out := buf.String()
		if !strings.Contains(out, "BLIND") {
			t.Errorf("no BLIND column:\n%s", out)
		}
		fields := []string{}
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "failing-tests") {
				fields = strings.Fields(l)
			}
		}
		// RULE MODE BLOCKED WOULD-BLOCK BLIND SESSIONS
		if len(fields) != 6 || fields[4] != "2" || fields[5] != "0" {
			t.Errorf("row = %v, want blind 2 and sessions 0", fields)
		}
	})
}
