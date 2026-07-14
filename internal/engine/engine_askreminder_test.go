package engine

import (
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/config"
)

// askEngine builds an enforce-mode engine (real verdicts, no shadow).
func askEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.ShadowMode = false
	return New(cfg, nil)
}

// TestAskReminder_DirectDB verifies that direct-DB commands and the make
// wrappers that open DB connections surface the Ask verdict (a nudge toward
// the API/MCP) rather than silently allowing or continuing.
func TestAskReminder_DirectDB(t *testing.T) {
	e := askEngine(t)
	cases := []string{
		`psql -h 127.0.0.1 -p 5434 -U sitegen_staging -d sitegen_staging -c "select 1"`,
		`pg_dump sitegen_staging > /tmp/dump.sql`,
		`mysql -u root -e "show databases"`,
		`mongosh "mongodb://localhost:27017"`,
		`redis-cli -h localhost ping`,
		`sqlite3 app.db ".tables"`,
		`cloud-sql-proxy content-gen-484211:europe-west4:sitegen-pg-staging --port=5434`,
		`make staging-pg-proxy-bg`,
		`make prod-pg-shell`,
		`make staging-pg-migrate`,
	}
	for _, cmd := range cases {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Ask {
			t.Errorf("expected Ask for %q, got verdict=%s tier=%s rule=%s", cmd, out.Verdict, out.Tier, out.Rule)
			continue
		}
		if out.Tier != "ask_reminder" {
			t.Errorf("expected tier=ask_reminder for %q, got %s", cmd, out.Tier)
		}
		if !strings.Contains(out.Hint, "Studio API") {
			t.Errorf("expected API/MCP hint for %q, got hint=%q", cmd, out.Hint)
		}
	}
}

// TestAskReminder_DoesNotHijackSafeCommands verifies the nudge is narrow: it
// must not fire for ordinary make targets or unrelated commands.
func TestAskReminder_DoesNotHijackSafeCommands(t *testing.T) {
	e := askEngine(t)
	for _, cmd := range []string{
		`make build`,
		`make test`,
		`go test ./...`,
		`git status`,
		`ls -la`,
	} {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict == Ask && out.Tier == "ask_reminder" {
			t.Errorf("ask-reminder wrongly fired for safe command %q", cmd)
		}
	}
}

// TestAskReminder_SecurityStillWins verifies a genuine Tier-1 block beats the
// soft ask nudge — the ask tier runs only when no block rule matched.
func TestAskReminder_SecurityStillWins(t *testing.T) {
	e := askEngine(t)
	out := e.Decide(Input{ToolName: "Bash", Command: `sudo psql -c "select 1"`})
	if out.Verdict != Deny {
		t.Errorf("expected Deny (sudo) to win over ask-reminder, got verdict=%s tier=%s", out.Verdict, out.Tier)
	}
}
