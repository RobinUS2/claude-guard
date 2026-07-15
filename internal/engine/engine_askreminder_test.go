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

// TestAskReminder_GhApiMutation verifies `gh api` calls with mutating HTTP
// methods surface a real confirmation prompt (Ask, deterministic, ahead of
// the LLM tier) rather than being silently allowed. Moved here from the
// bash_adversarial.txt corpus (2026-07-15) when the gh-api-mutation rule
// moved from Tier 1 block to Tier 1.6 ask-reminder — these commands are no
// longer "must always Deny", they're "must always Ask, never silently pass".
func TestAskReminder_GhApiMutation(t *testing.T) {
	e := askEngine(t)
	cases := []string{
		// both -X and --method shapes, both concat and space-separated
		`gh api -X DELETE /repos/foo/bar`,
		`gh api -XDELETE /repos/foo/bar`,
		`gh api --method DELETE /repos/foo/bar`,
		`gh api --request POST /repos/foo/bar/hooks`,
		`gh api /repos/foo/bar -X PATCH`,
		`gh api --method=DELETE /repos/foo/bar`,
		// AllowPathSuffixes bypass attempts: a path that merely CONTAINS a
		// suffix keyword (not ends-with) must not be treated as exempt
		`gh api repos/foo/bar/reviews/evil --method POST`,
		`gh api repos/foo/bar/comments/evil --method POST`,
		// DELETE on an otherwise-allowed-suffix path must still prompt -
		// isAllowedPost only exempts POST, never DELETE/PATCH/PUT
		`gh api repos/foo/bar/pulls/1/reviews --method DELETE`,
	}
	for _, cmd := range cases {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Ask {
			t.Errorf("expected Ask for %q, got verdict=%s tier=%s rule=%s reason=%s", cmd, out.Verdict, out.Tier, out.Rule, out.Reason)
			continue
		}
		if out.Tier != "ask_reminder" {
			t.Errorf("expected tier=ask_reminder for %q, got %s", cmd, out.Tier)
		}
		if out.Rule != "gh-api-mutation" {
			t.Errorf("expected rule=gh-api-mutation for %q, got %s", cmd, out.Rule)
		}
		if strings.Contains(out.Hint, "Studio API") {
			t.Errorf("expected gh-api-mutation's own hint (not the generic DB prefer-API hint) for %q, got hint=%q", cmd, out.Hint)
		}
		if out.Hint == "" {
			t.Errorf("expected a non-empty hint for %q", cmd)
		}
	}
}

// TestAskReminder_GhApiReadOnlyStillAllowed verifies plain reads and the
// still-unconditional PR review/comment creation exemption are unaffected
// by moving gh-api-mutation to the ask-reminder tier - they must never even
// reach the ask-reminder rule (NoMatch), so they fall through to Tier 2
// allow exactly as before.
func TestAskReminder_GhApiReadOnlyStillAllowed(t *testing.T) {
	e := askEngine(t)
	cases := []string{
		`gh api /user`,
		`gh api -X GET /user`,
		`gh api repos/foo/bar/pulls/28/reviews --method POST --input /tmp/review.json`,
		`gh api repos/foo/bar/pulls/28/comments --method POST --input /tmp/comment.json`,
	}
	for _, cmd := range cases {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Allow {
			t.Errorf("expected Allow for %q, got verdict=%s tier=%s rule=%s", cmd, out.Verdict, out.Tier, out.Rule)
		}
	}
}

// TestAskReminder_GhApiGraphqlStillHardBlocked verifies `gh api graphql` is
// unaffected by this change - it's caught by the separate gh-destructive
// Tier 1 rule (arbitrary mutations via -f query=), not gh-api-mutation, and
// must remain an unconditional Deny.
func TestAskReminder_GhApiGraphqlStillHardBlocked(t *testing.T) {
	e := askEngine(t)
	out := e.Decide(Input{ToolName: "Bash", Command: `gh api graphql -f query='mutation { deleteRepository }'`})
	if out.Verdict != Deny {
		t.Errorf("expected Deny for gh api graphql, got verdict=%s tier=%s rule=%s", out.Verdict, out.Tier, out.Rule)
	}
}
