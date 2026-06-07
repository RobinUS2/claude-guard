package main

// cmdHints generates a CLAUDE.md-compatible hints block that teaches Claude
// what the guard will and won't auto-approve. Two layers:
//
// Layer 1 (static): derived from the compiled-in rule set. Never changes
//   until a new claude-guard binary is installed.
//
// Layer 2 (dynamic): derived from decisions.jsonl. Shows patterns from the
//   user's actual history — what gets auto-allowed vs what still prompts.
//
// Usage:
//
//	claude-guard hints [--since 7d] [--output PATH] [--no-history]
//
// Add to ~/.claude/CLAUDE.md:
//
//	See /Users/you/.config/claude-guard/hints.md for guard auto-approval hints.
//
// Regenerate daily: claude-guard hints --output ~/.config/claude-guard/hints.md

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
)

func cmdHints(args []string) int {
	fs := flag.NewFlagSet("hints", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var since time.Duration
	var outputPath string
	var noHistory bool
	fs.DurationVar(&since, "since", 7*24*time.Hour, "history window for dynamic layer")
	fs.StringVar(&outputPath, "output", "", "write output to file instead of stdout")
	fs.BoolVar(&noHistory, "no-history", false, "skip dynamic history layer (static rules only)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	out := os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hints: create %s: %v\n", outputPath, err)
			return 1
		}
		defer f.Close()
		out = f
	}

	cfg := config.Default()
	paths := clog.DefaultPaths(cfg.Log.Dir)

	// Layer 1: static from rule set.
	writeStaticLayer(out, cfg)

	// Layer 2: dynamic from history.
	if !noHistory {
		writeDynamicLayer(out, paths.Decisions, time.Now().Add(-since), since)
	}

	// Layer 3: structural planning guidance (always static).
	writePlanningGuidance(out)

	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "hints: written to %s\n", outputPath)
		fmt.Fprintf(os.Stderr, "       add to CLAUDE.md: See %s for guard hints.\n", outputPath)
	}
	return 0
}

func writeStaticLayer(w *os.File, cfg *config.Config) {
	fmt.Fprintln(w, "# Claude Guard — Auto-Approval Hints")
	fmt.Fprintf(w, "# Generated %s\n", time.Now().Format("2006-01-02 15:04"))
	fmt.Fprintln(w, "# Add to CLAUDE.md or reference via: See /path/to/hints.md")
	fmt.Fprintln(w)

	// Tier 2 allow rules → "these always auto-approve"
	fmt.Fprintln(w, "## Commands That Auto-Approve (no user prompt needed)")
	fmt.Fprintln(w)

	// Extract allow rule names and present them as human-readable groups.
	allowedGroups := map[string][]string{
		"git (read + workflow)": {
			"git status, git log, git diff, git show, git branch",
			"git add, git commit, git fetch, git pull, git merge",
			"git stash, git checkout, git switch, git restore",
			"git push (non-force, to any branch) — new rule",
		},
		"Go development": {
			"go build ./..., go test ./..., go vet ./...",
			"go run, go install, go mod, go get",
		},
		"Make targets": {
			"make build, make test, make install, make lint, make clean",
		},
		"POSIX read-only": {
			"ls, cat, head, tail, find, grep, wc, stat, file, echo, which",
			"sed (read-only), awk, sort, uniq, cut, tr",
		},
		"GCP read-only": {
			"gcloud * list, gcloud * describe, gcloud * get, gcloud logging read",
			"bq query --dry_run, bq show, bq ls",
		},
		"Docker/npm/terraform (read)": {
			"docker ps, docker images, docker logs",
			"npm install, npm run build, npm test",
			"terraform init, terraform plan (never apply without review)",
		},
	}

	for group, items := range allowedGroups {
		fmt.Fprintf(w, "### %s\n", group)
		for _, item := range items {
			fmt.Fprintf(w, "- `%s`\n", item)
		}
		fmt.Fprintln(w)
	}

	// Tier 1 block rules → "these always require approval"
	blockCount := len(cfg.InstantBlock)
	fmt.Fprintln(w, "## Commands That ALWAYS Require User Approval (Tier 1 hard blocks)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "- `sudo *` — privilege escalation")
	fmt.Fprintln(w, "- `rm -rf /`, `rm -rf ~`, `rm -rf /*` — destructive filesystem")
	fmt.Fprintln(w, "- `git push --force`, `git push -f` — force push (may overwrite history)")
	fmt.Fprintln(w, "- `git push --force origin main/master` — force push to protected branch")
	fmt.Fprintln(w, "- `terraform destroy` — irreversible infrastructure destruction")
	fmt.Fprintln(w, "- `curl * | sh`, `wget * | bash` — remote code execution")
	fmt.Fprintln(w, "- Commands writing to `~/.ssh/`, `/etc/`, system paths")
	fmt.Fprintf(w, "\n(%d compiled-in block rules total)\n\n", blockCount)
}

func writeDynamicLayer(w *os.File, logPath string, cutoff time.Time, since time.Duration) {
	f, err := os.Open(logPath)
	if err != nil {
		return // silent fail — static layer is still useful
	}
	defer f.Close()

	type stats struct {
		allows   int
		prompts  int
		sessions map[string]bool
	}
	byCanonical := map[string]*stats{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		var rec clog.ReadRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Msg != clog.MsgDecision || rec.ToolName != "Bash" || rec.Command == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, rec.Time)
		if err != nil || ts.Before(cutoff) {
			continue
		}

		canonical := cache.SessionCanonical(rec.Command)
		if canonical == "" {
			continue
		}
		s := byCanonical[canonical]
		if s == nil {
			s = &stats{sessions: map[string]bool{}}
			byCanonical[canonical] = s
		}
		sid := rec.SessionID
		if sid == "" {
			sid = rec.ToolUseID
		}
		s.sessions[sid] = true

		if strings.EqualFold(rec.Verdict, "allow") {
			s.allows++
		} else if strings.EqualFold(rec.Verdict, "continue") {
			s.prompts++
		}
	}

	// Top auto-allowed patterns (sorted by count).
	type kv struct {
		canonical string
		count     int
	}
	var topAllow, topPrompt []kv
	for canonical, s := range byCanonical {
		if s.allows > 2 {
			topAllow = append(topAllow, kv{canonical, s.allows})
		}
		if s.prompts > 1 {
			topPrompt = append(topPrompt, kv{canonical, s.prompts})
		}
	}
	sort.Slice(topAllow, func(i, j int) bool { return topAllow[i].count > topAllow[j].count })
	sort.Slice(topPrompt, func(i, j int) bool { return topPrompt[i].count > topPrompt[j].count })
	if len(topAllow) > 10 {
		topAllow = topAllow[:10]
	}
	if len(topPrompt) > 8 {
		topPrompt = topPrompt[:8]
	}

	fmt.Fprintf(w, "## Your %s History — Frequently Auto-Approved\n\n", since)
	if len(topAllow) > 0 {
		fmt.Fprintln(w, "These patterns were auto-approved frequently — keep using them:")
		fmt.Fprintln(w)
		for _, kv := range topAllow {
			fmt.Fprintf(w, "- `%s` (%d×)\n", kv.canonical, kv.count)
		}
	} else {
		fmt.Fprintln(w, "(no frequent auto-approvals in this window yet)")
	}
	fmt.Fprintln(w)

	if len(topPrompt) > 0 {
		fmt.Fprintf(w, "## Your %s History — Commands That Still Prompt\n\n", since)
		fmt.Fprintln(w, "These needed user approval — consider restructuring or batching to end of task:")
		fmt.Fprintln(w)
		for _, kv := range topPrompt {
			fmt.Fprintf(w, "- `%s` (%d× prompted)\n", kv.canonical, kv.count)
		}
		fmt.Fprintln(w)
	}
}

func writePlanningGuidance(w *os.File) {
	fmt.Fprintf(w, "%s", `## How to Plan Tasks to Minimise Guard Interruptions

**Rule: put approval-gated steps LAST in every plan.**

The guard auto-approves all read/build/test operations instantly.
External-state changes (push, deploy, apply) require approval — but only once
per session per pattern. Batch them at the end.

### Optimal task structure:

  ✓ Phase 1 — READ (no prompts, instant):
    • grep, find, cat, git log, git diff, git status
    • gcloud * list, bq query --dry_run

  ✓ Phase 2 — BUILD/TEST (no prompts, instant):
    • go build, go test, make build, make test
    • npm install, npm run build
    • terraform plan (dry-run, no apply)

  ✓ Phase 3 — COMMIT (usually instant after first approval):
    • git add, git commit (auto-allowed)
    • git push origin feature-branch (auto-allowed — new rule)

  ⚠ Phase 4 — DEPLOY (may prompt, place at END):
    • git push origin main — LLM decides based on project context
      (ai-site-gen main = production = careful; tiny repo = relaxed)
    • terraform apply — always prompts, place last
    • make provision-prod — prompts first time, cached after

### Why this matters:
- Interrupting Phase 2 to do a git push kills flow
- Batching Phase 4 to end means ONE approval point instead of several
- Session cache: once approved, stays approved for the 8h session

### Context the guard uses for git push decisions:
- Which repo (CWD) — ai-site-gen vs personal scripts vs customer repos
- Which branch — main/master (careful) vs feature/* (relaxed)
- What's in the commit — size, files changed
- Whether CI/CD is triggered by this repo's main branch

### Quick reference:
  Auto-allow:  git push origin feature-*, go test, make test, find, grep
  LLM+cache:   git push origin main, make provision-diff, gcloud deploy
  Always asks: git push --force, terraform apply, sudo anything
`)
}
