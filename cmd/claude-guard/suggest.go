package main

// cmdSuggest analyses historical Continue (user-prompt) decisions and
// proposes concrete rules or prompt-hints to eliminate recurring friction.
//
// Algorithm:
//  1. Read decisions.jsonl, filter verdict=continue, Bash only
//  2. Group by cache.SessionCanonical — dedup within each session first
//     (one session seeing the same command 20× counts as 1 unique session)
//  3. Sort by session-count descending
//  4. Classify each canonical using a deterministic program lookup table
//  5. Print proposals: Tier 2 rule, prompt hint, project rule, or manual review
//
//	claude-guard suggest [--since 7d] [--min-sessions 2]

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
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	clog "github.com/RobinUS2/claude-guard/internal/log"
)

func cmdSuggest(args []string) int {
	fs := flag.NewFlagSet("suggest", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var since time.Duration
	var minSessions int
	var pathOverride string
	fs.DurationVar(&since, "since", 7*24*time.Hour, "analyse decisions from the last N")
	fs.IntVar(&minSessions, "min-sessions", 2, "minimum unique sessions for a pattern to appear in output")
	fs.StringVar(&pathOverride, "path", "", "override decisions log path")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := config.Default()
	paths := clog.DefaultPaths(cfg.Log.Dir)
	logPath := paths.Decisions
	if pathOverride != "" {
		logPath = pathOverride
	}

	legacyList, _ := legacy.Load(defaultLegacyPath())
	eng := engine.NewWithOptions(engine.Options{
		Config: cfg,
		Legacy: legacyList,
		// No LLM, no cache — suggest uses deterministic tiers only to classify.
	})

	cutoff := time.Now().Add(-since)
	candidates := runSuggest(logPath, cutoff, minSessions, eng)
	printSuggestions(candidates, since, minSessions)
	return 0
}

// suggestCandidate is one pattern group from the analysis.
type suggestCandidate struct {
	canonical    string     // program + subcommand (SessionCanonical output)
	sessionCount int        // unique sessions this appeared in
	totalCount   int        // raw occurrence count across all sessions
	samples      []string   // up to 3 representative commands
	ruleType     string     // "tier2" | "prompt_hint" | "project_rule" | "already_blocked" | "skip"
	confidence   string     // "high" | "medium" | "low"
	proposal     string     // human-readable proposal text
}

func runSuggest(logPath string, cutoff time.Time, minSessions int, eng *engine.Engine) []suggestCandidate {
	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "suggest: open %s: %v\n", logPath, err)
		return nil
	}
	defer f.Close()

	// canonical → set of session IDs that saw it (for unique-session counting)
	type entry struct {
		sessions map[string]bool
		total    int
		samples  []string
	}
	groups := map[string]*entry{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		var rec clog.ReadRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Msg != clog.MsgDecision || rec.ToolName != "Bash" {
			continue
		}
		if !strings.EqualFold(rec.Verdict, "continue") {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, rec.Time)
		if err != nil || ts.Before(cutoff) {
			continue
		}
		if rec.Command == "" {
			continue
		}

		canonical := cache.SessionCanonical(rec.Command)
		if canonical == "" {
			continue
		}

		e := groups[canonical]
		if e == nil {
			e = &entry{sessions: map[string]bool{}}
			groups[canonical] = e
		}
		e.total++
		sid := rec.SessionID
		if sid == "" {
			sid = "_anon_" + rec.ToolUseID // fallback: treat each anon call as own session
		}
		e.sessions[sid] = true
		if len(e.samples) < 3 && rec.Command != canonical {
			e.samples = append(e.samples, truncLong(rec.Command, 80))
		}
	}

	// Build candidates above threshold.
	var out []suggestCandidate
	for canonical, e := range groups {
		if len(e.sessions) < minSessions {
			continue
		}

		// Run through deterministic tiers to see current verdict.
		verdict := eng.Decide(engine.Input{ToolName: "Bash", Command: canonical})

		// Skip: already handled by current engine deterministically.
		if verdict.Verdict == engine.Allow {
			continue // already auto-allowed — new rule must have fixed it
		}
		if verdict.Verdict == engine.Deny {
			// Tier 1 block: correct, skip suggesting a workaround.
			c := suggestCandidate{
				canonical:    canonical,
				sessionCount: len(e.sessions),
				totalCount:   e.total,
				samples:      e.samples,
				ruleType:     "already_blocked",
				confidence:   "high",
				proposal:     "blocked by Tier 1 rule '" + verdict.Rule + "' — correct, no action",
			}
			out = append(out, c)
			continue
		}

		// Classify the canonical into a suggestion type.
		c := classify(canonical, len(e.sessions), e.total, e.samples)
		out = append(out, c)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].sessionCount != out[j].sessionCount {
			return out[i].sessionCount > out[j].sessionCount
		}
		return out[i].canonical < out[j].canonical
	})
	return out
}

// programTier maps the first program token to a classification hint.
// This is a deterministic lookup table — no engine calls, no LLM.
var programTier = map[string]string{
	// Likely safe: well-known read or workflow programs
	"git":    "tier2_check",
	"go":     "tier2_check",
	"make":   "tier2_check",
	"npm":    "tier2_check",
	"cargo":  "tier2_check",
	"python": "tier2_check",
	"python3": "tier2_check",
	// Secrets/credentials access → prompt hint is better than allow rule
	"export": "prompt_hint",
	// Medium: write implications
	"chmod":     "medium",
	"chown":     "medium",
	"curl":      "medium",
	"wget":      "medium",
	"bq":        "medium",
	"gcloud":    "medium",
	"gsutil":    "medium",
	"terraform": "medium",
	"kubectl":   "medium",
	// Usually safe (read-only)
	"find":    "high",
	"grep":    "high",
	"rg":      "high",
	"ls":      "high",
	"cat":     "high",
	"head":    "high",
	"tail":    "high",
	"echo":    "high",
	"wc":      "high",
	"stat":    "high",
	"file":    "high",
	"tree":    "high",
	"which":   "high",
	"command": "high",
}

// safeSubcommands lists program→[]subcommand pairs that are high-confidence safe.
var safeSubcommands = map[string][]string{
	"git":    {"push", "add", "commit", "fetch", "pull", "merge", "rebase", "stash"},
	"go":     {"build", "test", "vet", "install", "run", "generate", "mod", "get"},
	"make":   {"build", "test", "install", "lint", "check", "clean", "fmt"},
	"npm":    {"install", "run", "test", "build", "lint", "start"},
	"cargo":  {"build", "test", "clippy", "fmt", "check", "run"},
	"python": {"run"},
	"python3": {"run"},
	"bq":     {"query", "show", "ls"},
	"gcloud": {"logging", "builds", "run", "compute", "iam", "projects"},
}

func classify(canonical string, sessionCount, total int, samples []string) suggestCandidate {
	parts := strings.Fields(canonical)
	program := ""
	if len(parts) > 0 {
		program = parts[0]
	}
	subcommand := ""
	if len(parts) > 1 {
		subcommand = parts[1]
	}

	tier := programTier[program]
	confidence := "medium"
	ruleType := "project_rule"
	proposal := ""

	switch tier {
	case "prompt_hint":
		ruleType = "prompt_hint"
		confidence = "high"
		proposal = fmt.Sprintf(
			"add to ~/.config/claude-guard/prompt-hints.yaml:\n"+
			"       context: \"This user's %s commands are part of a normal local dev workflow.\"\n"+
			"       reason: recurring prompt (%d sessions)",
			canonical, sessionCount)

	case "high":
		ruleType = "tier2"
		confidence = "high"
		proposal = fmt.Sprintf(
			"consider adding to compiled-in Tier 2 (instant_allow) or .claude-guard.yml:\n"+
			"       allow: [{name: %s-readonly, programs: [%s], subcommands: [%s]}]",
			program, program, subcommand)

	case "tier2_check":
		safeSubs := safeSubcommands[program]
		isSafe := false
		for _, s := range safeSubs {
			if s == subcommand {
				isSafe = true
				break
			}
		}
		if isSafe {
			ruleType = "tier2"
			confidence = "high"
			proposal = fmt.Sprintf(
				"add to .claude-guard.yml for project-specific approval, or consider\n"+
				"       opening an issue to promote '%s %s' to compiled-in Tier 2",
				program, subcommand)
		} else {
			ruleType = "project_rule"
			confidence = "medium"
			proposal = fmt.Sprintf(
				"add to .claude-guard.yml in the relevant repo:\n"+
				"       allow: [{name: %s-%s, programs: [%s], subcommands: [%s]}]",
				program, subcommand, program, subcommand)
		}

	case "medium":
		ruleType = "project_rule"
		confidence = "medium"
		proposal = fmt.Sprintf(
			"medium-risk — verify it's safe, then add to .claude-guard.yml:\n"+
			"       allow: [{name: %s-%s, programs: [%s], subcommands: [%s]}]",
			program, subcommand, program, subcommand)

	default:
		ruleType = "manual"
		confidence = "low"
		proposal = "unknown program — review manually before adding any rule"
	}

	return suggestCandidate{
		canonical:    canonical,
		sessionCount: sessionCount,
		totalCount:   total,
		samples:      samples,
		ruleType:     ruleType,
		confidence:   confidence,
		proposal:     proposal,
	}
}

func printSuggestions(candidates []suggestCandidate, since time.Duration, minSessions int) {
	fmt.Printf("suggest — rule candidates from %s of Continue decisions (≥%d sessions)\n\n", since, minSessions)

	if len(candidates) == 0 {
		fmt.Println("  no recurring patterns found")
		fmt.Println("  hint: try --since 14d or --min-sessions 1")
		return
	}

	// Split by confidence tier for display.
	var high, medium, blocked []suggestCandidate
	for _, c := range candidates {
		switch {
		case c.ruleType == "already_blocked":
			blocked = append(blocked, c)
		case c.confidence == "high":
			high = append(high, c)
		default:
			medium = append(medium, c)
		}
	}

	if len(high) > 0 {
		fmt.Printf("  HIGH CONFIDENCE — safe pattern, high frequency:\n")
		fmt.Printf("  %s\n", strings.Repeat("─", 60))
		for _, c := range high {
			printCandidate(c)
		}
	}

	if len(medium) > 0 {
		if len(high) > 0 {
			fmt.Println()
		}
		fmt.Printf("  MEDIUM CONFIDENCE — check before adding:\n")
		fmt.Printf("  %s\n", strings.Repeat("─", 60))
		for _, c := range medium {
			printCandidate(c)
		}
	}

	if len(blocked) > 0 {
		fmt.Println()
		fmt.Printf("  ALREADY BLOCKED (Tier 1 correctly handles these — no action needed):\n")
		for _, c := range blocked {
			fmt.Printf("  %3d sessions  %-30s  %s\n",
				c.sessionCount, c.canonical, c.proposal)
		}
	}

	fmt.Printf("\n  total: %d high, %d medium, %d blocked\n",
		len(high), len(medium), len(blocked))
	fmt.Println("  tip: run 'claude-guard replay --verbose' to see the full command text for each pattern")
}

func printCandidate(c suggestCandidate) {
	fmt.Printf("\n  %3d sessions  %s\n", c.sessionCount, c.canonical)
	fmt.Printf("       type: %-14s  confidence: %s\n", c.ruleType, c.confidence)
	fmt.Printf("       → %s\n", c.proposal)
	if len(c.samples) > 0 {
		fmt.Printf("       examples:\n")
		for _, s := range c.samples {
			fmt.Printf("         • %s\n", s)
		}
	}
}
