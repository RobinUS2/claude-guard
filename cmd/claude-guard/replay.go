package main

// cmdReplay replaces the old stub (which just aliased explain).
//
// It reads decisions.jsonl, filters to Continue verdicts (commands the guard
// forwarded to the user) in the given time window, re-runs each through the
// current engine (deterministic tiers + existing verdict cache, NO new LLM
// calls), then reports how many would now be auto-handled — the improvement
// metric for systematic rule development.
//
//	claude-guard replay [--since 7d] [--session <id>] [--limit N] [--verbose]
//
// Output sections:
//   - Summary: total replayed, would-now-allow (improvement %), still-continue, regressions
//   - Tier breakdown: which tier handles the newly-auto-allowed commands
//   - Regressions: any historical Continue that would now be Deny (new block rule too broad)
//   - Sample commands: top examples from each outcome category

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

func cmdReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var since time.Duration
	var sessionFilter string
	var limit int
	var verbose bool
	var pathOverride string
	fs.DurationVar(&since, "since", 7*24*time.Hour, "replay decisions from the last N (e.g. 24h, 7d)")
	fs.StringVar(&sessionFilter, "session", "", "replay only decisions from this session ID (prefix match)")
	fs.IntVar(&limit, "limit", 2000, "max Continue decisions to replay; 0 = no limit (can be slow on large logs)")
	fs.BoolVar(&verbose, "verbose", false, "print each replayed decision")
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

	// Engine: deterministic tiers + existing LLM verdict cache. No new LLM
	// calls (LLM=nil). This measures: "of historical user prompts, how many
	// would now be handled by the rule set + accumulated cache?"
	//
	// Note: ProjectConfigLoader is intentionally nil — replay uses the global
	// rule set, not per-project .claude-guard.yml overrides (those vary by cwd).
	// Note: Store (session cache) is intentionally nil — replay simulates fresh
	// sessions, not the current live session state.
	legacyList, _ := legacy.Load(defaultLegacyPath())
	cacheRoot := defaultCacheRoot()
	cch := cache.New(cacheRoot + "/verdicts")
	eng := engine.NewWithOptions(engine.Options{
		Config: cfg,
		Legacy: legacyList,
		Cache:  cch,
	})

	cutoff := time.Now().Add(-since)
	result := runReplay(logPath, cutoff, sessionFilter, limit, verbose, eng)
	printReplayResult(result, since)
	return 0
}

// replayResult holds the aggregate outcome of a replay run.
type replayResult struct {
	total       int
	wouldAllow  int
	stillCont   int
	nowDeny     int // regressions: new block rule fires on something previously shown to user
	byTier      map[string]int
	regressions []replayEntry
	samples     []replayEntry // representative examples, capped
}

type replayEntry struct {
	rec     *clog.ReadRecord
	newTier string
	newRule string
}

func runReplay(logPath string, cutoff time.Time, sessionFilter string, limit int, verbose bool, eng *engine.Engine) replayResult {
	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: open %s: %v\n", logPath, err)
		return replayResult{}
	}
	defer f.Close()

	res := replayResult{byTier: map[string]int{}}
	sampleCap := 10 // per-category examples shown in output

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
		// Only replay historical Continue verdicts — these are the ones that prompted the user.
		if !strings.EqualFold(rec.Verdict, "continue") {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, rec.Time); err != nil || ts.Before(cutoff) {
			continue
		}
		if sessionFilter != "" && !strings.HasPrefix(rec.SessionID, sessionFilter) {
			continue
		}
		if limit > 0 && res.total >= limit {
			break
		}

		res.total++
		out := eng.Decide(engine.Input{
			ToolName:    rec.ToolName,
			Command:     rec.Command,
			Description: rec.Description,
			CWD:         rec.CWD,
			SessionID:   rec.SessionID,
			ToolUseID:   rec.ToolUseID,
			AgentID:     rec.AgentID,
			AgentType:   rec.AgentType,
		})

		entry := replayEntry{rec: &rec, newTier: out.Tier, newRule: out.Rule}

		switch out.Verdict {
		case engine.Allow:
			res.wouldAllow++
			res.byTier[out.Tier]++
			if len(res.samples) < sampleCap*3 { // collect more, trim later
				res.samples = append(res.samples, entry)
			}
			if verbose {
				fmt.Printf("  ✓ [%-14s] %s\n", out.Tier, truncLong(rec.Command, 80))
			}
		case engine.Deny:
			res.nowDeny++
			res.regressions = append(res.regressions, entry)
			if verbose {
				fmt.Printf("  ! [REGRESSION  ] %s  → deny(%s)\n", truncLong(rec.Command, 70), out.Rule)
			}
		default: // still Continue
			res.stillCont++
			if verbose {
				fmt.Printf("  - [still prompt ] %s\n", truncLong(rec.Command, 80))
			}
		}
	}

	return res
}

func printReplayResult(r replayResult, since time.Duration) {
	fmt.Printf("replay — historical Continue decisions vs current engine (last %s)\n", since)
	fmt.Println("  (global rules + LLM cache only; per-project .claude-guard.yml not applied)")
	fmt.Println()

	if r.total == 0 {
		fmt.Println("  no Continue decisions found in this window")
		fmt.Println("  hint: try --since 30d or check --path")
		return
	}

	improvePct := 0.0
	if r.total > 0 {
		improvePct = float64(r.wouldAllow) / float64(r.total) * 100
	}

	fmt.Printf("  replayed:     %d historical user-prompts\n", r.total)
	fmt.Printf("  would allow:  %d  (%.1f%% improvement — no longer needs user prompt)\n", r.wouldAllow, improvePct)
	fmt.Printf("  still prompt: %d  (%.1f%% — still needs user approval)\n", r.stillCont, float64(r.stillCont)/float64(r.total)*100)
	if r.nowDeny > 0 {
		fmt.Printf("  REGRESSIONS:  %d  (new block rule fires on previously-shown commands!)\n", r.nowDeny)
	}

	if r.wouldAllow > 0 {
		fmt.Println()
		fmt.Println("  tier breakdown (what would handle the newly-auto-approved):")

		type kv struct{ k string; v int }
		tiers := make([]kv, 0, len(r.byTier))
		for k, v := range r.byTier {
			tiers = append(tiers, kv{k, v})
		}
		sort.Slice(tiers, func(i, j int) bool { return tiers[i].v > tiers[j].v })
		for _, t := range tiers {
			pct := float64(t.v) / float64(r.wouldAllow) * 100
			fmt.Printf("    %-22s %4d  (%4.1f%% of improvements)\n", t.k, t.v, pct)
		}
	}

	if len(r.regressions) > 0 {
		fmt.Println()
		fmt.Println("  REGRESSIONS (commands that would now be Denied — review these rules):")
		for i, e := range r.regressions {
			if i >= 10 {
				fmt.Printf("    ... and %d more\n", len(r.regressions)-10)
				break
			}
			fmt.Printf("    rule=%-30s  %s\n", e.newRule, truncLong(e.rec.Command, 70))
		}
	}

	if len(r.samples) > 0 {
		fmt.Println()
		fmt.Println("  sample improvements (commands that would no longer prompt user):")
		seen := map[string]bool{}
		shown := 0
		for _, e := range r.samples {
			key := e.newTier + ":" + truncLong(e.rec.Command, 60)
			if seen[key] || shown >= 12 {
				continue
			}
			seen[key] = true
			shown++
			cmd := truncLong(e.rec.Command, 72)
			fmt.Printf("    ✓ [%-16s] %s\n", e.newTier, cmd)
		}
	}

	fmt.Println()
	if improvePct >= 20 {
		fmt.Printf("  improvement: significant (%.1f%% of historical prompts eliminated)\n", improvePct)
	} else if improvePct >= 5 {
		fmt.Printf("  improvement: moderate (%.1f%%)\n", improvePct)
	} else if improvePct > 0 {
		fmt.Printf("  improvement: small (%.1f%%) — consider adding rules for the still-prompt commands\n", improvePct)
	} else {
		fmt.Println("  improvement: none — historical prompts unchanged by current rule set")
		fmt.Println("  hint: run with --verbose to see what commands still need approval")
	}
}

func defaultCacheRoot() string {
	home, _ := os.UserHomeDir()
	root := home + "/.cache/claude-guard"
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		root = xdg + "/claude-guard"
	}
	return root
}
