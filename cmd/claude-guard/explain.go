package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	clog "github.com/RobinUS2/claude-guard/internal/log"
)

// cmdExplain looks up a historical decision by tool_use_id (or by a
// partial prefix match on the id), then prints the original verdict
// alongside what the current engine would decide for the same command
// today. Useful when rule changes are suspected of changing behavior.
//
//	claude-guard explain <tool-use-id>
//	claude-guard explain --last    # most recent decision
//	claude-guard explain --verdict=deny --last 5    # last 5 denies
func cmdExplain(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var count int
	var verdict string
	var lastBool bool
	var lastN int
	// `--last` with no value defaults to 1; `-n N` is a separate opt to
	// show N records when combined with --last or a verdict filter.
	fs.BoolVar(&lastBool, "last", false, "show the most recent entry (use -n N for more)")
	fs.IntVar(&lastN, "last-n", 0, "alias for --last -n N: show the last N entries")
	fs.IntVar(&count, "n", 1, "limit on the number of entries to explain (default: 1)")
	fs.StringVar(&verdict, "verdict", "", "filter by verdict (allow|deny|continue)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	idPrefix := ""
	if fs.NArg() > 0 {
		idPrefix = fs.Arg(0)
	}
	last := lastBool || lastN > 0
	if idPrefix == "" && !last {
		fmt.Fprintln(os.Stderr, "usage: claude-guard explain <tool-use-id> | --last [-n N] | --last-n N")
		return 2
	}
	if lastN > 0 {
		count = lastN
	}

	cfg := config.Default()
	// config.Default always sets Log.Dir via DefaultLogDir; no fallback needed.
	paths := clog.DefaultPaths(cfg.Log.Dir)
	recs, err := findDecisions(paths.Decisions, idPrefix, verdict, count)
	if err != nil {
		fmt.Fprintf(os.Stderr, "explain: %v\n", err)
		return 1
	}
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "explain: no matching decisions found")
		return 1
	}

	// Build an engine with the CURRENT config (no LLM, no cache, no
	// breaker — just the deterministic tiers) so we can compare the
	// historical verdict to what today's rules would say.
	legacyList, _ := legacy.Load(defaultLegacyPath())
	eng := engine.NewWithOptions(engine.Options{
		Config: cfg,
		Legacy: legacyList,
	})

	for i, rec := range recs {
		if i > 0 {
			fmt.Println()
		}
		printExplainRecord(rec, eng)
	}
	return 0
}

func printExplainRecord(rec *clog.ReadRecord, eng *engine.Engine) {
	fmt.Printf("=== %s ===\n", rec.ToolUseID)
	fmt.Printf("when:    %s\n", rec.Time)
	fmt.Printf("cwd:     %s\n", rec.CWD)
	if rec.SessionID != "" {
		fmt.Printf("session: %s\n", rec.SessionID)
	}
	if rec.AgentType != "" {
		fmt.Printf("agent:   %s (%s)\n", rec.AgentType, rec.AgentID)
	}
	fmt.Printf("command: %s\n", truncLong(rec.Command, 160))
	if rec.Description != "" {
		fmt.Printf("intent:  %s\n", truncLong(rec.Description, 160))
	}

	fmt.Println()
	fmt.Println("ORIGINAL decision (at the time of the call):")
	fmt.Printf("  verdict: %s\n", rec.Verdict)
	fmt.Printf("  tier:    %s\n", rec.Tier)
	if rec.Rule != "" {
		fmt.Printf("  rule:    %s\n", rec.Rule)
	}
	if rec.Reason != "" {
		fmt.Printf("  reason:  %s\n", truncLong(rec.Reason, 240))
	}
	if rec.LatencyUS > 0 {
		fmt.Printf("  latency: %.1fms\n", float64(rec.LatencyUS)/1000.0)
	}

	fmt.Println()
	fmt.Println("NOW (re-evaluated against current deterministic rules):")
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
	fmt.Printf("  verdict: %s\n", out.Verdict)
	fmt.Printf("  tier:    %s\n", out.Tier)
	if out.Rule != "" {
		fmt.Printf("  rule:    %s\n", out.Rule)
	}
	if out.Reason != "" {
		fmt.Printf("  reason:  %s\n", truncLong(out.Reason, 240))
	}
	fmt.Printf("  latency: %s\n", out.Latency)

	if string(out.Verdict) != rec.Verdict {
		fmt.Printf("\n!  VERDICT CHANGED: %s -> %s\n", rec.Verdict, out.Verdict)
		fmt.Println("   (NOTE: a cached LLM allow from a previous rule set can mask a")
		fmt.Println("    new deterministic verdict on the hot path. tier 1 blocks always")
		fmt.Println("    override the cache, but allow-rule changes and LLM re-classifications")
		fmt.Println("    require cache eviction to take effect immediately.)")
	}
}

// findDecisions streams the decisions log and returns up to `limit`
// matching ReadRecords. Supports prefix match on tool_use_id and an
// optional verdict filter.
//
// When idPrefix is set, returns matches in file order (earliest first).
// When idPrefix is empty, returns the LAST `limit` matching entries
// (newest first) via an in-memory ring buffer of size `limit` — so a
// huge decisions.jsonl doesn't balloon memory for `explain --last`.
func findDecisions(path, idPrefix, verdict string, limit int) ([]*clog.ReadRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)

	// Prefix-match path: keep all matches (typically 1-few records).
	if idPrefix != "" {
		var matches []*clog.ReadRecord
		for scanner.Scan() {
			var rec clog.ReadRecord
			if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
				continue
			}
			if rec.Msg != clog.MsgDecision {
				continue
			}
			if verdict != "" && rec.Verdict != verdict {
				continue
			}
			if !strings.HasPrefix(rec.ToolUseID, idPrefix) {
				continue
			}
			matches = append(matches, &rec)
			if limit > 0 && len(matches) >= limit {
				break
			}
		}
		return matches, nil
	}

	// Last-N path: ring buffer sized to `limit` (default 1). Avoids
	// reading the full log into memory on large decisions.jsonl files.
	if limit <= 0 {
		limit = 1
	}
	ring := make([]*clog.ReadRecord, limit)
	var count, pos int
	for scanner.Scan() {
		var rec clog.ReadRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Msg != clog.MsgDecision {
			continue
		}
		if verdict != "" && rec.Verdict != verdict {
			continue
		}
		ring[pos] = &rec
		pos = (pos + 1) % limit
		count++
	}
	// Extract ring in chronological order (oldest-first) then reverse
	// to get newest-first.
	out := make([]*clog.ReadRecord, 0, min(count, limit))
	start := pos
	if count < limit {
		start = 0
	}
	for i := 0; i < min(count, limit); i++ {
		idx := (start + i) % limit
		if ring[idx] != nil {
			out = append(out, ring[idx])
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncLong(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
