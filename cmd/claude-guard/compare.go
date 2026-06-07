package main

// cmdCompare reads decisions.jsonl and compares two time windows side-by-side:
// interrupt rate, tier distribution, latency. Default: last 7 days vs
// the 7 days before that, showing whether recent changes improved things.
//
//	claude-guard compare [--since 14d] [--period 7d]
//
// --since   total window to analyse (default: 14d)
// --period  size of each half (default: since/2)

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
)

func cmdCompare(args []string) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var since, period time.Duration
	var pathOverride string
	fs.DurationVar(&since, "since", 14*24*time.Hour, "total window to analyse (default: 14d)")
	fs.DurationVar(&period, "period", 0, "size of each half (default: since/2)")
	fs.StringVar(&pathOverride, "path", "", "override decisions log path")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if period <= 0 {
		period = since / 2
	}

	cfg := config.Default()
	paths := clog.DefaultPaths(cfg.Log.Dir)
	logPath := paths.Decisions
	if pathOverride != "" {
		logPath = pathOverride
	}

	now := time.Now()
	afterStart := now.Add(-period)   // [afterStart, now]
	beforeStart := now.Add(-since)   // [beforeStart, afterStart)

	before := newAggregation()
	after := newAggregation()

	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare: open %s: %v\n", logPath, err)
		return 1
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		var rec clog.ReadRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Msg == clog.MsgStopHook {
			var sr clog.StopHookRecord
			if err := json.Unmarshal(scanner.Bytes(), &sr); err == nil {
				// Count stop hooks in both windows.
				if ts, err := time.Parse(time.RFC3339Nano, rec.Time); err == nil {
					if ts.After(beforeStart) && ts.Before(afterStart) {
						before.addStopHook(&sr)
					} else if !ts.Before(afterStart) {
						after.addStopHook(&sr)
					}
				}
			}
			continue
		}
		if rec.Msg != clog.MsgDecision {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, rec.Time)
		if err != nil {
			continue
		}
		if ts.After(beforeStart) && ts.Before(afterStart) {
			before.add(&rec)
		} else if !ts.Before(afterStart) && !ts.After(now) {
			after.add(&rec)
		}
	}

	printCompare(before, after, period, since)
	return 0
}

func printCompare(before, after *aggregation, period, since time.Duration) {
	bLabel := fmt.Sprintf("before (-%s–-%s)", formatDur(since), formatDur(period))
	aLabel := fmt.Sprintf("after  (last %s)", formatDur(period))

	fmt.Printf("compare — %s | %s\n\n", bLabel, aLabel)

	if before.total == 0 && after.total == 0 {
		fmt.Println("  no decisions found in either window")
		fmt.Printf("  hint: try --since %s to widen the window\n", formatDur(since*2))
		return
	}

	sep := strings.Repeat("─", 28)
	fmt.Printf("  %-28s  %10s  %10s  %10s\n", "metric", "before", "after", "delta")
	fmt.Printf("  %-28s  %10s  %10s  %10s\n", sep, strings.Repeat("─", 10), strings.Repeat("─", 10), strings.Repeat("─", 10))

	bInterrupt := cmpPct(before.byVerdict["continue"], before.total)
	aInterrupt := cmpPct(after.byVerdict["continue"], after.total)
	bAllow := cmpPct(before.byVerdict["allow"], before.total)
	aAllow := cmpPct(after.byVerdict["allow"], after.total)

	cmpInt("decisions", before.total, after.total, false)
	cmpPctRow("interrupt rate", bInterrupt, aInterrupt, true /* lower = better */)
	cmpPctRow("auto-allow rate", bAllow, aAllow, false /* higher = better */)

	bP50 := percentileMs(before.latencies, 0.50)
	aP50 := percentileMs(after.latencies, 0.50)
	bP95 := percentileMs(before.latencies, 0.95)
	aP95 := percentileMs(after.latencies, 0.95)
	cmpMs("latency p50", bP50, aP50)
	cmpMs("latency p95", bP95, aP95)

	// Tier breakdown.
	allTiers := cmpUnionKeys(before.byTier, after.byTier)
	sort.Slice(allTiers, func(i, j int) bool {
		// Sort by combined count descending so most-active tiers are first.
		return before.byTier[allTiers[i]]+after.byTier[allTiers[i]] >
			before.byTier[allTiers[j]]+after.byTier[allTiers[j]]
	})
	fmt.Println()
	fmt.Printf("  tier breakdown (pct of all decisions):\n")
	fmt.Printf("  %-28s  %10s  %10s  %10s\n", "", "before", "after", "delta")
	for _, tier := range allTiers {
		bp := cmpPct(before.byTier[tier], before.total)
		ap := cmpPct(after.byTier[tier], after.total)
		lowerBetter := tier == "default" || tier == "parse_error"
		cmpPctRow("  "+tier, bp, ap, lowerBetter)
	}

	// Flow / interrupt summary.
	if before.interruptCount+after.interruptCount > 0 {
		fmt.Println()
		cmpInt("user prompts (total)", before.interruptCount, after.interruptCount, true)
		bStr := computeStretches(before)
		aStr := computeStretches(after)
		if len(bStr) > 0 || len(aStr) > 0 {
			bMed := percentileDuration(bStr, 0.50).Minutes()
			aMed := percentileDuration(aStr, 0.50).Minutes()
			delta := aMed - bMed
			arrow := ""
			if delta > 0.5 {
				arrow = " ↑"
			} else if delta < -0.5 {
				arrow = " ↓"
			}
			fmt.Printf("  %-28s  %9.1fm  %9.1fm  %+.1fm%s\n",
				"uninterrupted stretch p50", bMed, aMed, delta, arrow)
		}
	}

	// Stop hook summary.
	if before.stopTotal+after.stopTotal > 0 {
		fmt.Println()
		cmpInt("stop hook evaluations", before.stopTotal, after.stopTotal, false)
		cmpInt("stop hook injections", before.stopInjected, after.stopInjected, false)
	}

	// Guidance line.
	fmt.Println()
	delta := aInterrupt - bInterrupt
	switch {
	case delta < -5:
		fmt.Printf("  ✓ interrupt rate dropped %.1fpp — rule/session changes are working\n", -delta)
	case delta < -1:
		fmt.Printf("  ~ interrupt rate dropped %.1fpp — small improvement\n", -delta)
	case math.Abs(delta) <= 1:
		fmt.Println("  = interrupt rate essentially unchanged between windows")
	case delta < 5:
		fmt.Printf("  ~ interrupt rate rose %.1fpp — slight regression, worth investigating\n", delta)
	default:
		fmt.Printf("  ! interrupt rate rose %.1fpp — run 'replay' to identify causes\n", delta)
	}
}

// ─── formatting helpers ──────────────────────────────────────────────────────

func cmpPct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func cmpInt(label string, before, after int, lowerBetter bool) {
	delta := after - before
	sign := ""
	if delta > 0 {
		sign = "+"
	}
	arrow := ""
	if delta != 0 {
		if (lowerBetter && delta < 0) || (!lowerBetter && delta > 0) {
			arrow = " ↑"
		} else {
			arrow = " ↓"
		}
	}
	fmt.Printf("  %-28s  %10d  %10d  %s%d%s\n", label, before, after, sign, delta, arrow)
}

func cmpPctRow(label string, before, after float64, lowerBetter bool) {
	delta := after - before
	arrow := ""
	if math.Abs(delta) > 0.05 {
		if (lowerBetter && delta < 0) || (!lowerBetter && delta > 0) {
			arrow = " ↑"
		} else {
			arrow = " ↓"
		}
	}
	sign := ""
	if delta > 0 {
		sign = "+"
	}
	deltaStr := fmt.Sprintf("%s%.1fpp%s", sign, delta, arrow)
	if math.Abs(delta) <= 0.05 {
		deltaStr = "  ±0pp"
	}
	fmt.Printf("  %-28s  %9.1f%%  %9.1f%%  %s\n", label, before, after, deltaStr)
}

func cmpMs(label string, before, after float64) {
	delta := after - before
	arrow := ""
	if math.Abs(delta) > 0.1 {
		if delta < 0 {
			arrow = " ↑" // lower latency = better
		} else {
			arrow = " ↓"
		}
	}
	fmt.Printf("  %-28s  %9.1fms  %9.1fms  %+.1fms%s\n", label, before, after, delta, arrow)
}

func formatDur(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days >= 1 {
		return fmt.Sprintf("%dd", days)
	}
	hours := int(d.Hours())
	if hours >= 1 {
		return fmt.Sprintf("%dh", hours)
	}
	return d.String()
}

func cmpUnionKeys(a, b map[string]int) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}
