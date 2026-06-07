package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/store"
)

// cmdStats prints an aggregate summary of decisions.jsonl plus cache
// health. Zero network calls — pure file read and aggregation.
//
//	claude-guard stats [--since 24h] [--path decisions.jsonl]
func cmdStats(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var since time.Duration
	var pathOverride string
	var record, history, bySession bool
	fs.DurationVar(&since, "since", 24*time.Hour, "only consider log entries from the last N (e.g. 24h, 7d)")
	fs.StringVar(&pathOverride, "path", "", "override the decisions log path")
	fs.BoolVar(&record, "record", false, "write a metrics snapshot to SQLite")
	fs.BoolVar(&history, "history", false, "show metrics trend over time")
	fs.BoolVar(&bySession, "by-session", false, "show per-session interrupt rate breakdown")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// --history: show trend table and exit early.
	if history {
		return showHistory()
	}

	cfg := config.Default()
	// config.Default always sets Log.Dir via DefaultLogDir; no fallback needed.
	paths := clog.DefaultPaths(cfg.Log.Dir)
	path := paths.Decisions
	if pathOverride != "" {
		path = pathOverride
	}

	// --by-session: group by session and show interrupt rate per session.
	if bySession {
		return showBySession(path, since)
	}

	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats: cannot read %s: %v\n", path, err)
		return 1
	}
	defer f.Close()

	cutoff := time.Now().Add(-since)
	agg := newAggregation()
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
				agg.addStopHook(&sr)
			}
			continue
		}
		if rec.Msg != clog.MsgDecision {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, rec.Time); err == nil {
			if ts.Before(cutoff) {
				continue
			}
		}
		agg.add(&rec)
	}

	fmt.Printf("decisions stats (last %s)\n", since)
	fmt.Printf("source: %s\n\n", path)

	fmt.Printf("total decisions: %d\n", agg.total)
	if agg.total == 0 {
		fmt.Println("(no entries in window)")
		return 0
	}

	fmt.Println()
	fmt.Println("verdicts:")
	printCounts(agg.byVerdict, agg.total)

	fmt.Println()
	fmt.Println("tiers:")
	printCounts(agg.byTier, agg.total)

	if len(agg.byTier4Shadow) > 0 {
		fmt.Println()
		fmt.Println("tier 4 (LLM) shadow trace:")
		printCounts(agg.byTier4Shadow, agg.total)
	}

	fmt.Println()
	fmt.Printf("latency (ms): p50=%.1f  p95=%.1f  p99=%.1f  max=%.1f\n",
		percentileMs(agg.latencies, 0.50),
		percentileMs(agg.latencies, 0.95),
		percentileMs(agg.latencies, 0.99),
		percentileMs(agg.latencies, 1.00),
	)

	// Cache stats
	home, _ := os.UserHomeDir()
	cacheDir := filepath.Join(home, ".cache", "claude-guard", "verdicts")
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		cacheDir = filepath.Join(xdg, "claude-guard", "verdicts")
	}
	cch := cache.New(cacheDir)
	if cs, err := cch.Stats(); err == nil && cs.Entries > 0 {
		fmt.Println()
		fmt.Printf("cache:       %d entries, %s on disk, %d shards\n",
			cs.Entries, humanBytes(cs.BytesOnDisk), cs.Shards)
		fmt.Printf("             verified=%d pending=%d disagreements=%d expired=%d\n",
			cs.Verified, cs.Entries-cs.Verified, cs.Disagree, cs.ExpiredHits)
	}

	// Cache hit rate (cache tier vs LLM tier)
	cacheHits := agg.byTier["cache"]
	llmHits := agg.byTier["llm"]
	if cacheHits+llmHits > 0 {
		rate := float64(cacheHits) / float64(cacheHits+llmHits) * 100
		fmt.Printf("cache hit:   %d / %d LLM-eligible = %.1f%% hit rate\n",
			cacheHits, cacheHits+llmHits, rate)
	}

	// Stop hook evaluation summary.
	if agg.stopTotal > 0 {
		fmt.Println()
		fmt.Println("stop hooks:")
		fmt.Printf("  evaluations: %d\n", agg.stopTotal)
		fmt.Printf("  continues injected: %d (%.1f%%)\n",
			agg.stopInjected, float64(agg.stopInjected)/float64(agg.stopTotal)*100)
		if agg.stopCapped > 0 {
			fmt.Printf("  max-continue cap hit: %d\n", agg.stopCapped)
		}
		if len(agg.stopByRule) > 0 {
			parts := make([]string, 0, len(agg.stopByRule))
			for rule, n := range agg.stopByRule {
				parts = append(parts, fmt.Sprintf("%s=%d", rule, n))
			}
			fmt.Printf("  top rules: %s\n", strings.Join(parts, "  "))
		}
	}

	// Time saved estimate.
	avoided, savedMin := computeTimeSaved(agg)
	fmt.Println()
	fmt.Printf("interrupts avoided: %d (est. ~%d min / ~%.1f h saved)\n",
		avoided, savedMin, float64(savedMin)/60.0)
	fmt.Printf("  heuristic: %d min per avoided user-prompt\n", minutesPerInterruptAvoided)

	// Canonical breakdown: how many cache hits went through canonical
	// patterns vs exact entries, and which programs benefit the most.
	if cs, err := cch.Stats(); err == nil && cs.Entries > 0 {
		canonicalEntries, programHits := canonicalSummary(cacheDir)
		if canonicalEntries > 0 {
			fmt.Println()
			fmt.Printf("canonical:   %d canonical entries (of %d total cache entries)\n",
				canonicalEntries, cs.Entries)
			if len(programHits) > 0 {
				fmt.Println("             per-program match counts:")
				// Sort programs by match count, descending.
				type pHit struct {
					program string
					count   int
				}
				list := make([]pHit, 0, len(programHits))
				for p, n := range programHits {
					list = append(list, pHit{p, n})
				}
				sort.Slice(list, func(i, j int) bool {
					if list[i].count != list[j].count {
						return list[i].count > list[j].count
					}
					return list[i].program < list[j].program
				})
				for _, p := range list {
					fmt.Printf("               %-18s %d command%s\n", p.program, p.count, pluralS(p.count))
				}
			}
		}
	}

	// Flow metrics: uninterrupted stretches and interrupt breakdown.
	stretches := computeStretches(agg)
	learnedPatterns, autoAllows := countLearnedFromStore()
	if len(stretches) > 0 || agg.interruptCount > 0 {
		fmt.Println()
		fmt.Printf("flow metrics (last %s):\n", since)
		if len(stretches) > 0 {
			fmt.Println("  uninterrupted stretches:")
			fmt.Printf("    median:  %s\n", formatDuration(percentileDuration(stretches, 0.50)))
			fmt.Printf("    p95:     %s\n", formatDuration(percentileDuration(stretches, 0.95)))
			fmt.Printf("    longest: %s\n", formatDuration(percentileDuration(stretches, 1.00)))
		}
		userApproved := agg.interruptCount
		unanswered := 0
		if learnedPatterns > 0 && userApproved > learnedPatterns {
			unanswered = userApproved - learnedPatterns
			userApproved = learnedPatterns
		}
		fmt.Printf("  human interrupts: %d (user-approved: %d, unanswered: %d)\n",
			agg.interruptCount, userApproved, unanswered)
		fmt.Printf("  learned patterns: %d (auto-allows from learning: %d)\n",
			learnedPatterns, autoAllows)
	}

	// --record: write a metrics snapshot to SQLite.
	if record {
		medianS := 0.0
		p95S := 0.0
		if len(stretches) > 0 {
			medianS = percentileDuration(stretches, 0.50).Seconds()
			p95S = percentileDuration(stretches, 0.95).Seconds()
		}
		snap := store.MetricsSnapshot{
			PeriodHours:         int(since.Hours()),
			TotalDecisions:      agg.total,
			AllowCount:          agg.byVerdict["allow"],
			ContinueCount:       agg.byVerdict["continue"],
			DenyCount:           agg.byVerdict["deny"],
			LearnedAllows:       autoAllows,
			StopHookEvals:       agg.stopTotal,
			StopHookFires:       agg.stopInjected,
			Interrupts:          agg.interruptCount,
			UserApproved:        agg.interruptCount, // best estimate
			MedianUninterrupted: medianS,
			P95Uninterrupted:    p95S,
			LearnedPatterns:     learnedPatterns,
		}
		dbPath := defaultStorePath()
		db, err := store.Open(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stats: cannot open store: %v\n", err)
		} else {
			if err := db.RecordMetrics(snap); err != nil {
				fmt.Fprintf(os.Stderr, "stats: record metrics: %v\n", err)
			} else {
				fmt.Println()
				fmt.Println("(snapshot recorded to SQLite)")
			}
			db.Close()
		}
	}

	return 0
}

// canonicalSummary walks the verdict cache and returns (numCanonicalEntries,
// programHitCounts). programHitCounts maps program name to total MatchCount
// summed across canonical entries for that program.
func canonicalSummary(cacheDir string) (int, map[string]int) {
	hits := map[string]int{}
	entries := 0
	_ = filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var e cache.Entry
		if err := json.Unmarshal(data, &e); err != nil {
			return nil
		}
		if e.CanonicalForm == "" {
			return nil
		}
		entries++
		if e.Program != "" {
			hits[e.Program] += e.MatchCount
			if e.MatchCount == 0 {
				hits[e.Program]++ // count the canonical itself
			}
		}
		return nil
	})
	return entries, hits
}

const minutesPerInterruptAvoided = 3

// computeTimeSaved counts how many user-prompt interrupts were avoided and
// estimates wall-clock time saved. An interrupt is "avoided" when the engine
// resolved the decision automatically (instant_allow, cache, bq_preflight, or
// llm tier with an "allow" verdict). Tiers that fall through to the user
// prompt (verdict=continue, tier=default) are counted as interrupts NOT avoided.
func computeTimeSaved(agg *aggregation) (interruptsAvoided, minutesSaved int) {
	// Automated allow paths: instant_allow, cache (LLM already approved),
	// bq_preflight (pre-flight within budget), llm (LLM approved in real-time).
	for _, tier := range []string{"instant_allow", "cache", "bq_preflight", "llm"} {
		interruptsAvoided += agg.byTier[tier]
	}
	// Also count the legacy tier (migrated allow list — still automated).
	interruptsAvoided += agg.byTier["legacy"]
	minutesSaved = interruptsAvoided * minutesPerInterruptAvoided
	return
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// aggregation holds counters while walking the log.
type aggregation struct {
	total         int
	byVerdict     map[string]int
	byTier        map[string]int
	byTier4Shadow map[string]int
	latencies     []float64 // milliseconds

	// stop_hook event counters
	stopTotal    int
	stopInjected int
	stopCapped   int
	stopByRule   map[string]int

	// flow metrics: interrupt tracking per session
	interruptTimes map[string][]time.Time // session_id → list of Continue timestamps
	interruptCount int                    // total Continue verdicts

	// session boundaries: first and last event per session
	sessionFirst map[string]time.Time
	sessionLast  map[string]time.Time
}

func newAggregation() *aggregation {
	return &aggregation{
		byVerdict:      map[string]int{},
		byTier:         map[string]int{},
		byTier4Shadow:  map[string]int{},
		stopByRule:     map[string]int{},
		interruptTimes: map[string][]time.Time{},
		sessionFirst:   map[string]time.Time{},
		sessionLast:    map[string]time.Time{},
	}
}

func (a *aggregation) addStopHook(rec *clog.StopHookRecord) {
	a.stopTotal++
	if rec.Injected {
		a.stopInjected++
		if rec.FiredRule != "" {
			a.stopByRule[rec.FiredRule]++
		}
	}
	if rec.Suppressed == "max_continues_reached" {
		a.stopCapped++
	}
}

func (a *aggregation) add(rec *clog.ReadRecord) {
	a.total++
	a.byVerdict[rec.Verdict]++
	a.byTier[rec.Tier]++
	if rec.Shadow != nil {
		// Pick the most informative tier 4 field.
		if rec.Shadow.Tier4LLM != "" {
			a.byTier4Shadow[rec.Shadow.Tier4LLM]++
		}
	}
	a.latencies = append(a.latencies, float64(rec.LatencyUS)/1000.0)

	// Track flow metrics: interrupt times and session boundaries.
	ts, err := time.Parse(time.RFC3339Nano, rec.Time)
	if err != nil {
		return
	}
	sid := rec.SessionID
	if sid == "" {
		return
	}

	// Update session boundaries.
	if first, ok := a.sessionFirst[sid]; !ok || ts.Before(first) {
		a.sessionFirst[sid] = ts
	}
	if last, ok := a.sessionLast[sid]; !ok || ts.After(last) {
		a.sessionLast[sid] = ts
	}

	// Track Continue verdicts as human interrupts.
	if strings.EqualFold(rec.Verdict, "continue") {
		a.interruptCount++
		a.interruptTimes[sid] = append(a.interruptTimes[sid], ts)
	}
}

// printCounts prints a sorted table of (name, count, pct%).
func printCounts(m map[string]int, total int) {
	type kv struct {
		k string
		v int
	}
	entries := make([]kv, 0, len(m))
	for k, v := range m {
		entries = append(entries, kv{k, v})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].v != entries[j].v {
			return entries[i].v > entries[j].v
		}
		return entries[i].k < entries[j].k
	})
	for _, e := range entries {
		pct := float64(e.v) / float64(total) * 100
		fmt.Printf("  %-32s %6d  %5.1f%%\n", e.k, e.v, pct)
	}
}

// percentileMs returns the p-th percentile of the sorted latencies in ms.
func percentileMs(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	idx := int(float64(len(sorted)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// computeStretches calculates uninterrupted time stretches from the
// aggregation's per-session interrupt times. Within each session it
// measures the gap between consecutive Continue verdicts, plus the gap
// from session start to the first Continue and from the last Continue
// to session end.
func computeStretches(agg *aggregation) []time.Duration {
	var stretches []time.Duration
	for sid, times := range agg.interruptTimes {
		if len(times) == 0 {
			continue
		}
		sorted := make([]time.Time, len(times))
		copy(sorted, times)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

		// Gap from session start to first interrupt.
		if start, ok := agg.sessionFirst[sid]; ok && sorted[0].After(start) {
			stretches = append(stretches, sorted[0].Sub(start))
		}

		// Gaps between consecutive interrupts.
		for i := 1; i < len(sorted); i++ {
			d := sorted[i].Sub(sorted[i-1])
			if d > 0 {
				stretches = append(stretches, d)
			}
		}

		// Gap from last interrupt to session end.
		if end, ok := agg.sessionLast[sid]; ok && end.After(sorted[len(sorted)-1]) {
			stretches = append(stretches, end.Sub(sorted[len(sorted)-1]))
		}
	}

	// Also add full-session stretches for sessions with zero interrupts.
	for sid, start := range agg.sessionFirst {
		if _, hasInterrupts := agg.interruptTimes[sid]; hasInterrupts {
			continue
		}
		if end, ok := agg.sessionLast[sid]; ok && end.After(start) {
			stretches = append(stretches, end.Sub(start))
		}
	}

	return stretches
}

// percentileDuration returns the p-th percentile from a slice of
// durations. Returns 0 for empty input.
func percentileDuration(values []time.Duration, p float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// formatDuration produces human-readable durations like "12m 30s",
// "2h 15m", "45s". Returns "0s" for zero duration.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Round(time.Second)

	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh %02dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh 00m", h)
	case m > 0 && s > 0:
		return fmt.Sprintf("%dm %02ds", m, s)
	case m > 0:
		return fmt.Sprintf("%dm 00s", m)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// countLearnedFromStore queries the SQLite store for learned patterns
// and their cumulative auto-allow match counts. Returns (patterns, autoAllows).
func countLearnedFromStore() (int, int) {
	dbPath := defaultStorePath()
	db, err := store.Open(dbPath)
	if err != nil {
		return 0, 0
	}
	defer db.Close()

	patterns, autoAllows, err := db.LearnedStats()
	if err != nil {
		return 0, 0
	}
	return patterns, autoAllows
}

// showBySession reads decisions.jsonl and prints per-session interrupt rates.
// This is Phase 0 baseline measurement: see how often each session falls
// through to a user prompt (Continue verdict) vs auto-approving.
func showBySession(logPath string, since time.Duration) int {
	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats: cannot read %s: %v\n", logPath, err)
		return 1
	}
	defer f.Close()

	type sessionData struct {
		total     int
		continues int // human interrupts (verdict=continue, tier=default)
		allows    int
		first     time.Time
		last      time.Time
	}
	sessions := map[string]*sessionData{}
	cutoff := time.Now().Add(-since)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		var rec clog.ReadRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil || rec.Msg != clog.MsgDecision {
			continue
		}
		if rec.SessionID == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, rec.Time)
		if err != nil || ts.Before(cutoff) {
			continue
		}
		sd := sessions[rec.SessionID]
		if sd == nil {
			sd = &sessionData{}
			sessions[rec.SessionID] = sd
		}
		sd.total++
		if strings.EqualFold(rec.Verdict, "continue") {
			sd.continues++
		} else if strings.EqualFold(rec.Verdict, "allow") {
			sd.allows++
		}
		if sd.first.IsZero() || ts.Before(sd.first) {
			sd.first = ts
		}
		if sd.last.IsZero() || ts.After(sd.last) {
			sd.last = ts
		}
	}

	if len(sessions) == 0 {
		fmt.Println("no session data in the given window")
		return 0
	}

	type sessionRow struct {
		id        string
		data      *sessionData
		interruptPct float64
	}
	rows := make([]sessionRow, 0, len(sessions))
	for id, sd := range sessions {
		pct := 0.0
		if sd.total > 0 {
			pct = float64(sd.continues) / float64(sd.total) * 100
		}
		rows = append(rows, sessionRow{id: id, data: sd, interruptPct: pct})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].data.first.After(rows[j].data.first) // newest first
	})

	fmt.Printf("per-session interrupt rate (last %s)\n\n", since)
	fmt.Printf("  %-14s  %-19s  %6s  %7s  %7s  %9s\n",
		"session", "started", "total", "allows", "prompts", "interrupt%")
	fmt.Printf("  %-14s  %-19s  %6s  %7s  %7s  %9s\n",
		"──────────────", "───────────────────", "──────", "───────", "───────", "─────────")
	totalContinues, totalDecisions := 0, 0
	for _, row := range rows {
		shortID := row.id
		if len(shortID) > 14 {
			shortID = shortID[:14]
		}
		fmt.Printf("  %-14s  %-19s  %6d  %7d  %7d  %8.1f%%\n",
			shortID,
			row.data.first.Format("2006-01-02 15:04"),
			row.data.total,
			row.data.allows,
			row.data.continues,
			row.interruptPct,
		)
		totalContinues += row.data.continues
		totalDecisions += row.data.total
	}
	avgPct := 0.0
	if totalDecisions > 0 {
		avgPct = float64(totalContinues) / float64(totalDecisions) * 100
	}
	fmt.Printf("\n  baseline interrupt rate: %.1f%% across %d sessions (%d/%d decisions prompted user)\n",
		avgPct, len(rows), totalContinues, totalDecisions)
	return 0
}

// showHistory prints a trend table from SQLite metrics_snapshots.
func showHistory() int {
	dbPath := defaultStorePath()
	db, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats: cannot open store: %v\n", err)
		return 1
	}
	defer db.Close()

	snapshots, err := db.GetMetricsHistory(30)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats: query history: %v\n", err)
		return 1
	}

	if len(snapshots) == 0 {
		fmt.Println("trend (last 30 days): no snapshots recorded")
		fmt.Println("  hint: run 'claude-guard stats --record' to capture a snapshot")
		return 0
	}

	fmt.Println("trend (last 30 days):")
	fmt.Printf("  %-12s %10s %7s %11s %8s %11s\n",
		"date", "decisions", "allow%", "interrupts", "learned", "stop-fires")
	for _, s := range snapshots {
		allowPct := 0.0
		if s.TotalDecisions > 0 {
			allowPct = float64(s.AllowCount) / float64(s.TotalDecisions) * 100
		}
		fmt.Printf("  %-12s %10d %6.1f%% %11d %8d %11d\n",
			s.RecordedAt.Format("2006-01-02"),
			s.TotalDecisions,
			allowPct,
			s.Interrupts,
			s.LearnedPatterns,
			s.StopHookFires,
		)
	}
	return 0
}
