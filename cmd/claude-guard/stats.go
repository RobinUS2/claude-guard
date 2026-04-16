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
	fs.DurationVar(&since, "since", 24*time.Hour, "only consider log entries from the last N (e.g. 24h, 7d)")
	fs.StringVar(&pathOverride, "path", "", "override the decisions log path")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := config.Default()
	// config.Default always sets Log.Dir via DefaultLogDir; no fallback needed.
	paths := clog.DefaultPaths(cfg.Log.Dir)
	path := paths.Decisions
	if pathOverride != "" {
		path = pathOverride
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
}

func newAggregation() *aggregation {
	return &aggregation{
		byVerdict:     map[string]int{},
		byTier:        map[string]int{},
		byTier4Shadow: map[string]int{},
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
