package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
)

const cacheUsage = `claude-guard cache — inspect and prune the verdict cache

Usage:
  claude-guard cache <subcommand> [flags]

Subcommands:
  stats                        detailed cache health
  inspect [flags]              search and display full cache entries
  prune [flags]                selectively delete entries
  clear --force                wipe the entire cache

Inspect flags:
  --match <substring>          command text contains substring (case-sensitive)
  --disagreements              only entries where the verifier disagreed
  --unverified                 only entries not yet verified
  --verdict <allow|deny>       effective verdict equals this
  --limit <N>                  max entries to display (default 20)
  --json                       output raw JSON entries

Prune flags (combine with AND — entries must match every filter given):
  --dry-run                    print matches, don't delete
  --expired                    entries past their TTL (default when no other filter)
  --older-than <duration>      entries stored more than N ago (e.g. 30m, 2h, 7d, 1w)
  --match <substring>          command text contains substring (case-sensitive)
  --verdict <allow|deny>       effective verdict equals this
  --disagreements              entries where the verifier disagreed
  --corrupt                    entries whose JSON failed to parse (always deleted, no opt-in needed)

Examples:
  claude-guard cache stats
  claude-guard cache inspect                            # show all entries (limit 20)
  claude-guard cache inspect --disagreements            # verifier disagreements
  claude-guard cache inspect --match "curl" --json      # curl entries as JSON
  claude-guard cache inspect --unverified               # entries awaiting verification
  claude-guard cache prune                              # default: expired entries
  claude-guard cache prune --older-than 30d --dry-run
  claude-guard cache prune --match "Google Chrome" --dry-run
  claude-guard cache prune --disagreements
  claude-guard cache clear --force
`

// cmdCache dispatches cache subcommands.
func cmdCache(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, cacheUsage)
		return 2
	}
	switch args[0] {
	case "stats":
		return cacheStatsCmd(args[1:])
	case "inspect":
		return cacheInspectCmd(args[1:])
	case "prune":
		return cachePruneCmd(args[1:])
	case "clear":
		return cacheClearCmd(args[1:])
	case "help", "-h", "--help":
		fmt.Print(cacheUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "cache: unknown subcommand %q\n\n", args[0])
		fmt.Fprint(os.Stderr, cacheUsage)
		return 2
	}
}

func cacheStatsCmd(args []string) int {
	fs := flag.NewFlagSet("cache stats", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	dir := cacheDirForOps()
	cch := cache.New(dir)
	cs, err := cch.Stats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cache stats: %v\n", err)
		return 1
	}

	fmt.Printf("cache dir:   %s\n", dir)
	fmt.Printf("entries:     %d\n", cs.Entries)
	fmt.Printf("size:        %s across %d shard%s\n", humanBytes(cs.BytesOnDisk), cs.Shards, pluralS(cs.Shards))
	if cs.Entries == 0 {
		return 0
	}
	fmt.Printf("verified:    %d (%d pending)\n", cs.Verified, cs.Entries-cs.Verified)
	fmt.Printf("disagree:    %d\n", cs.Disagree)
	fmt.Printf("expired:     %d\n", cs.ExpiredHits)
	if !cs.Oldest.IsZero() {
		fmt.Printf("oldest:      %s (%s ago)\n",
			cs.Oldest.Format(time.RFC3339), time.Since(cs.Oldest).Round(time.Minute))
	}
	if !cs.Newest.IsZero() {
		fmt.Printf("newest:      %s (%s ago)\n",
			cs.Newest.Format(time.RFC3339), time.Since(cs.Newest).Round(time.Second))
	}

	breakdown, err := walkCacheBreakdown(dir)
	if err == nil && breakdown != nil {
		fmt.Println()
		fmt.Println("verdicts:")
		for _, v := range sortedStringKeys(breakdown.byVerdict) {
			fmt.Printf("  %-16s %d\n", v, breakdown.byVerdict[v])
		}
		if len(breakdown.byProgram) > 0 {
			fmt.Println()
			fmt.Println("top programs (by entry count):")
			type kv struct {
				k string
				v int
			}
			list := make([]kv, 0, len(breakdown.byProgram))
			for k, v := range breakdown.byProgram {
				list = append(list, kv{k, v})
			}
			sort.Slice(list, func(i, j int) bool {
				if list[i].v != list[j].v {
					return list[i].v > list[j].v
				}
				return list[i].k < list[j].k
			})
			n := len(list)
			if n > 10 {
				n = 10
			}
			for _, e := range list[:n] {
				fmt.Printf("  %-20s %d\n", e.k, e.v)
			}
		}
	}
	return 0
}

func cacheInspectCmd(args []string) int {
	fs := flag.NewFlagSet("cache inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		matchSub     string
		onlyDisagree bool
		onlyUnverif  bool
		verdictStr   string
		limit        int
		asJSON       bool
	)
	fs.StringVar(&matchSub, "match", "", "command text contains substring")
	fs.BoolVar(&onlyDisagree, "disagreements", false, "only verifier disagreements")
	fs.BoolVar(&onlyUnverif, "unverified", false, "only unverified entries")
	fs.StringVar(&verdictStr, "verdict", "", "effective verdict (allow or deny)")
	fs.IntVar(&limit, "limit", 20, "max entries to display")
	fs.BoolVar(&asJSON, "json", false, "output raw JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if verdictStr != "" && verdictStr != "allow" && verdictStr != "deny" {
		fmt.Fprintf(os.Stderr, "cache inspect: --verdict must be allow or deny, got %q\n", verdictStr)
		return 2
	}

	dir := cacheDirForOps()
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Println("cache dir does not exist; nothing to inspect")
		return 0
	}

	now := time.Now()
	shown := 0

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		if shown >= limit {
			return filepath.SkipAll
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var e cache.Entry
		if json.Unmarshal(data, &e) != nil {
			return nil
		}
		if e.Expired(now) {
			return nil
		}

		// Apply filters (AND).
		if matchSub != "" && !strings.Contains(e.Command, matchSub) {
			return nil
		}
		if onlyDisagree && !e.Disagreement {
			return nil
		}
		if onlyUnverif && e.Verified {
			return nil
		}
		if verdictStr != "" && string(e.EffectiveVerdict()) != verdictStr {
			return nil
		}

		shown++
		if asJSON {
			fmt.Println(string(data))
			return nil
		}

		// Human-readable display.
		fmt.Printf("─── entry %d ───\n", shown)
		fmt.Printf("command:    %s\n", truncateInline(e.Command, 120))
		fmt.Printf("verdict:    %s", e.Verdict)
		if e.EffectiveVerdict() != e.Verdict {
			fmt.Printf(" → %s (overridden by verifier)", e.EffectiveVerdict())
		}
		fmt.Println()
		fmt.Printf("tier:       %s\n", e.Tier)
		if e.Reason != "" {
			fmt.Printf("reason:     %s\n", e.Reason)
		}
		fmt.Printf("provider:   %s (%s)\n", e.Provider, e.Model)
		fmt.Printf("stored:     %s (%s ago)\n", e.StoredAt.Format(time.RFC3339), time.Since(e.StoredAt).Round(time.Second))
		if !e.ExpiresAt.IsZero() {
			remaining := time.Until(e.ExpiresAt).Round(time.Second)
			if remaining > 0 {
				fmt.Printf("expires:    %s (in %s)\n", e.ExpiresAt.Format(time.RFC3339), remaining)
			} else {
				fmt.Printf("expires:    %s (expired)\n", e.ExpiresAt.Format(time.RFC3339))
			}
		}
		if e.CWD != "" {
			fmt.Printf("cwd:        %s\n", e.CWD)
		}
		if e.CanonicalForm != "" {
			fmt.Printf("canonical:  %s (matches: %d)\n", e.CanonicalForm, e.MatchCount)
		}

		// Verification details.
		if e.Verified {
			fmt.Printf("verified:   %s by %s (%s)\n",
				e.VerifiedAt.Format(time.RFC3339), e.VerifierProvider, e.VerifierModel)
			fmt.Printf("  verdict:  %s\n", e.VerifierVerdict)
			if e.VerifierReason != "" {
				fmt.Printf("  reason:   %s\n", e.VerifierReason)
			}
			if e.Disagreement {
				fmt.Printf("  ⚠ DISAGREEMENT: verifier overrides original verdict\n")
			}
		} else {
			fmt.Printf("verified:   pending\n")
		}
		if !e.TrustedAt.IsZero() {
			fmt.Printf("trusted:    %s\n", e.TrustedAt.Format(time.RFC3339))
			if e.TrustedReason != "" {
				fmt.Printf("  reason:   %s\n", e.TrustedReason)
			}
		}
		fmt.Println()
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cache inspect: walk: %v\n", err)
		return 1
	}

	if !asJSON {
		if shown == 0 {
			fmt.Println("no matching entries found")
		} else {
			fmt.Printf("(%d entr%s shown)\n", shown, pluralIES(shown))
		}
	}
	return 0
}

type cacheBreakdown struct {
	byVerdict map[string]int
	byProgram map[string]int
}

// walkCacheBreakdown counts entries by effective verdict and by program.
// Tolerates unreadable entries — they're skipped silently so that a
// single corrupt file doesn't poison the summary.
func walkCacheBreakdown(dir string) (*cacheBreakdown, error) {
	out := &cacheBreakdown{
		byVerdict: map[string]int{},
		byProgram: map[string]int{},
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return out, nil
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var e cache.Entry
		if json.Unmarshal(data, &e) != nil {
			return nil
		}
		out.byVerdict[string(e.EffectiveVerdict())]++
		prog := e.Program
		if prog == "" {
			prog = programFromCommand(e.Command)
		}
		if prog != "" {
			out.byProgram[prog]++
		}
		return nil
	})
	return out, err
}

// programFromCommand returns the first whitespace-delimited token,
// suitable as a rough program name when Entry.Program is empty (older
// entries predating the Program field).
func programFromCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	for i, r := range cmd {
		if r == ' ' || r == '\t' {
			return cmd[:i]
		}
	}
	return cmd
}

func sortedStringKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cachePruneCmd(args []string) int {
	fs := flag.NewFlagSet("cache prune", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		dryRun       bool
		onlyExpired  bool
		olderThanStr string
		matchSub     string
		verdictStr   string
		onlyDisagree bool
	)
	fs.BoolVar(&dryRun, "dry-run", false, "print matches, don't delete")
	fs.BoolVar(&onlyExpired, "expired", false, "entries past their TTL")
	fs.StringVar(&olderThanStr, "older-than", "", "entries stored more than N ago (e.g. 30d, 1w, 24h)")
	fs.StringVar(&matchSub, "match", "", "entries whose command contains this substring")
	fs.StringVar(&verdictStr, "verdict", "", "effective verdict equals this (allow or deny)")
	fs.BoolVar(&onlyDisagree, "disagreements", false, "entries where verifier disagreed")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// No explicit filter → default to --expired. Without this default,
	// a bare `cache prune` would match every entry and delete the cache.
	// That's what `cache clear` is for; `prune` should always be safe.
	anyFilter := onlyExpired || olderThanStr != "" || matchSub != "" || verdictStr != "" || onlyDisagree
	if !anyFilter {
		onlyExpired = true
	}

	var olderThan time.Duration
	if olderThanStr != "" {
		d, err := parseExtendedDuration(olderThanStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cache prune: --older-than: %v\n", err)
			return 2
		}
		olderThan = d
	}

	if verdictStr != "" && verdictStr != "allow" && verdictStr != "deny" {
		fmt.Fprintf(os.Stderr, "cache prune: --verdict must be allow or deny, got %q\n", verdictStr)
		return 2
	}

	dir := cacheDirForOps()
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Println("cache dir does not exist; nothing to prune")
		return 0
	}

	now := time.Now()
	matched := 0
	deleted := 0
	corruptDeleted := 0
	var errs []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var e cache.Entry
		if json.Unmarshal(data, &e) != nil {
			// Corrupt entry — always prune (but count separately so
			// operators can tell apart "filter matched" from "disk was
			// broken").
			if dryRun {
				fmt.Printf("CORRUPT: %s\n", path)
				corruptDeleted++
				return nil
			}
			if rmErr := os.Remove(path); rmErr != nil {
				errs = append(errs, fmt.Sprintf("delete %s: %v", path, rmErr))
			} else {
				corruptDeleted++
			}
			return nil
		}

		// AND semantics: the entry must satisfy every filter that was
		// supplied. A filter that wasn't supplied is a no-op.
		if onlyExpired && !e.Expired(now) {
			return nil
		}
		if olderThan > 0 && now.Sub(e.StoredAt) < olderThan {
			return nil
		}
		if matchSub != "" && !strings.Contains(e.Command, matchSub) {
			return nil
		}
		if verdictStr != "" && string(e.EffectiveVerdict()) != verdictStr {
			return nil
		}
		if onlyDisagree && !e.Disagreement {
			return nil
		}

		matched++
		if dryRun {
			fmt.Printf("MATCH: %s\n", truncateInline(e.Command, 100))
			fmt.Printf("       tier=%s verdict=%s stored=%s\n",
				e.Tier, e.EffectiveVerdict(), e.StoredAt.Format(time.RFC3339))
			return nil
		}
		if rmErr := os.Remove(path); rmErr != nil {
			errs = append(errs, fmt.Sprintf("delete %s: %v", path, rmErr))
		} else {
			deleted++
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cache prune: walk: %v\n", err)
		return 1
	}

	if dryRun {
		fmt.Printf("\nwould delete %d filter-matched entr%s + %d corrupt (dry-run)\n",
			matched, pluralIES(matched), corruptDeleted)
	} else {
		fmt.Printf("deleted %d filter-matched entr%s (matched %d) + %d corrupt\n",
			deleted, pluralIES(deleted), matched, corruptDeleted)
	}
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "  %s\n", e)
	}
	if len(errs) > 0 {
		return 1
	}
	return 0
}

func cacheClearCmd(args []string) int {
	fs := flag.NewFlagSet("cache clear", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var force bool
	fs.BoolVar(&force, "force", false, "confirm destructive action")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !force {
		fmt.Fprintln(os.Stderr, "cache clear: refusing to wipe cache without --force")
		return 2
	}
	dir := cacheDirForOps()
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintf(os.Stderr, "cache clear: %v\n", err)
		return 1
	}
	fmt.Printf("cleared %s\n", dir)
	return 0
}

// cacheDirFn resolves the verdict cache directory. Overridable in tests.
var cacheDirFn = defaultCacheDirForOps

func cacheDirForOps() string { return cacheDirFn() }

func defaultCacheDirForOps() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cache", "claude-guard", "verdicts")
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		dir = filepath.Join(xdg, "claude-guard", "verdicts")
	}
	return dir
}

// parseExtendedDuration extends time.ParseDuration with day (d) and
// week (w) suffixes. Only the trailing unit is extended — compound
// durations like "2w3d" are not supported; use seconds/hours if needed.
func parseExtendedDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	last := s[len(s)-1]
	if last == 'd' || last == 'D' {
		h, err := time.ParseDuration(s[:len(s)-1] + "h")
		if err != nil {
			return 0, err
		}
		return h * 24, nil
	}
	if last == 'w' || last == 'W' {
		h, err := time.ParseDuration(s[:len(s)-1] + "h")
		if err != nil {
			return 0, err
		}
		return h * 24 * 7, nil
	}
	return time.ParseDuration(s)
}

func truncateInline(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func pluralIES(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
