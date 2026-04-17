package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/review"
)

func cmdReview(args []string) int {
	fs := flag.NewFlagSet("review", flag.ExitOnError)
	hours := fs.Int("hours", 24, "how many hours of decisions to review")
	apply := fs.Bool("apply", false, "apply recommended changes (otherwise dry-run)")
	dryRun := fs.Bool("dry-run", false, "analyze and validate but don't write changes (default)")
	showLearned := fs.Bool("show-learned", false, "list active learned rules and exit")
	showHints := fs.Bool("show-hints", false, "list active prompt hints and exit")
	modelFlag := fs.String("model", "", "override the review model (default: claude-opus-4-6)")
	_ = fs.Parse(args)

	configDir := review.DefaultConfigDir()

	if *showLearned {
		return cmdShowLearned(configDir)
	}
	if *showHints {
		return cmdShowHints(configDir)
	}

	// Lockfile to prevent concurrent reviews.
	lockPath := filepath.Join(os.Getenv("HOME"), ".cache", "claude-guard", "review.lock")
	if !acquireLock(lockPath) {
		fmt.Fprintln(os.Stderr, "claude-guard review: another review is running (lockfile exists). Skipping.")
		return 0
	}
	defer releaseLock(lockPath)

	// Resolve log directory.
	result := config.Load("")
	cfg := result.Config
	logDir := cfg.Log.Dir
	if logDir == "" {
		logDir = config.DefaultLogDir()
	}

	// Collect interesting cases.
	fmt.Printf("Collecting decisions from last %dh...\n", *hours)
	cases, err := review.Collect(logDir, *hours)
	if err != nil {
		fmt.Fprintf(os.Stderr, "collect: %v\n", err)
		return 1
	}
	fmt.Printf("Found %d interesting cases.\n", len(cases))
	if len(cases) == 0 {
		fmt.Println("Nothing to review.")
		return 0
	}

	// Print category breakdown.
	cats := map[string]int{}
	for _, c := range cases {
		cats[c.Category]++
	}
	for cat, n := range cats {
		fmt.Printf("  %s: %d\n", cat, n)
	}

	// Get API key.
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		// Try aliases.
		for _, k := range []string{"CLAUDE_API_KEY", "SITEGEN_ANTHROPIC_KEY"} {
			if v := os.Getenv(k); v != "" {
				apiKey = v
				break
			}
		}
	}
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "No ANTHROPIC_API_KEY set. Cannot call Opus for review.")
		return 1
	}

	model := review.DefaultModel
	if *modelFlag != "" {
		model = *modelFlag
	}

	// Analyze with Opus.
	fmt.Printf("Analyzing with %s (this may take 30-60s)...\n", model)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	report, err := review.Analyze(ctx, cases, apiKey, model)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze: %v\n", err)
		return 1
	}

	// Validate.
	plan := review.Validate(report)

	// Print report.
	fmt.Println("\n" + "═══════════════════════════════════════")
	fmt.Println("CLAUDE-GUARD SELF-REVIEW REPORT")
	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("\n%s\n\n", plan.Summary)

	if len(report.FalsePositives) > 0 {
		fmt.Printf("False positives found: %d\n", len(report.FalsePositives))
		for _, fp := range report.FalsePositives {
			fmt.Printf("  [%d] %s → should be %s: %s\n", fp.CaseIndex, fp.Command, fp.Expected, fp.Reason)
		}
		fmt.Println()
	}
	if len(report.FalseNegatives) > 0 {
		fmt.Printf("⚠ False negatives found: %d\n", len(report.FalseNegatives))
		for _, fn := range report.FalseNegatives {
			fmt.Printf("  [%d] %s → should be %s: %s\n", fn.CaseIndex, fn.Command, fn.Expected, fn.Reason)
		}
		fmt.Println()
	}
	if len(plan.AcceptedRules) > 0 {
		fmt.Printf("Recommended learned rules: %d\n", len(plan.AcceptedRules))
		for _, r := range plan.AcceptedRules {
			fmt.Printf("  %v %v (%d evidence): %s\n", r.Programs, r.Subcommands, len(r.Evidence), r.Reason)
		}
		fmt.Println()
	}
	if len(plan.RejectedRules) > 0 {
		fmt.Printf("Rejected rules: %d\n", len(plan.RejectedRules))
		for _, r := range plan.RejectedRules {
			fmt.Printf("  %s → %s\n", r.Description, r.Reason)
		}
		fmt.Println()
	}
	if len(plan.AcceptedHints) > 0 {
		fmt.Printf("Recommended prompt hints: %d\n", len(plan.AcceptedHints))
		for _, h := range plan.AcceptedHints {
			fmt.Printf("  \"%s\"\n", truncateStr(h.Context, 80))
		}
		fmt.Println()
	}
	if len(plan.AcceptedTrims) > 0 {
		fmt.Printf("Recommended legacy trims: %d\n", len(plan.AcceptedTrims))
		for _, t := range plan.AcceptedTrims {
			fmt.Printf("  %s → %s\n", t.Prefix, t.Reason)
		}
		fmt.Println()
	}

	// Apply or dry-run.
	if *apply && !*dryRun {
		fmt.Println("Applying changes...")
		n, err := review.Apply(plan, configDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "apply: %v\n", err)
			return 1
		}
		fmt.Printf("Applied %d changes. Review log: %s/review-log.jsonl\n", n, configDir)

		// Update last-review timestamp.
		tsPath := filepath.Join(os.Getenv("HOME"), ".cache", "claude-guard", "last-review.txt")
		_ = os.MkdirAll(filepath.Dir(tsPath), 0o755)
		_ = os.WriteFile(tsPath, []byte(time.Now().Format(time.RFC3339)), 0o640)
	} else {
		fmt.Println("Dry-run mode — no changes written. Use --apply to apply.")
	}

	return 0
}

func cmdShowLearned(configDir string) int {
	f := review.LoadLearnedRules(configDir)
	if len(f.Rules) == 0 {
		fmt.Println("No learned rules.")
		return 0
	}
	fmt.Printf("Learned rules (%d):\n", len(f.Rules))
	for _, r := range f.Rules {
		fmt.Printf("  %s: %v %v (evidence=%d, added=%s)\n",
			r.Name, r.Programs, r.Subcommands, r.EvidenceCount,
			r.AddedAt.Format("2006-01-02"))
	}
	return 0
}

func cmdShowHints(configDir string) int {
	f := review.LoadPromptHints(configDir)
	if len(f.Hints) == 0 {
		fmt.Println("No prompt hints.")
		return 0
	}
	fmt.Printf("Prompt hints (%d):\n", len(f.Hints))
	total := 0
	for _, h := range f.Hints {
		fmt.Printf("  [%s] %s\n", h.AddedAt.Format("2006-01-02"), truncateStr(h.Context, 80))
		total += len(h.Context)
	}
	fmt.Printf("Total: %d bytes / 2048 cap\n", total)
	return 0
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func acquireLock(path string) bool {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	// Check if lock exists and is recent (< 10 minutes).
	if info, err := os.Stat(path); err == nil {
		if time.Since(info.ModTime()) < 10*time.Minute {
			return false
		}
		// Stale lock — remove it.
		_ = os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func releaseLock(path string) {
	_ = os.Remove(path)
}
