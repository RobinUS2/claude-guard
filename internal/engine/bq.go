package engine

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/budget"
)

// runShellCommand executes cmd via `sh -c` and returns combined stdout+stderr.
func runShellCommand(ctx context.Context, cmd string) ([]byte, error) {
	return exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
}

const bqPreflightTimeout = 10 * time.Second

// runBQDryRun is a var so tests can stub it out.
var runBQDryRun = func(ctx context.Context, cmd string) ([]byte, error) {
	dryCmd := buildDryRunCommand(cmd)
	if dryCmd == "" {
		return nil, fmt.Errorf("not a bq query command: %q", cmd)
	}
	// Execute via shell so flags and quoted SQL are handled correctly.
	return runShellCommand(ctx, dryCmd)
}

// buildDryRunCommand inserts --dry_run into a `bq query ...` command.
// Uses simple string replacement to preserve all quoting intact.
// Returns "" if the command is not a `bq query` command.
func buildDryRunCommand(cmd string) string {
	trimmed := strings.TrimSpace(cmd)
	const marker = "bq query "
	if !strings.HasPrefix(trimmed, marker) && trimmed != "bq query" {
		return ""
	}
	return strings.Replace(trimmed, "bq query", "bq query --dry_run", 1)
}

// isBQQueryWithoutDryRun returns true when cmd is a `bq query` command
// that does NOT already include --dry_run or --dry-run.
func isBQQueryWithoutDryRun(cmd string) bool {
	trimmed := strings.TrimSpace(cmd)
	if !strings.HasPrefix(trimmed, "bq query") {
		return false
	}
	lower := strings.ToLower(trimmed)
	return !strings.Contains(lower, "--dry_run") && !strings.Contains(lower, "--dry-run")
}

// parseBytesFromDryRun extracts the estimated bytes from a bq --dry_run response.
// The output contains a line like "Query successfully validated. Assuming the
// tables are not modified, running this query will process 1073741824 bytes."
func parseBytesFromDryRun(output []byte) (int64, bool) {
	for _, line := range bytes.Split(output, []byte("\n")) {
		s := string(line)
		if strings.Contains(s, "will process") && strings.Contains(s, "bytes") {
			fields := strings.Fields(s)
			for i, f := range fields {
				if f == "process" && i+1 < len(fields) {
					raw := strings.TrimRight(fields[i+1], ".")
					n, err := strconv.ParseInt(raw, 10, 64)
					if err == nil {
						return n, true
					}
				}
			}
		}
	}
	return 0, false
}

// formatBytes renders a byte count as a human-readable string (GB/MB/KB/B).
func formatBytes(b int64) string {
	const gb = 1 << 30
	const mb = 1 << 20
	const kb = 1 << 10
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// bqPreflightResult is the engine-internal result of the BQ pre-flight check.
type bqPreflightResult struct {
	// allow is true when the query is within budget.
	allow bool
	// userMessage is the hint to inject into Claude's conversation.
	// Non-empty regardless of allow/deny — always gives Claude context.
	userMessage string
	// skipped is true when the pre-flight was not applicable or errored.
	// Engine treats this as "fall through normally".
	skipped bool
}

// runBQPreflight runs the BQ pre-flight tier for a Bash command.
// Returns a result indicating whether to allow and what hint to inject.
// Always returns a non-nil result; never panics.
func runBQPreflight(cmd string, bqBudget *budget.BQBudget) bqPreflightResult {
	if bqBudget == nil {
		return bqPreflightResult{skipped: true}
	}
	if !isBQQueryWithoutDryRun(cmd) {
		return bqPreflightResult{skipped: true}
	}

	ctx, cancel := context.WithTimeout(context.Background(), bqPreflightTimeout)
	defer cancel()

	out, err := runBQDryRun(ctx, cmd)
	if err != nil {
		// Dry-run failed (no credentials, network, invalid SQL).
		// Fall through — never hard-block on a pre-flight error.
		return bqPreflightResult{
			skipped:     true,
			userMessage: "claude-guard: BQ pre-flight dry-run failed — proceeding without budget check",
		}
	}

	estimatedBytes, ok := parseBytesFromDryRun(out)
	if !ok {
		// Couldn't parse bytes — still fall through.
		return bqPreflightResult{
			skipped:     true,
			userMessage: "claude-guard: BQ pre-flight ran but could not parse byte estimate",
		}
	}

	withinBudget, usedAfter, limitBytes := bqBudget.CheckAndRecord(estimatedBytes)
	humanEstimate := formatBytes(estimatedBytes)
	humanUsed := formatBytes(usedAfter)
	humanLimit := formatBytes(limitBytes)

	if withinBudget {
		msg := fmt.Sprintf(
			"BQ pre-flight: will process %s — %s of %s daily budget used",
			humanEstimate, humanUsed, humanLimit,
		)
		return bqPreflightResult{allow: true, userMessage: msg}
	}

	// Over budget — don't record (CheckAndRecord already didn't).
	usedCurrent, _ := bqBudget.Status()
	humanCurrentUsed := formatBytes(usedCurrent)
	msg := fmt.Sprintf(
		"BQ daily budget exhausted (%s of %s used). This query would process %s. "+
			"Consider adding a LIMIT clause or rewriting to scan fewer bytes.",
		humanCurrentUsed, humanLimit, humanEstimate,
	)
	return bqPreflightResult{allow: false, userMessage: msg}
}
