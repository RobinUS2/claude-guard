package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/budget"
)

// TestBuildDryRunCommand verifies that buildDryRunCommand correctly inserts
// --dry_run using string replacement, preserving all quoting intact.
func TestBuildDryRunCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want string // "" means expect empty (not a bq query)
	}{
		{"bq query --nouse_legacy_sql 'SELECT 1'", "bq query --dry_run --nouse_legacy_sql 'SELECT 1'"},
		{"bq query --nouse_legacy_sql 'SELECT id FROM users WHERE name = \"Alice Smith\"'",
			"bq query --dry_run --nouse_legacy_sql 'SELECT id FROM users WHERE name = \"Alice Smith\"'"},
		{"bq show dataset.table", ""},
		{"bq ls", ""},
		{"gcloud compute", ""},
		{"bq query", "bq query --dry_run"},
		{"  bq query --nouse_legacy_sql 'SELECT 1'", "bq query --dry_run --nouse_legacy_sql 'SELECT 1'"},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			got := buildDryRunCommand(tc.cmd)
			if got != tc.want {
				t.Errorf("buildDryRunCommand(%q)\n  got:  %q\n  want: %q", tc.cmd, got, tc.want)
			}
			if tc.want != "" && !strings.Contains(got, "--dry_run") {
				t.Errorf("result %q does not contain --dry_run", got)
			}
		})
	}
}

func TestIsBQQueryWithoutDryRun(t *testing.T) {
	cases := []struct{ cmd string; want bool }{
		{"bq query --nouse_legacy_sql 'SELECT 1'", true},
		{"bq query --dry_run --nouse_legacy_sql 'SELECT 1'", false},
		{"bq query --dry-run --nouse_legacy_sql 'SELECT 1'", false},
		{"bq show dataset.table", false},
		{"gcloud compute instances list", false},
	}
	for _, tc := range cases {
		got := isBQQueryWithoutDryRun(tc.cmd)
		if got != tc.want {
			t.Errorf("isBQQueryWithoutDryRun(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

func TestParseBytesFromDryRun(t *testing.T) {
	cases := []struct {
		output string
		wantN  int64
		wantOK bool
	}{
		{
			"Query successfully validated. Assuming the tables are not modified, running this query will process 1073741824 bytes.",
			1073741824, true,
		},
		{
			"running this query will process 500 bytes.",
			500, true,
		},
		{
			"No matching output here",
			0, false,
		},
	}
	for _, tc := range cases {
		n, ok := parseBytesFromDryRun([]byte(tc.output))
		if ok != tc.wantOK || n != tc.wantN {
			t.Errorf("parseBytesFromDryRun(%q) = (%d, %v), want (%d, %v)",
				tc.output, n, ok, tc.wantN, tc.wantOK)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct{ in int64; want string }{
		{1 << 30, "1.0 GB"},
		{1<<30 + 500<<20, "1.5 GB"},
		{1 << 20, "1.0 MB"},
		{1 << 10, "1.0 KB"},
		{512, "512 B"},
	}
	for _, tc := range cases {
		got := formatBytes(tc.in)
		if got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRunBQPreflight_WithinBudget(t *testing.T) {
	origRun := runBQDryRun
	defer func() { runBQDryRun = origRun }()
	runBQDryRun = func(_ context.Context, _ string) ([]byte, error) {
		return []byte("running this query will process 1073741824 bytes."), nil
	}

	dir := t.TempDir()
	b := budget.NewBQ(dir, 100<<30) // 100 GB limit

	result := runBQPreflight("bq query --nouse_legacy_sql 'SELECT 1'", b)
	if !result.allow {
		t.Errorf("expected allow, got deny; msg=%q", result.userMessage)
	}
	if !strings.Contains(result.userMessage, "1.0 GB") {
		t.Errorf("userMessage missing byte estimate: %q", result.userMessage)
	}
	if !strings.Contains(result.userMessage, "daily budget used") {
		t.Errorf("userMessage missing budget info: %q", result.userMessage)
	}
}

func TestRunBQPreflight_OverBudget(t *testing.T) {
	origRun := runBQDryRun
	defer func() { runBQDryRun = origRun }()
	runBQDryRun = func(_ context.Context, _ string) ([]byte, error) {
		return []byte("running this query will process 10737418240 bytes."), nil // 10 GB
	}

	dir := t.TempDir()
	b := budget.NewBQ(dir, 5<<30) // 5 GB limit — 10 GB query exceeds it

	result := runBQPreflight("bq query --nouse_legacy_sql 'SELECT * FROM big_table'", b)
	if result.allow {
		t.Error("expected deny, got allow")
	}
	if !strings.Contains(result.userMessage, "exhausted") {
		t.Errorf("userMessage missing exhausted marker: %q", result.userMessage)
	}
}

func TestRunBQPreflight_NoBudget(t *testing.T) {
	result := runBQPreflight("bq query 'SELECT 1'", nil)
	if !result.skipped {
		t.Error("expected skipped when bqBudget is nil")
	}
}

func TestRunBQPreflight_NotBQQuery(t *testing.T) {
	dir := t.TempDir()
	b := budget.NewBQ(dir, 100<<30)
	result := runBQPreflight("gcloud compute instances list", b)
	if !result.skipped {
		t.Error("expected skipped for non-bq-query command")
	}
}

func TestRunBQPreflight_AlreadyDryRun(t *testing.T) {
	dir := t.TempDir()
	b := budget.NewBQ(dir, 100<<30)
	result := runBQPreflight("bq query --dry_run 'SELECT 1'", b)
	if !result.skipped {
		t.Error("expected skipped for commands already using --dry_run")
	}
}
