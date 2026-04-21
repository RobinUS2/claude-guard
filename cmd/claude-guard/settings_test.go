package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestSettings creates a temporary settings.json with the given
// permission entries and configures settingsPathFn + storePathFn to
// point at temp locations. Returns a cleanup function.
func writeTestSettings(t *testing.T, entries []string) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	raw := map[string]any{
		"permissions": map[string]any{
			"allow": entries,
		},
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	origSettings := settingsPathFn
	origStore := storePathFn

	settingsPathFn = func() string { return settingsPath }

	// Set up store path in a subdirectory.
	guardDir := filepath.Join(dir, "claude-guard")
	os.MkdirAll(guardDir, 0o755)
	dbPath := filepath.Join(guardDir, "guard.db")
	storePathFn = func() string { return dbPath }

	cleanup := func() {
		settingsPathFn = origSettings
		storePathFn = origStore
	}
	return settingsPath, cleanup
}

func TestSettingsAudit_Empty(t *testing.T) {
	_, cleanup := writeTestSettings(t, []string{})
	defer cleanup()

	code := settingsAuditCmd(nil)
	if code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
}

func TestSettingsAudit_WithEntries(t *testing.T) {
	entries := []string{
		// Bash entries matching tier 2 programs (redundant).
		"Bash(git status:*)",
		"Bash(ls -la:*)",
		"Bash(grep -r foo:*)",
		// Bash entry NOT matching tier 2 (remaining).
		"Bash(python3 script.py:*)",
		"Bash(make test:*)",
		// Non-Bash entries (kept).
		"Read(file:/tmp/foo)",
		"WebFetch(domain:github.com)",
		"mcp__server__tool(arg:*)",
		// Credential entry.
		"Bash(curl -H Authorization: Bearer ghp_secret123 https://api.github.com:*)",
	}
	_, cleanup := writeTestSettings(t, entries)
	defer cleanup()

	code := settingsAuditCmd(nil)
	if code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}

	// Verify classification directly.
	res := auditSettings(entries)
	if res.total != len(entries) {
		t.Errorf("total=%d, want %d", res.total, len(entries))
	}
	if len(res.redundant) != 3 {
		t.Errorf("redundant=%d, want 3 (git, ls, grep)", len(res.redundant))
	}
	if len(res.credentials) != 1 {
		t.Errorf("credentials=%d, want 1", len(res.credentials))
	}
	if len(res.nonBash) != 3 {
		t.Errorf("nonBash=%d, want 3", len(res.nonBash))
	}
	if len(res.remaining) != 2 {
		t.Errorf("remaining=%d, want 2 (python3, make)", len(res.remaining))
	}
}

func TestSettingsMigrate_DryRun(t *testing.T) {
	entries := []string{
		"Bash(git status:*)",
		"Bash(ls -la:*)",
		"Bash(python3 script.py:*)",
		"Bash(make test:*)",
		"Read(file:/tmp/foo)",
		"WebFetch(domain:github.com)",
	}
	settingsPath, cleanup := writeTestSettings(t, entries)
	defer cleanup()

	// Capture original file content.
	origData, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}

	code := settingsMigrateCmd([]string{"--dry-run"})
	if code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}

	// Verify settings.json was NOT modified.
	afterData, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings after: %v", err)
	}
	if string(origData) != string(afterData) {
		t.Error("settings.json was modified during --dry-run")
	}
}

func TestSettingsMigrate_Apply(t *testing.T) {
	entries := []string{
		"Bash(git status:*)",           // redundant (tier 2)
		"Bash(ls -la:*)",               // redundant (tier 2)
		"Bash(python3 script.py:*)",    // remaining -> learned
		"Bash(make test:*)",            // remaining -> learned
		"Read(file:/tmp/foo)",          // non-Bash -> keep
		"WebFetch(domain:github.com)",  // non-Bash -> keep
	}
	settingsPath, cleanup := writeTestSettings(t, entries)
	defer cleanup()

	code := settingsMigrateCmd([]string{"--apply"})
	if code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}

	// Read back settings.json — should only have non-Bash entries.
	s, err := readSettings(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if len(s.Permissions.Allow) != 2 {
		t.Errorf("remaining entries=%d, want 2 (non-Bash only), got: %v",
			len(s.Permissions.Allow), s.Permissions.Allow)
	}
	for _, e := range s.Permissions.Allow {
		if strings.HasPrefix(e, "Bash(") {
			t.Errorf("Bash entry still in settings.json after migrate: %s", e)
		}
	}
}

func TestSettingsMigrate_NoFlag(t *testing.T) {
	_, cleanup := writeTestSettings(t, []string{})
	defer cleanup()

	code := settingsMigrateCmd(nil)
	if code != 2 {
		t.Fatalf("exit code %d, want 2 (usage error)", code)
	}
}

func TestExtractBashProgram(t *testing.T) {
	tests := []struct {
		entry string
		want  string
	}{
		{"Bash(git status:*)", "git"},
		{"Bash(ls -la:*)", "ls"},
		{"Bash(python3 script.py:*)", "python3"},
		{"Bash(make:*)", "make"},
		{"Read(file:*)", ""},
		{"Bash(curl -H 'Bearer tok' https://api.com:*)", "curl"},
	}
	for _, tt := range tests {
		got := extractBashProgram(tt.entry)
		if got != tt.want {
			t.Errorf("extractBashProgram(%q) = %q, want %q", tt.entry, got, tt.want)
		}
	}
}

func TestExtractBashCommand(t *testing.T) {
	tests := []struct {
		entry string
		want  string
	}{
		{"Bash(git status:*)", "git status"},
		{"Bash(ls -la:*)", "ls -la"},
		{"Bash(make:*)", "make"},
		{"Read(file:*)", ""},
	}
	for _, tt := range tests {
		got := extractBashCommand(tt.entry)
		if got != tt.want {
			t.Errorf("extractBashCommand(%q) = %q, want %q", tt.entry, got, tt.want)
		}
	}
}

func TestClassifyEntry(t *testing.T) {
	tests := []struct {
		entry   string
		wantCat entryCategory
	}{
		{"Bash(git status:*)", catBash},
		{"Read(file:/tmp/foo)", catNonBash},
		{"mcp__server__tool(arg:*)", catNonBash},
		{"Bash(curl -H Authorization: Bearer ghp_abc:*)", catCredential},
		{"Bash(curl -H token=secret123:*)", catCredential},
	}
	for _, tt := range tests {
		got, _ := classifyEntry(tt.entry)
		if got != tt.wantCat {
			t.Errorf("classifyEntry(%q) = %d, want %d", tt.entry, got, tt.wantCat)
		}
	}
}

