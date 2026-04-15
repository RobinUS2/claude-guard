package legacy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEntry_BasicBash(t *testing.T) {
	cases := []struct {
		entry      string
		wantPrefix string
		wantOK     bool
	}{
		{"Bash(ls:*)", "ls", true},
		{"Bash(git status:*)", "git status", true},
		{"Bash(gcloud builds list:*)", "gcloud builds list", true},
		{"Bash(make test*:*)", "make test*", true},
		{"Bash(npm run test:unit:*)", "npm run test:unit", true},
		{"Bash()", "", false},                  // empty
		{"Read(/foo)", "", false},              // not Bash
		{"WebFetch(domain:github.com)", "", false},
		{"mcp__atlassian__getJiraIssue", "", false},
		{"Bash(curl ... | sh)", "", false},     // pipe — skipped
		{"Bash(echo $(date))", "", false},      // command sub — skipped
	}
	for _, tc := range cases {
		t.Run(tc.entry, func(t *testing.T) {
			got, ok := parseEntry(tc.entry)
			if ok != tc.wantOK {
				t.Fatalf("parseEntry(%q) ok=%v, want %v", tc.entry, ok, tc.wantOK)
			}
			if ok && got.Prefix != tc.wantPrefix {
				t.Errorf("Prefix = %q, want %q", got.Prefix, tc.wantPrefix)
			}
		})
	}
}

func TestPattern_MatchPrefix(t *testing.T) {
	patterns, skipped := ParseSettingsAllowList([]string{
		"Bash(ls:*)",
		"Bash(git status:*)",
		"Bash(make test*:*)",
		"Bash(gcloud builds list:*)",
		"Bash(npm run lint)",
	})
	if len(skipped) != 0 {
		t.Errorf("skipped should be empty: %v", skipped)
	}

	a := &AllowList{Patterns: patterns}

	cases := []struct {
		cmd  string
		want bool
	}{
		{"ls -la", true},
		{"ls", true},
		{"git status", true},
		{"git status --short", true},
		{"git push", false}, // no matching pattern
		{"make test", true},
		{"make testfoo", true},      // glob
		{"make test-thing-x", true}, // glob
		{"make build", false},
		{"gcloud builds list --limit=5", true},
		{"gcloud builds describe abc", false}, // describe ≠ list
		{"npm run lint", true},
		{"npm run lintfoo", false}, // exact prefix, no trailing wildcard implied
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			match := a.Match(tc.cmd)
			got := match != nil
			if got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestPattern_NotPrefixSubstring(t *testing.T) {
	// Important: "ls" must not match "lsof" or "lsblk" — otherwise
	// any process listing or block listing would inherit ls's
	// permissions.
	patterns, _ := ParseSettingsAllowList([]string{"Bash(ls:*)"})
	a := &AllowList{Patterns: patterns}

	if a.Match("lsof -i") != nil {
		t.Error("ls pattern wrongly matched lsof")
	}
	if a.Match("lsblk") != nil {
		t.Error("ls pattern wrongly matched lsblk")
	}
}

func TestPattern_AnchoredAtStart(t *testing.T) {
	patterns, _ := ParseSettingsAllowList([]string{"Bash(git status:*)"})
	a := &AllowList{Patterns: patterns}

	// Same prefix in middle of the line should NOT match — patterns
	// are anchored at the beginning of the command.
	if a.Match("foo && git status") != nil {
		t.Error("git status pattern wrongly matched compound command")
	}
}

func TestParseSettingsAllowList_RealisticMix(t *testing.T) {
	// Mirror of an actual settings.json sample.
	entries := []string{
		"Bash(ls:*)",
		"Bash(grep:*)",
		"Read(//Users/robin/Documents/code/**)",
		"Bash(git status:*)",
		"Bash(go test:*)",
		"WebFetch(domain:github.com)",
		"mcp__atlassian__getJiraIssue",
		"Bash(make build*:*)",
		"Bash(curl -s https://example.com/api)",
	}
	patterns, skipped := ParseSettingsAllowList(entries)

	// Bash entries make it in, others get skipped.
	if len(patterns) < 5 {
		t.Errorf("expected 5+ patterns, got %d", len(patterns))
	}
	if len(skipped) < 3 {
		t.Errorf("expected 3+ skipped (Read, WebFetch, mcp), got %d: %v", len(skipped), skipped)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	a, err := Load("/nonexistent/legacy.yaml")
	if err != nil {
		t.Fatalf("missing file should not be an error: %v", err)
	}
	if a == nil {
		t.Fatal("Load should never return nil AllowList")
	}
	if a.Match("anything") != nil {
		t.Error("empty AllowList must not match anything")
	}
}

func TestWriteAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")

	patterns, _ := ParseSettingsAllowList([]string{
		"Bash(ls:*)",
		"Bash(git status:*)",
		"Bash(make test*:*)",
	})
	in := &File{
		Version:  SchemaVersion,
		Source:   "test",
		Patterns: patterns,
	}
	if err := WriteFile(path, in); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Patterns) != len(in.Patterns) {
		t.Errorf("loaded %d patterns, want %d", len(loaded.Patterns), len(in.Patterns))
	}

	// Patterns still work after round trip
	if loaded.Match("ls -la") == nil {
		t.Error("loaded pattern should match")
	}
	if loaded.Match("make test-fast") == nil {
		t.Error("loaded glob pattern should match")
	}
}

func TestMigrateSettingsJSON(t *testing.T) {
	json := []byte(`{
  "permissions": {
    "allow": [
      "Bash(ls:*)",
      "Bash(git status:*)",
      "Read(/foo)",
      "Bash(make test*:*)"
    ]
  },
  "other_key": {}
}`)
	f, err := MigrateSettingsJSON(json)
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != SchemaVersion {
		t.Errorf("Version = %d", f.Version)
	}
	if len(f.Patterns) != 3 {
		t.Errorf("Patterns = %d, want 3", len(f.Patterns))
	}
	if len(f.Skipped) != 1 {
		t.Errorf("Skipped = %d, want 1 (Read entry)", len(f.Skipped))
	}
	if !strings.Contains(strings.Join(f.Skipped, " "), "Read(/foo)") {
		t.Errorf("Skipped should contain Read(/foo): %v", f.Skipped)
	}
}

func TestMigrateSettingsJSON_Empty(t *testing.T) {
	json := []byte(`{}`)
	f, err := MigrateSettingsJSON(json)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Patterns) != 0 {
		t.Errorf("expected empty patterns, got %d", len(f.Patterns))
	}
}

func TestHasUnsupported(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"ls", false},
		{"git status", false},
		{"make test*", false},
		{"echo $(date)", true},
		{"foo && bar", true},
		{"foo || bar", true},
		{"cmd > out", true},
		{"cmd < in", true},
		{"cmd; cmd", true},
		{`echo "hello\"world"`, true},
		// Pipe is also rejected — too easy to migrate a curl|sh entry
		// and accidentally bless RCE patterns.
		{"cat /tmp/x | grep foo", true},
		{"cmd & background", true},
	}
	for _, tc := range cases {
		got := hasUnsupported(tc.s)
		if got != tc.want {
			t.Errorf("hasUnsupported(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestWriteFile_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yaml")
	if err := WriteFile(path, &File{Version: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("leftover tmp file")
	}
}
