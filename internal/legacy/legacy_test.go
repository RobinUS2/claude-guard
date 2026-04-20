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
		// `make test*` is now filtered (make is unsafe-legacy post-hardening).
		{"Bash(make test*:*)", "", false},
		{"Bash(npm run test:unit:*)", "npm run test:unit", true},
		{"Bash()", "", false},     // empty
		{"Read(/foo)", "", false}, // not Bash
		{"WebFetch(domain:github.com)", "", false},
		{"mcp__atlassian__getJiraIssue", "", false},
		{"Bash(curl ... | sh)", "", false}, // pipe — skipped
		{"Bash(echo $(date))", "", false},  // command sub — skipped
		// Unsafe-legacy filter: these are dropped because the
		// corresponding tier-2 rules were removed in the 2026-04
		// hardening, and a blanket tier-5 allow would undo that.
		{"Bash(awk:*)", "", false},
		{"Bash(sed:*)", "", false},
		{"Bash(env:*)", "", false},
		{"Bash(find:*)", "", false},
		{"Bash(bash:*)", "", false},
		{"Bash(python3:*)", "", false},
		{"Bash(docker exec:*)", "", false},
		{"Bash(docker run alpine:*)", "", false},
		{"Bash(terraform init:*)", "", false},
		{"Bash(terraform import:*)", "", false},
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
	// Use `yarn build*` instead of the old `make test*` since
	// `make` is now unsafe-legacy and gets dropped.
	patterns, skipped := ParseSettingsAllowList([]string{
		"Bash(ls:*)",
		"Bash(git status:*)",
		"Bash(yarn build*:*)",
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
		{"yarn build", true},
		{"yarn buildfoo", true},      // glob
		{"yarn build-thing-x", true}, // glob
		{"yarn install", false},
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

	// Use `yarn build*` for the glob test since `make *` is now
	// unsafe-legacy-filtered.
	patterns, _ := ParseSettingsAllowList([]string{
		"Bash(ls:*)",
		"Bash(git status:*)",
		"Bash(yarn build*:*)",
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
	if loaded.Match("yarn build-fast") == nil {
		t.Error("loaded glob pattern should match")
	}
}

func TestMigrateSettingsJSON(t *testing.T) {
	// Two allow shapes: a legit one (`Bash(ls:*)`), a unsafe-legacy
	// one that post-hardening is filtered (`make *`), and an
	// orthogonal Read entry that's skipped regardless.
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
	// 2 patterns: Bash(ls:*), Bash(git status:*). `make test*` dropped
	// by unsafe-legacy filter; `Read(/foo)` skipped as non-Bash.
	if len(f.Patterns) != 2 {
		t.Errorf("Patterns = %d, want 2", len(f.Patterns))
	}
	if len(f.Skipped) != 2 {
		t.Errorf("Skipped = %d, want 2 (Read entry + unsafe make)", len(f.Skipped))
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

// --- unsafe-legacy filter (2026-04 hardening) ---

func TestIsUnsafeLegacy(t *testing.T) {
	cases := []struct {
		prefix string
		want   bool
	}{
		// Unsafe programs dropped.
		{"awk", true},
		{"awk -F:", true},
		{"sed -i", true},
		{"env", true},
		{"env PATH=/bin", true},
		{"find /tmp", true},
		{"make", true},
		{"make test", true},
		{"make test-fast", true},
		{"bash", true},
		{"bash -c", true},
		{"python", true},
		{"python3 -c", true},
		{"perl -e", true},
		{"ruby -e", true},
		{"node -e", true},
		// Unsafe multi-word prefixes.
		{"docker exec", true},
		{"docker exec container bash", true},
		{"docker run", true},
		{"docker run alpine sh", true},
		{"terraform init", true},
		{"terraform import", true},
		// Safe programs still pass.
		{"ls", false},
		{"ls -la", false},
		{"git status", false},
		{"gcloud builds list", false},
		{"npm run lint", false},
		{"yarn build", false},
		{"docker ps", false},
		{"docker images", false}, // docker alone (no exec/run) OK
		{"terraform plan", false},
		{"terraform apply", false}, // not on unsafe prefix list (yet)
		{"kubectl get pods", false},
		// Edge cases.
		{"", true},         // empty prefix dropped
		{"  ", true},       // whitespace-only dropped
		{"makefoo", false}, // `makefoo` is not `make`; don't false-match
	}
	for _, tc := range cases {
		t.Run(tc.prefix, func(t *testing.T) {
			if got := isUnsafeLegacy(tc.prefix); got != tc.want {
				t.Errorf("isUnsafeLegacy(%q) = %v, want %v", tc.prefix, got, tc.want)
			}
		})
	}
}

// Load must drop unsafe patterns even when they're already written
// in the YAML file (migration happened before hardening).
func TestLoad_DropsUnsafeLegacyEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	// Craft a File that looks like a pre-hardening migration.
	pre := &File{
		Version: SchemaVersion,
		Source:  "test",
		Patterns: []Pattern{
			{Source: "Bash(ls:*)", Prefix: "ls"},
			{Source: "Bash(make test:*)", Prefix: "make test"},
			{Source: "Bash(awk:*)", Prefix: "awk"},
			{Source: "Bash(python3:*)", Prefix: "python3"},
			{Source: "Bash(docker exec:*)", Prefix: "docker exec"},
			{Source: "Bash(git status:*)", Prefix: "git status"},
		},
	}
	if err := WriteFile(path, pre); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// Only `ls` and `git status` should survive.
	if len(loaded.Patterns) != 2 {
		t.Errorf("loaded %d patterns, want 2 (only ls + git status should survive)", len(loaded.Patterns))
		for _, p := range loaded.Patterns {
			t.Logf("  survived: %q", p.Prefix)
		}
	}
	if loaded.Match("make test") != nil {
		t.Error("make test should NOT match after unsafe-legacy filter")
	}
	if loaded.Match("awk 'BEGIN{}'") != nil {
		t.Error("awk should NOT match after unsafe-legacy filter")
	}
	if loaded.Match("python3 -c 'import os'") != nil {
		t.Error("python3 should NOT match after unsafe-legacy filter")
	}
	if loaded.Match("docker exec container sh") != nil {
		t.Error("docker exec should NOT match after unsafe-legacy filter")
	}
	if loaded.Match("ls -la") == nil {
		t.Error("ls must still match")
	}
	if loaded.Match("git status") == nil {
		t.Error("git status must still match")
	}
}

// --- TrustedPrograms ---

func TestTrustedPrograms_DedupAndSort(t *testing.T) {
	a := &AllowList{Patterns: []Pattern{
		{Prefix: "ls"},
		{Prefix: "git status"},
		{Prefix: "git log"}, // same program, different subcommand
		{Prefix: "gcloud builds list"},
		{Prefix: "ls -la"}, // duplicate program
		{Prefix: "taufinity datasheet get"},
	}}
	got := a.TrustedPrograms(0)
	want := []string{"gcloud", "git", "ls", "taufinity"}
	if len(got) != len(want) {
		t.Fatalf("got %d programs, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("[%d] got %q, want %q (full: %v)", i, got[i], w, got)
		}
	}
}

func TestTrustedPrograms_Cap(t *testing.T) {
	a := &AllowList{Patterns: []Pattern{
		{Prefix: "a"}, {Prefix: "b"}, {Prefix: "c"}, {Prefix: "d"},
	}}
	got := a.TrustedPrograms(2)
	if len(got) != 2 {
		t.Fatalf("cap ignored: got %d, want 2 (%v)", len(got), got)
	}
	if got[0] != "a" || got[1] != "b" {
		t.Errorf("cap should keep the first two sorted entries, got %v", got)
	}
}

func TestTrustedPrograms_NilReceiverAndEmpty(t *testing.T) {
	var nilList *AllowList
	if got := nilList.TrustedPrograms(10); got != nil {
		t.Errorf("nil receiver should return nil, got %v", got)
	}
	empty := &AllowList{}
	if got := empty.TrustedPrograms(10); got != nil {
		t.Errorf("empty list should return nil, got %v", got)
	}
}

func TestTrustedPrograms_TrimsGlobStar(t *testing.T) {
	// `make*` is filtered as unsafe-legacy, but defensively test that a
	// trailing '*' on a first word is stripped so we never emit "make*".
	a := &AllowList{Patterns: []Pattern{
		{Prefix: "npmx*"}, // synthetic; not filtered by unsafe-legacy
	}}
	got := a.TrustedPrograms(0)
	if len(got) != 1 || got[0] != "npmx" {
		t.Errorf("trailing '*' should be stripped, got %v", got)
	}
}
