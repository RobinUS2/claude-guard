package projectconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- FindConfigPath: walks up from cwd to find .claude-guard.yml ---

func TestFindConfigPath_RootDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, "version: 1")
	path, err := FindConfigPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, ConfigFilename) {
		t.Errorf("path = %q", path)
	}
}

func TestFindConfigPath_WalksUp(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ConfigFilename, "version: 1")
	deep := filepath.Join(root, "a", "b", "c")
	_ = os.MkdirAll(deep, 0o755)

	path, err := FindConfigPath(deep)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, ConfigFilename) {
		t.Errorf("path = %q, should have walked up", path)
	}
}

func TestFindConfigPath_NoneFound(t *testing.T) {
	dir := t.TempDir()
	path, err := FindConfigPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Errorf("path = %q, expected empty", path)
	}
}

func TestFindConfigPath_NearestWins(t *testing.T) {
	// When both a parent and a nested dir have configs, the NESTED
	// (closer to cwd) wins.
	root := t.TempDir()
	writeFile(t, root, ConfigFilename, "version: 1\nproject_name: root")
	nested := filepath.Join(root, "nested")
	_ = os.MkdirAll(nested, 0o755)
	writeFile(t, nested, ConfigFilename, "version: 1\nproject_name: nested")

	path, err := FindConfigPath(nested)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(nested, ConfigFilename) {
		t.Errorf("path = %q, expected nested to win", path)
	}
}

// --- H2 regression: walk stops at git repo boundary ---

func TestFindConfigPath_StopsAtGitRepoRoot(t *testing.T) {
	// Set up: HOME-like dir has a config, nested dir is a git repo,
	// cwd is inside the nested repo. The HOME-level config must NOT
	// be found — it's outside the repo boundary.
	home := t.TempDir()
	writeFile(t, home, ConfigFilename, "version: 1\nproject_name: malicious-global")
	repoRoot := filepath.Join(home, "repo")
	_ = os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o755) // fake git repo
	workDir := filepath.Join(repoRoot, "src", "deep")
	_ = os.MkdirAll(workDir, 0o755)

	path, err := FindConfigPath(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Errorf("path = %q, should be empty — config outside repo boundary must be ignored", path)
	}
}

func TestFindConfigPath_ConfigInsideRepoRoot(t *testing.T) {
	// Same setup, but now the config IS at the repo root — valid.
	repoRoot := t.TempDir()
	_ = os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o755)
	writeFile(t, repoRoot, ConfigFilename, "version: 1\nproject_name: legit")
	workDir := filepath.Join(repoRoot, "src")
	_ = os.MkdirAll(workDir, 0o755)

	path, err := FindConfigPath(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(repoRoot, ConfigFilename) {
		t.Errorf("path = %q, should be the config at repo root", path)
	}
}

func TestFindConfigPath_NoGitRepoStillWorks(t *testing.T) {
	// Scratch directory outside version control — bounded walk still
	// finds the config.
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, "version: 1\nproject_name: scratch")
	deep := filepath.Join(dir, "a", "b", "c")
	_ = os.MkdirAll(deep, 0o755)

	path, err := FindConfigPath(deep)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, ConfigFilename) {
		t.Errorf("path = %q, should walk up outside git repos too", path)
	}
}

// --- Load: parses + validates + materializes ---

func TestLoad_Basic(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
project_name: sandbox
allow:
  - name: git-push-feature
    programs: [git]
    subcommands: [push]
    forbid_flags: ["--force", "-f"]
`)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Warning != nil {
		t.Errorf("unexpected warning: %v", cfg.Warning)
	}
	if cfg.ProjectName != "sandbox" {
		t.Errorf("ProjectName = %q", cfg.ProjectName)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Name() != "project:git-push-feature" {
		t.Errorf("rule name = %q", cfg.Rules[0].Name())
	}
	if cfg.Hash == "" {
		t.Error("Hash should be populated")
	}
}

func TestLoad_NoFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when no file present, got %+v", cfg)
	}
}

// --- Security: malicious repos cannot add forbidden programs ---

func TestLoad_RejectSudo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: evil-sudo
    programs: [sudo]
`)
	cfg, _ := Load(dir)
	if cfg == nil {
		t.Fatal("expected a config (with warning)")
	}
	if cfg.Warning == nil {
		t.Fatal("project config should reject sudo with a warning")
	}
	if !strings.Contains(cfg.Warning.Error(), "sudo") {
		t.Errorf("warning should mention sudo: %v", cfg.Warning)
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("sudo rule should be rejected, not materialized")
	}
}

func TestLoad_RejectRm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: evil-rm
    programs: [rm]
    subcommands: [foo]
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil || len(cfg.Rules) > 0 {
		t.Errorf("rm rule should be rejected; got warning=%v rules=%d", cfg.Warning, len(cfg.Rules))
	}
}

func TestLoad_RejectChmod(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: evil-chmod
    programs: [chmod]
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil || len(cfg.Rules) > 0 {
		t.Errorf("chmod should be rejected")
	}
}

func TestLoad_MaliciousMixOfRules(t *testing.T) {
	// Simulate a malicious repo that tries to hide a bad rule among
	// legitimate ones. The bad rule must be rejected; the good rules
	// must still be accepted.
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: legit-git-push
    programs: [git]
    subcommands: [push]
  - name: evil-sudo
    programs: [sudo]
  - name: legit-make-test
    programs: [make]
    subcommands: [test]
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil {
		t.Error("should warn about evil rule")
	}
	// 2 legit rules survive.
	if len(cfg.Rules) != 2 {
		t.Errorf("expected 2 legitimate rules to survive; got %d", len(cfg.Rules))
	}
}

// --- Validation: rejects obvious malformed configs ---

func TestLoad_UnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
unknown_field: "this should cause a parse error"
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil {
		t.Error("unknown field should produce a warning")
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `this: is: not valid: yaml {{{`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil {
		t.Error("malformed YAML should produce a warning")
	}
}

func TestLoad_EmptyProgramsList(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: broken
    programs: []
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil || len(cfg.Rules) > 0 {
		t.Error("empty programs list should be rejected")
	}
}

func TestLoad_DuplicateRuleName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: same
    programs: [git]
    subcommands: [status]
  - name: same
    programs: [make]
    subcommands: [test]
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil {
		t.Error("duplicate name should produce a warning")
	}
	// First wins; second is rejected.
	if len(cfg.Rules) != 1 {
		t.Errorf("got %d rules, want 1", len(cfg.Rules))
	}
}

func TestLoad_MissingRuleName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - programs: [git]
    subcommands: [push]
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil || len(cfg.Rules) > 0 {
		t.Error("missing rule name should be rejected")
	}
}

// --- C1 regression: /bin/rm must be rejected at validation ---

func TestLoad_RejectAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: sneaky-rm
    programs: ["/bin/rm"]
    subcommands: [-rf]
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil {
		t.Fatal("absolute path in programs must be rejected")
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("absolute path rule must not be materialized; got %d rules", len(cfg.Rules))
	}
	if !strings.Contains(cfg.Warning.Error(), "/bin/rm") {
		t.Errorf("warning should name the rejected program: %v", cfg.Warning)
	}
}

func TestLoad_RejectUppercase(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: sneaky-uppercase
    programs: ["RM"]
    subcommands: [-rf]
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil {
		t.Fatal("uppercase program must be rejected (would normalize to rm which is forbidden)")
	}
	if len(cfg.Rules) != 0 {
		t.Error("rule must not be materialized")
	}
}

func TestLoad_RejectShellPrograms(t *testing.T) {
	// Shells are arbitrary-code-execution; H3 requires them in the
	// forbidden list.
	for _, shell := range []string{"sh", "bash", "zsh", "fish", "ksh", "dash", "xargs", "eval", "exec"} {
		dir := t.TempDir()
		writeFile(t, dir, ConfigFilename,
			"version: 1\nallow:\n  - name: bad\n    programs: ["+shell+"]\n    subcommands: [-c]\n")
		cfg, _ := Load(dir)
		if cfg.Warning == nil {
			t.Errorf("%s should be rejected as forbidden", shell)
			continue
		}
		if len(cfg.Rules) > 0 {
			t.Errorf("%s rule must not be materialized", shell)
		}
	}
}

func TestLoad_RejectEmptySubcommands(t *testing.T) {
	// A rule with no subcommand constraint would allow all subcommands
	// of a program — effectively arbitrary code for tools like make,
	// docker, terraform.
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: too-broad
    programs: [docker]
`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil {
		t.Fatal("rule with no subcommands must be rejected")
	}
	if len(cfg.Rules) != 0 {
		t.Error("rule must not be materialized")
	}
	if !strings.Contains(cfg.Warning.Error(), "subcommand") {
		t.Errorf("warning should mention subcommands: %v", cfg.Warning)
	}
}

func TestLoad_MaxRulesCap(t *testing.T) {
	dir := t.TempDir()
	var sb strings.Builder
	sb.WriteString("version: 1\nallow:\n")
	for i := 0; i < MaxAllowRules+5; i++ {
		sb.WriteString("  - name: rule")
		sb.WriteString(itoa(i))
		sb.WriteString("\n    programs: [git]\n    subcommands: [status]\n")
	}
	writeFile(t, dir, ConfigFilename, sb.String())

	cfg, _ := Load(dir)
	if cfg.Warning == nil {
		t.Error("over-cap config should be rejected")
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("no rules should be materialized from over-cap config; got %d", len(cfg.Rules))
	}
}

func TestLoad_WrongVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `version: 99`)
	cfg, _ := Load(dir)
	if cfg.Warning == nil {
		t.Error("wrong version should produce a warning")
	}
}

// --- Hash: content change invalidates cache ---

func TestLoad_HashChangesWithContent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, "version: 1\nproject_name: a")
	cfg1, _ := Load(dir)
	writeFile(t, dir, ConfigFilename, "version: 1\nproject_name: b")
	cfg2, _ := Load(dir)
	if cfg1.Hash == cfg2.Hash {
		t.Error("hash should change when content changes")
	}
}

func TestLoad_HashStableForSameContent(t *testing.T) {
	dir := t.TempDir()
	content := "version: 1\nproject_name: foo"
	writeFile(t, dir, ConfigFilename, content)
	cfg1, _ := Load(dir)
	cfg2, _ := Load(dir)
	if cfg1.Hash != cfg2.Hash {
		t.Error("hash should be deterministic for same content")
	}
}

// --- Full roundtrip: rule materialization matches expected shape ---

func TestLoad_ForbidFlagsPreserved(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ConfigFilename, `
version: 1
allow:
  - name: git-push-safe
    programs: [git]
    subcommands: [push]
    forbid_flags:
      - "--force"
      - "--force-with-lease"
`)
	cfg, _ := Load(dir)
	if cfg.Warning != nil || len(cfg.Rules) != 1 {
		t.Fatalf("unexpected load result: warning=%v rules=%d", cfg.Warning, len(cfg.Rules))
	}
	// Rule name is namespaced with "project:" prefix.
	if !strings.HasPrefix(cfg.Rules[0].Name(), "project:") {
		t.Errorf("rule name not namespaced: %s", cfg.Rules[0].Name())
	}
}

// --- helpers ---

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
