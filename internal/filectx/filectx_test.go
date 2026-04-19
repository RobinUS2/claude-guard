package filectx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

func parseFirst(t *testing.T, cmd string) shellparse.Call {
	t.Helper()
	p, err := shellparse.Parse(cmd)
	if err != nil {
		t.Fatalf("parse %q: %v", cmd, err)
	}
	if len(p.Calls) == 0 {
		t.Fatalf("no calls in %q", cmd)
	}
	return p.Calls[0]
}

func TestExtract_GoRun(t *testing.T) {
	f := filepath.Join(t.TempDir(), "main.go")
	os.WriteFile(f, []byte("package main\nfunc main() {}\n"), 0o644)

	call := parseFirst(t, "go run "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for go run")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
	if fc.Content == "" {
		t.Fatal("expected file content")
	}
	if fc.Path != f {
		t.Errorf("Path = %q, want %q", fc.Path, f)
	}
}

func TestExtract_PythonScript(t *testing.T) {
	f := filepath.Join(t.TempDir(), "script.py")
	os.WriteFile(f, []byte("print('hello')\n"), 0o644)

	call := parseFirst(t, "python3 "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for python3")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
	if !strings.Contains(fc.Content, "hello") {
		t.Errorf("content missing expected text: %q", fc.Content)
	}
}

func TestExtract_NodeScript(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.js")
	os.WriteFile(f, []byte("console.log('hi')\n"), 0o644)

	call := parseFirst(t, "node "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for node")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_NotARunner(t *testing.T) {
	call := parseFirst(t, "git status")
	fc := Extract(call)
	if fc != nil {
		t.Fatalf("expected nil for non-runner, got %+v", fc)
	}
}

func TestExtract_FileTooLarge(t *testing.T) {
	f := filepath.Join(t.TempDir(), "big.go")
	os.WriteFile(f, make([]byte, MaxFileSize+1), 0o644)

	call := parseFirst(t, "go run "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext")
	}
	if !fc.Skipped {
		t.Fatal("expected Skipped for large file")
	}
	if !strings.Contains(fc.Reason, "exceeds") {
		t.Errorf("Reason = %q, want 'exceeds' substring", fc.Reason)
	}
}

func TestExtract_BinaryFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "binary.py")
	data := make([]byte, 100)
	data[50] = 0x00 // null byte
	os.WriteFile(f, data, 0o644)

	call := parseFirst(t, "python3 "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext")
	}
	if !fc.Skipped {
		t.Fatal("expected Skipped for binary file")
	}
	if !strings.Contains(fc.Reason, "binary") {
		t.Errorf("Reason = %q, want 'binary' substring", fc.Reason)
	}
}

func TestExtract_Symlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.go")
	link := filepath.Join(dir, "link.go")
	os.WriteFile(real, []byte("package main\n"), 0o644)
	os.Symlink(real, link)

	call := parseFirst(t, "go run "+link)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext")
	}
	if !fc.Skipped {
		t.Fatal("expected Skipped for symlink")
	}
	if !strings.Contains(fc.Reason, "symlink") {
		t.Errorf("Reason = %q, want 'symlink' substring", fc.Reason)
	}
}

func TestExtract_FileNotFound(t *testing.T) {
	call := parseFirst(t, "go run /nonexistent/path/main.go")
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext")
	}
	if !fc.Skipped {
		t.Fatal("expected Skipped for missing file")
	}
	if !strings.Contains(fc.Reason, "not found") {
		t.Errorf("Reason = %q, want 'not found' substring", fc.Reason)
	}
}

func TestExtract_GoRunWithFlags(t *testing.T) {
	f := filepath.Join(t.TempDir(), "main.go")
	os.WriteFile(f, []byte("package main\nfunc main() {}\n"), 0o644)

	// go run -v main.go — flags before the file arg.
	call := parseFirst(t, "go run -v "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for go run with flags")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_DenoRun(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.ts")
	os.WriteFile(f, []byte("console.log('deno')\n"), 0o644)

	call := parseFirst(t, "deno run "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for deno run")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_RubyScript(t *testing.T) {
	f := filepath.Join(t.TempDir(), "script.rb")
	os.WriteFile(f, []byte("puts 'hello'\n"), 0o644)

	call := parseFirst(t, "ruby "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for ruby")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_TsxScript(t *testing.T) {
	f := filepath.Join(t.TempDir(), "run.ts")
	os.WriteFile(f, []byte("console.log('tsx')\n"), 0o644)

	call := parseFirst(t, "tsx "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for tsx")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_BunRunScriptName_ReturnsNil(t *testing.T) {
	// "bun run dev" is a package.json script, not a file — should return nil.
	call := parseFirst(t, "bun run dev")
	fc := Extract(call)
	if fc != nil {
		t.Fatalf("expected nil for bun run script name, got %+v", fc)
	}
}

func TestExtract_BunRunFilePath(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.ts")
	os.WriteFile(f, []byte("console.log('bun')\n"), 0o644)

	call := parseFirst(t, "bun run "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for bun run with file path")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_CompoundCommand_FirstRunnerOnly(t *testing.T) {
	// "go run /tmp/test.go && echo done" — parseFirst returns "go" call.
	f := filepath.Join(t.TempDir(), "test.go")
	os.WriteFile(f, []byte("package main\nfunc main() {}\n"), 0o644)

	// Parse full compound command, extract from first call.
	p, err := shellparse.Parse("go run " + f + " && echo done")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Calls) < 1 {
		t.Fatal("expected at least 1 call")
	}
	fc := Extract(p.Calls[0])
	if fc == nil {
		t.Fatal("expected FileContext from first call of compound command")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}
