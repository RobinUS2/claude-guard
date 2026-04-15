package projectctx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNpmContext_FindsScript(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{
  "name": "my-app",
  "scripts": {
    "build": "vite build",
    "test": "vitest run"
  }
}`)
	out := Context(dir, "npm run build")
	if out == "" {
		t.Fatal("empty context")
	}
	if !strings.Contains(out, "my-app") {
		t.Errorf("missing package name: %s", out)
	}
	if !strings.Contains(out, "vite build") {
		t.Errorf("missing build script body: %s", out)
	}
}

func TestNpmContext_YarnDirectScript(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"scripts":{"start":"node server.js"}}`)
	out := Context(dir, "yarn start")
	if !strings.Contains(out, "node server.js") {
		t.Errorf("yarn direct invocation should resolve: %s", out)
	}
}

func TestNpmContext_PnpmRun(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"scripts":{"check":"tsc --noEmit"}}`)
	out := Context(dir, "pnpm run check")
	if !strings.Contains(out, "tsc --noEmit") {
		t.Errorf("pnpm run should resolve: %s", out)
	}
}

func TestNpmContext_NoPackageJson(t *testing.T) {
	dir := t.TempDir()
	out := Context(dir, "npm run build")
	if out != "" {
		t.Errorf("expected empty context, got: %s", out)
	}
}

func TestNpmContext_WalksUp(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name":"root","scripts":{"build":"echo ok"}}`)
	subdir := filepath.Join(dir, "src", "deep")
	_ = os.MkdirAll(subdir, 0o755)
	out := Context(subdir, "npm run build")
	if !strings.Contains(out, "echo ok") {
		t.Errorf("should find package.json by walking up: %s", out)
	}
}

func TestMakeContext_FindsTarget(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Makefile", `.PHONY: test build deploy

test:
	go test -race ./...

build:
	go build -o bin/app ./cmd/app

deploy:
	./scripts/deploy.sh prod
`)
	out := Context(dir, "make build")
	if !strings.Contains(out, "go build") {
		t.Errorf("should find build recipe: %s", out)
	}
	// Must NOT include unrelated targets.
	if strings.Contains(out, "deploy.sh") {
		t.Errorf("should not include unrelated target: %s", out)
	}
}

func TestMakeContext_NoTargetListsAll(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Makefile", `test:
	go test ./...

build:
	go build ./...
`)
	out := Context(dir, "make")
	if !strings.Contains(out, "test") || !strings.Contains(out, "build") {
		t.Errorf("bare 'make' should list available targets: %s", out)
	}
}

func TestPyContext_PoetryScripts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pyproject.toml", `[tool.poetry]
name = "foo"

[tool.poetry.scripts]
serve = "foo.cli:main"
`)
	out := Context(dir, "poetry run serve")
	if !strings.Contains(out, "foo.cli:main") {
		t.Errorf("should include poetry scripts: %s", out)
	}
}

func TestGoContext_ReadsModule(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", `module github.com/example/foo

go 1.22
`)
	out := Context(dir, "go build ./...")
	if !strings.Contains(out, "github.com/example/foo") {
		t.Errorf("should include module name: %s", out)
	}
}

func TestContext_UnknownCommandReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	out := Context(dir, "ls -la")
	if out != "" {
		t.Errorf("ls should not produce project context: %s", out)
	}
}

func TestContext_EmptyInputs(t *testing.T) {
	if Context("", "ls") != "" {
		t.Error("empty cwd should return empty")
	}
	if Context("/tmp", "") != "" {
		t.Error("empty command should return empty")
	}
}

func TestContext_CapsOutput(t *testing.T) {
	dir := t.TempDir()
	huge := strings.Repeat("x", MaxBytes*2)
	writeFile(t, dir, "package.json", `{"scripts":{"big":"`+huge+`"}}`)
	out := Context(dir, "npm run big")
	if len(out) > MaxBytes {
		t.Errorf("output too large: %d bytes (cap %d)", len(out), MaxBytes)
	}
}

func TestContext_DoesNotReadDotEnv(t *testing.T) {
	// Sanity: even if a .env file exists in the cwd, projectctx
	// should never read it. We don't have an explicit code path
	// that does, but verify by grepping the source... instead
	// just verify by behavior: writing a .env should not appear
	// in any output for any supported command.
	dir := t.TempDir()
	writeFile(t, dir, ".env", "SECRET=hunter2\n")
	writeFile(t, dir, "package.json", `{"scripts":{"start":"node server.js"}}`)
	out := Context(dir, "npm run start")
	if strings.Contains(out, "hunter2") || strings.Contains(out, "SECRET") {
		t.Errorf("CRITICAL: .env content leaked into LLM context: %s", out)
	}
}

func TestExtractNpmScriptName(t *testing.T) {
	cases := map[string]string{
		"npm run build":                   "build",
		"npm run build --silent":          "build",
		"npm run-script test":             "test",
		"yarn start":                      "start",
		"yarn run check":                  "check",
		"pnpm run lint":                   "lint",
		"yarn install":                    "", // builtin, not a script
		"npm install":                     "",
		"yarn add react":                  "",
	}
	for cmd, want := range cases {
		got := extractNpmScriptName(cmd)
		if got != want {
			t.Errorf("extractNpmScriptName(%q) = %q, want %q", cmd, got, want)
		}
	}
}
