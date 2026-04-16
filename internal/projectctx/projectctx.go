// Package projectctx reads small, relevant pieces of the project at
// the command's cwd and serializes them into a string that the LLM
// classifier can use to make better decisions.
//
// Why: the fast classifier sees only the command text. For commands
// like `npm run build` or `make deploy`, the safety judgment depends
// on what the script ACTUALLY does, which is defined in package.json
// or Makefile. Without project context, the verifier (and any
// reasonable model) has to be conservative and say "unsure".
//
// What we read (cheap, bounded):
//   - package.json → just the "scripts" key, capped to 1500 chars
//   - Makefile     → the targets the user is invoking, capped to 1500 chars
//   - pyproject.toml → just [tool.poetry.scripts] / [project.scripts] section
//
// We deliberately do NOT read .env, secrets files, or anything that
// could leak credentials into the LLM prompt. The redactor is a
// belt-and-suspenders second line of defense.
package projectctx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// MaxBytes caps any single context block sent to the LLM so a giant
// Makefile or package.json doesn't blow up the prompt.
const MaxBytes = 1500

// Context returns a short, LLM-readable description of the project
// state at cwd that's relevant to the given command. Returns empty
// string when there's nothing useful to add — the LLM falls back to
// reasoning from the command text alone.
//
// This function is on the hot path. It must be fast (~5ms max) and
// cannot block on network or expensive I/O. Reads only known files,
// no recursive walks.
func Context(cwd, command string) string {
	if cwd == "" || command == "" {
		return ""
	}
	cmd := strings.TrimSpace(command)
	first := firstWord(cmd)

	switch first {
	case "npm", "yarn", "pnpm":
		return npmContext(cwd, cmd)
	case "make":
		return makeContext(cwd, cmd)
	case "python", "python3", "uv", "poetry":
		return pyContext(cwd, cmd)
	case "cargo":
		return cargoContext(cwd, cmd)
	case "go":
		return goContext(cwd, cmd)
	}
	return ""
}

// --- npm/yarn/pnpm: read package.json scripts ---

func npmContext(cwd, cmd string) string {
	pj, ok := readNearbyFile(cwd, "package.json", 64*1024)
	if !ok {
		return ""
	}
	var parsed struct {
		Name    string            `json:"name"`
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(pj, &parsed); err != nil {
		return ""
	}
	if len(parsed.Scripts) == 0 {
		return ""
	}

	// Try to identify the script being invoked: `npm run <name>` /
	// `yarn <name>` / `pnpm run <name>`.
	scriptName := extractNpmScriptName(cmd)
	var b strings.Builder
	if parsed.Name != "" {
		fmt.Fprintf(&b, "package: %s\n", parsed.Name)
	}
	if scriptName != "" {
		if body, ok := parsed.Scripts[scriptName]; ok {
			fmt.Fprintf(&b, "script %q: %s\n", scriptName, body)
			return capContext(b.String())
		}
	}
	// Fall back to listing all scripts (helps the LLM understand
	// that this is a real npm project with a small known surface).
	b.WriteString("available scripts:\n")
	for name, body := range parsed.Scripts {
		fmt.Fprintf(&b, "  %s: %s\n", name, body)
	}
	return capContext(b.String())
}

func extractNpmScriptName(cmd string) string {
	// `npm run <name> [args]`
	// `yarn <name> [args]`
	// `pnpm run <name> [args]`
	fields := strings.Fields(cmd)
	if len(fields) < 2 {
		return ""
	}
	switch fields[0] {
	case "npm", "pnpm":
		// Skip flags like --silent and find "run" then the next token.
		for i := 1; i < len(fields); i++ {
			if fields[i] == "run" || fields[i] == "run-script" {
				if i+1 < len(fields) {
					return stripArgSuffix(fields[i+1])
				}
			}
		}
	case "yarn":
		// `yarn <script>` or `yarn run <script>`.
		if fields[1] == "run" && len(fields) >= 3 {
			return stripArgSuffix(fields[2])
		}
		// Skip yarn subcommands that aren't scripts.
		if isYarnBuiltin(fields[1]) {
			return ""
		}
		return stripArgSuffix(fields[1])
	}
	return ""
}

func stripArgSuffix(s string) string {
	// Cut at first space, pipe, or shell metachar.
	for i, ch := range s {
		if ch == ' ' || ch == '|' || ch == '&' || ch == ';' || ch == '>' || ch == '<' {
			return s[:i]
		}
	}
	return s
}

func isYarnBuiltin(name string) bool {
	switch name {
	case "install", "add", "remove", "upgrade", "list", "info", "audit",
		"link", "unlink", "publish", "version", "config", "cache", "global",
		"workspaces", "init":
		return true
	}
	return false
}

// MaxMakefileHashBytes caps the size of a Makefile we'll hash. Bigger
// files fall through (empty hash). Prevents pathological multi-MB
// Makefiles from slowing the hot path.
const MaxMakefileHashBytes = 1 * 1024 * 1024

// MakefileHash returns a stable short hash (first 16 hex chars of
// SHA-256) of the Makefile content that would govern the given
// command, when the command is a simple `make <target>` shape.
// Returns "" in any of these cases:
//
//   - command's first word isn't `make`
//   - command uses `-f <file>`, `-C <dir>`, or `VAR=value` args —
//     can't trust content of a user-specified file / different cwd
//   - no Makefile / GNUmakefile / makefile found within cwd walk
//   - the file is a symlink (TOCTOU / attacker-controlled target;
//     refused via os.Lstat)
//   - file size > MaxMakefileHashBytes
//   - read error
//
// The returned hash feeds into cache.KeyInputs.MakefileHash so a
// cached verdict for `make test` invalidates when the Makefile
// changes. Approvals persist across branches with the same Makefile.
func MakefileHash(cwd, command string) string {
	if cwd == "" || command == "" {
		return ""
	}
	cmd := strings.TrimSpace(command)
	if firstWord(cmd) != "make" {
		return ""
	}
	// Bail on -f / -C / VAR= arg shapes: the command can reference a
	// non-default Makefile path or chdir before running, so our
	// cwd-local hash isn't the right scope. Let LLM decide without a
	// content-hash cache scope.
	fields := strings.Fields(cmd)
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if f == "-f" || f == "-C" || strings.HasPrefix(f, "-f=") || strings.HasPrefix(f, "-C=") {
			return ""
		}
		if strings.Contains(f, "=") && !strings.HasPrefix(f, "-") {
			return ""
		}
	}

	for _, name := range []string{"GNUmakefile", "makefile", "Makefile"} {
		if data, ok := readMakefileForHash(cwd, name); ok {
			sum := sha256.Sum256(data)
			return hex.EncodeToString(sum[:])[:16]
		}
	}
	return ""
}

// readMakefileForHash is a symlink-refusing variant of readNearbyFile.
// Walks cwd up looking for `name`; returns file content if it's a
// regular file (via os.Lstat — refuses symlinks). Size-caps to
// MaxMakefileHashBytes.
func readMakefileForHash(cwd, name string) ([]byte, bool) {
	dir := cwd
	for i := 0; i < 16; i++ {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err == nil {
			// Refuse symlinks — TOCTOU and attacker-swap risk.
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, false
			}
			if info.IsDir() {
				return nil, false
			}
			if info.Size() > MaxMakefileHashBytes {
				return nil, false
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, false
			}
			return data, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, false
		}
		dir = parent
	}
	return nil, false
}

// --- make: read Makefile and find the matching target ---

func makeContext(cwd, cmd string) string {
	data, ok := readNearbyFile(cwd, "Makefile", 256*1024)
	if !ok {
		// Try GNUmakefile and makefile
		data, ok = readNearbyFile(cwd, "GNUmakefile", 256*1024)
	}
	if !ok {
		return ""
	}

	target := extractMakeTarget(cmd)
	if target == "" {
		// Just list available top-level targets to give the LLM a sense
		// of the project shape.
		return capContext("makefile targets:\n" + extractMakeTargets(string(data), 30))
	}

	// Find the recipe for that specific target.
	recipe := extractMakeRecipe(string(data), target)
	if recipe == "" {
		return capContext("makefile target " + target + ": (recipe not found)")
	}
	return capContext(fmt.Sprintf("makefile target %q recipe:\n%s", target, recipe))
}

func extractMakeTarget(cmd string) string {
	// `make <target> [VAR=value ...]` or `make -j 4 <target>`
	fields := strings.Fields(cmd)
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if strings.HasPrefix(f, "-") {
			continue
		}
		if strings.Contains(f, "=") {
			continue // VAR=value
		}
		return stripArgSuffix(f)
	}
	return ""
}

var (
	makeTargetRE = regexp.MustCompile(`(?m)^([a-zA-Z0-9_./-]+)\s*:`)
)

func extractMakeTargets(makefile string, limit int) string {
	matches := makeTargetRE.FindAllStringSubmatch(makefile, -1)
	var b strings.Builder
	seen := map[string]bool{}
	count := 0
	for _, m := range matches {
		name := m[1]
		if seen[name] || strings.HasPrefix(name, ".") {
			continue
		}
		seen[name] = true
		b.WriteString("  ")
		b.WriteString(name)
		b.WriteByte('\n')
		count++
		if count >= limit {
			break
		}
	}
	return b.String()
}

func extractMakeRecipe(makefile, target string) string {
	lines := strings.Split(makefile, "\n")
	var out []string
	inTarget := false
	prefix := target + ":"
	for _, line := range lines {
		if !inTarget {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, prefix) || strings.HasPrefix(t, target+" :") {
				inTarget = true
				out = append(out, line)
				continue
			}
		} else {
			// Recipes are tab-indented.
			if strings.HasPrefix(line, "\t") || strings.TrimSpace(line) == "" {
				out = append(out, line)
				continue
			}
			// New target started — stop.
			break
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n")
}

// --- python: pyproject.toml [project.scripts] / [tool.poetry.scripts] ---

func pyContext(cwd, cmd string) string {
	data, ok := readNearbyFile(cwd, "pyproject.toml", 64*1024)
	if !ok {
		return ""
	}
	// Cheap section-only extract — we don't pull in a TOML parser.
	out := extractTomlSection(string(data), []string{"project.scripts", "tool.poetry.scripts"})
	if out == "" {
		return ""
	}
	return capContext("pyproject.toml scripts:\n" + out)
}

func extractTomlSection(toml string, sections []string) string {
	lines := strings.Split(toml, "\n")
	var out []string
	inSection := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			header := strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
			inSection = false
			for _, s := range sections {
				if header == s {
					inSection = true
					out = append(out, line)
					break
				}
			}
			continue
		}
		if inSection && t != "" {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// --- cargo: read Cargo.toml package name + the binary list ---

func cargoContext(cwd, cmd string) string {
	data, ok := readNearbyFile(cwd, "Cargo.toml", 64*1024)
	if !ok {
		return ""
	}
	// Just include [package] and any [[bin]] sections.
	out := extractTomlSection(string(data), []string{"package"})
	if out == "" {
		return ""
	}
	return capContext("cargo project:\n" + out)
}

// --- go: read go.mod for the module name ---

func goContext(cwd, cmd string) string {
	data, ok := readNearbyFile(cwd, "go.mod", 8*1024)
	if !ok {
		return ""
	}
	first := strings.SplitN(string(data), "\n", 3)
	out := strings.Join(first[:min(2, len(first))], "\n")
	return capContext("go module:\n" + out)
}

// --- helpers ---

// readNearbyFile walks up from cwd looking for a file with the given
// name, capped at maxSize bytes and 16 levels of ascent. Returns
// (contents, true) on success.
func readNearbyFile(cwd, name string, maxSize int) ([]byte, bool) {
	dir := cwd
	for i := 0; i < 16; i++ {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			if info.Size() > int64(maxSize) {
				return nil, false
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, false
			}
			return data, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, false
		}
		dir = parent
	}
	return nil, false
}

func capContext(s string) string {
	if len(s) <= MaxBytes {
		return s
	}
	return s[:MaxBytes-3] + "..."
}

func firstWord(s string) string {
	for i, ch := range s {
		if ch == ' ' || ch == '\t' {
			return s[:i]
		}
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
