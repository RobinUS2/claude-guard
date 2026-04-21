// Package filectx detects runner commands (go run, python, node, etc.)
// and extracts the contents of the referenced file for LLM analysis.
//
// Security constraints:
//   - No symlink following (os.Lstat, not os.Stat)
//   - Max file size enforced (20KB)
//   - Binary files detected and skipped (null byte check)
//   - Read-only: never modifies files
//   - Only the directly referenced file, no transitive imports
package filectx

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

// MaxFileSize is the largest file we'll read. Files exceeding this are
// skipped — the LLM classifies based on the command string alone.
const MaxFileSize = 20 * 1024 // 20KB

// FileContext holds the result of examining a runner command.
type FileContext struct {
	Path    string // absolute path of the file
	Content string // file contents (empty if skipped)
	Size    int64  // file size in bytes
	Skipped bool   // true if file was detected but not read
	Reason  string // why it was skipped
}

// runner defines a program that executes a file argument.
type runner struct {
	program string // e.g. "go", "python3"
	subcmd  string // e.g. "run" (empty = file is first positional)
}

// runners is the known runner table. Order doesn't matter — we match
// on program name.
//
// Shells (bash/sh/zsh) are included so `bash path/to/script.sh` surfaces
// the script contents to the LLM. `bash -c '<cmd>'` is tier-1 denied by
// shell-dash-c before we ever get here, so there's no risk of treating
// an inline command string as a file path.
var runners = []runner{
	{program: "go", subcmd: "run"},
	{program: "python"},
	{program: "python3"},
	{program: "node"},
	{program: "tsx"},
	{program: "deno", subcmd: "run"},
	{program: "ruby"},
	{program: "bun", subcmd: "run"},
	{program: "bash"},
	{program: "sh"},
	{program: "zsh"},
}

// Extract examines a parsed command and returns file context if the
// command is a runner with a readable file argument. Returns nil if
// the command is not a runner pattern.
func Extract(call shellparse.Call) *FileContext {
	prog := strings.ToLower(call.Program)
	if prog == "" {
		return nil
	}

	for _, r := range runners {
		if prog != r.program {
			continue
		}
		filePath := findFileArg(call, r)
		if filePath == "" {
			return nil
		}
		return readFile(filePath)
	}
	return nil
}

// findFileArg locates the file argument in the parsed call based on
// the runner definition.
func findFileArg(call shellparse.Call, r runner) string {
	positionals := call.Positional
	if len(positionals) == 0 {
		return ""
	}

	if r.subcmd == "" {
		// File is the first positional that looks like a file path
		// (not a flag). Positional already excludes flags.
		for _, p := range positionals {
			if p != "" {
				return p
			}
		}
		return ""
	}

	// Has subcommand (e.g. "go run"): find subcmd in positionals,
	// then the file arg is the next non-empty positional after it.
	found := false
	for _, p := range positionals {
		if !found {
			if strings.ToLower(p) == r.subcmd {
				found = true
			}
			continue
		}
		// Skip empty (unresolved) args.
		if p != "" {
			// For "bun run", distinguish script names from file paths.
			// File paths contain a slash or have a known extension.
			if r.program == "bun" && !looksLikeFilePath(p) {
				return ""
			}
			return p
		}
	}
	return ""
}

// looksLikeFilePath returns true if the argument looks like a file path
// rather than a package.json script name.
func looksLikeFilePath(arg string) bool {
	if strings.Contains(arg, "/") || strings.Contains(arg, "\\") {
		return true
	}
	// Check for common source file extensions.
	for _, ext := range []string{".go", ".py", ".js", ".ts", ".tsx", ".jsx", ".rb", ".mjs", ".cjs"} {
		if strings.HasSuffix(strings.ToLower(arg), ext) {
			return true
		}
	}
	return false
}

// readFile reads the file at path with all safety checks.
func readFile(path string) *FileContext {
	fc := &FileContext{Path: path}

	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		fc.Skipped = true
		fc.Reason = "file not found"
		return fc
	}
	if err != nil {
		fc.Skipped = true
		fc.Reason = fmt.Sprintf("stat error: %v", err)
		return fc
	}

	// No symlinks.
	if info.Mode()&os.ModeSymlink != 0 {
		fc.Skipped = true
		fc.Reason = "symlink — not followed for security"
		return fc
	}
	if !info.Mode().IsRegular() {
		fc.Skipped = true
		fc.Reason = "not a regular file"
		return fc
	}

	fc.Size = info.Size()
	if fc.Size > MaxFileSize {
		fc.Skipped = true
		fc.Reason = fmt.Sprintf("exceeds %dKB limit (%d bytes)", MaxFileSize/1024, fc.Size)
		return fc
	}

	// Open the file and re-verify via Fstat to close the TOCTOU window
	// between Lstat and read. A malicious process could replace the
	// regular file with a symlink between those two calls.
	f, err := os.Open(path)
	if err != nil {
		fc.Skipped = true
		fc.Reason = fmt.Sprintf("open error: %v", err)
		return fc
	}
	defer f.Close()

	finfo, err := f.Stat()
	if err != nil || !finfo.Mode().IsRegular() || finfo.Size() != info.Size() {
		fc.Skipped = true
		fc.Reason = "file changed during read (TOCTOU safety)"
		return fc
	}

	data, err := io.ReadAll(f)
	if err != nil {
		fc.Skipped = true
		fc.Reason = fmt.Sprintf("read error: %v", err)
		return fc
	}

	// Binary check: look for null bytes in first 512 bytes.
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	if bytes.IndexByte(check, 0) >= 0 {
		fc.Skipped = true
		fc.Reason = "binary file detected (null bytes)"
		return fc
	}

	fc.Content = string(data)
	return fc
}
