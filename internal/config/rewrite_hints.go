package config

// DefaultRewriteHints maps a tier-1 block rule name to a concrete rewrite
// recipe. The returned strings are appended to the deny reason Claude sees,
// so they must be imperative, short, and reference commands that are already
// in the user's allowlist (Write tool, python3 <file>, etc.).
//
// Contract:
//   - Every key must be the .Name() of a rule in DefaultBlockRules().
//     rewrite_hints_test.go enforces this to prevent drift when rules are
//     renamed.
//   - An absent key is a no-op — the rule denies with its own reason and
//     no hint. Starting minimal and adding entries case-by-case keeps the
//     user-facing copy reviewable.
func DefaultRewriteHints() map[string]string {
	return map[string]string{
		"script-interpreter-exec": "write the code to /tmp/claude-<random>.<ext> with the Write tool, then run `<interpreter> /tmp/claude-<random>.<ext>`. Inline -c/-e cannot be reviewed; a file can.",
		"cp-over-executable-path": "use `install -m 755 <src> <dest>` instead. It writes a temp file and rename(2)s it, so the destination gets a NEW inode and any process already running the old binary keeps its vnode and finishes cleanly. `cp` rewrites in place and the kernel SIGKILLs those processes. `mv` is also safe. Same hazard applies to `go build -o <dest>` and `> <dest>` — build to a temp path, then install.",
	}
}
