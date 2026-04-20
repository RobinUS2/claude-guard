package config

import "testing"

// Every key in DefaultRewriteHints must match the .Name() of a rule in
// DefaultBlockRules. Without this test, renaming a rule silently orphans
// its hint and nothing surfaces to Claude.
func TestDefaultRewriteHints_KeysMatchBlockRules(t *testing.T) {
	blockNames := make(map[string]bool)
	for _, r := range DefaultBlockRules() {
		blockNames[r.Name()] = true
	}
	for hintName := range DefaultRewriteHints() {
		if !blockNames[hintName] {
			t.Errorf("DefaultRewriteHints key %q does not match any DefaultBlockRules rule name", hintName)
		}
	}
}

// Hint strings must be non-empty. An empty hint is a bug — it would emit
// "reason\n\nRewrite: " with nothing after the colon.
func TestDefaultRewriteHints_NoEmptyValues(t *testing.T) {
	for name, hint := range DefaultRewriteHints() {
		if hint == "" {
			t.Errorf("hint for rule %q is empty", name)
		}
	}
}

// script-interpreter-exec is the motivating case for this feature; if it
// ever goes missing, the PR that removes it should at least have to update
// this assertion.
func TestDefaultRewriteHints_HasScriptInterpreterExec(t *testing.T) {
	if _, ok := DefaultRewriteHints()["script-interpreter-exec"]; !ok {
		t.Error("script-interpreter-exec hint missing — this was the motivating rule")
	}
}
