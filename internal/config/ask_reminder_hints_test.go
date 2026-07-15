package config

import "testing"

// Every key in DefaultAskReminderHints must match the .Name() of a rule in
// DefaultAskReminderRules. Without this test, renaming a rule silently
// orphans its hint and the generic prefer-API hint would be shown instead,
// with no warning.
func TestDefaultAskReminderHints_KeysMatchAskReminderRules(t *testing.T) {
	askNames := make(map[string]bool)
	for _, r := range DefaultAskReminderRules() {
		askNames[r.Name()] = true
	}
	for hintName := range DefaultAskReminderHints() {
		if !askNames[hintName] {
			t.Errorf("DefaultAskReminderHints key %q does not match any DefaultAskReminderRules rule name", hintName)
		}
	}
}

// Hint strings must be non-empty. An empty override hint would silently
// suppress the fallback generic hint with nothing in its place.
func TestDefaultAskReminderHints_NoEmptyValues(t *testing.T) {
	for name, hint := range DefaultAskReminderHints() {
		if hint == "" {
			t.Errorf("hint for rule %q is empty", name)
		}
	}
}

// gh-api-mutation is the motivating case for this feature; if it ever goes
// missing, the PR that removes it should at least have to update this
// assertion.
func TestDefaultAskReminderHints_HasGhApiMutation(t *testing.T) {
	if _, ok := DefaultAskReminderHints()["gh-api-mutation"]; !ok {
		t.Error("gh-api-mutation hint missing — this was the motivating rule")
	}
}
