package config

// DefaultAskReminderHints maps a tier-1.6 ask-reminder rule name to a hint
// appended to the Ask prompt, for rules whose nudge isn't the generic
// "prefer the API/MCP over direct DB access" message (that default lives in
// engine.preferAPIHint and is used for any ask-reminder rule with no entry
// here).
//
// Contract:
//   - Every key must be the .Name() of a rule in DefaultAskReminderRules().
//     ask_reminder_hints_test.go enforces this to prevent drift when rules
//     are renamed.
//   - An absent key falls back to the generic prefer-API hint — this map is
//     only for rules that need a different message.
func DefaultAskReminderHints() map[string]string {
	return map[string]string{
		"gh-api-mutation": "This changes GitHub state directly (repo settings, rulesets, branch protection, etc.) and can't be reviewed as a diff the way a file edit can. Confirm the exact API path and payload before approving.",
	}
}
