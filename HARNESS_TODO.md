# Checklist: guard-stop-followups

Managed by the agent harness. Tick an item (`- [x]`) only when it is fully done.
Every ticked item is independently verified; items that fail are reopened with the reason.
Do not edit or remove items. Add work you discover under "## Discovered" as `- [ ] text`.

## Items

- [x] **T1**: Privacy: cmd/claude-guard/stop.go writes no part of the final assistant message to the decision log,
only its length in bytes; README.md says so. Tests: TestStopLogPrivacy with subtests
no_message_text_logged, message_length_logged.
- [x] **T2**: Transcript rules can see their data: cmd/claude-guard/stop.go reads the transcript file at
`transcript_path` (JSONL, bounded to the last 2 MB) to fill BashCalls, todo items and turn count, so the
transcript-based rules can match in log mode. When the path is missing or unreadable, those rules are
reported as blind (skipped, counted as `blind` in stop-stats) instead of evaluated on empty data, and
proposed-test-not-run only fires when the transcript shows no test run after the proposal. Tests:
TestTranscriptRead with subtests bash_calls_from_transcript, missing_transcript_marks_blind,
proposed_test_run_does_not_fire.
- [x] **T3**: waiting-nothing-running in internal/stop/rules.go also splits clauses at commas, semicolons, colons and
dashes, so these fire: "PR #12 is open, waiting for CI.", "Pushed the fix; waiting for CI.",
"Gepusht, ik wacht nu op de pipeline."; and the existing passing phrases still pass. Tests:
TestStopWaitingClauses with subtests comma_clause_fires, semicolon_clause_fires, dutch_comma_clause_fires,
review_clause_still_passes.

## Discovered

