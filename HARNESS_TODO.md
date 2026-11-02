# Checklist: guard-stop-followups-2

Managed by the agent harness. Tick an item (`- [x]`) only when it is fully done.
Every ticked item is independently verified; items that fail are reopened with the reason.
Do not edit or remove items. Add work you discover under "## Discovered" as `- [ ] text`.

## Items

- [x] **T1**: Blocker: in internal/stop/stop.go, a rule in log mode whose evaluation would call an external service
(llm-semantic-review) is skipped entirely: no call, no record beyond "skipped in log mode". Prove with a
fake HTTP transport that 5 stops in one session make 0 calls in log mode, and that enforce mode still
respects its once-per-session cap. Also add llm-semantic-review to the blind-rule list when the
transcript is missing. Tests: TestLLMRuleLogMode with subtests no_external_call_in_log_mode,
enforce_mode_capped_once, blind_without_transcript.
- [x] **T2**: proposed-test-not-run in internal/stop/rules.go compares by message order, not line order: a test command
run in the same turn (any Bash call after the assistant proposed the test, in the transcript's message
sequence) means the test ran. Use a real-shape transcript fixture (each content block on its own JSONL
line, final text after the Bash calls) under internal/stop/testdata/. Tests: TestProposedTestRun with
subtests ran_in_same_turn_does_not_fire, never_ran_fires.
- [x] **T3**: stop-stats in cmd/claude-guard/stopstats.go counts in SESSIONS only sessions where the rule matched (would
block or did block); blind sessions get their own BLIND column. Tests: TestStopStats with subtests
sessions_exclude_blind, blind_column_counts.
- [x] **T4**: gofmt: every Go file this branch touches is gofmt-clean.

## Discovered

