# Checklist: guard-stop-hook-io-fix

Managed by the agent harness. Tick an item (`- [x]`) only when it is fully done.
Every ticked item is independently verified; items that fail are reopened with the reason.
Do not edit or remove items. Add work you discover under "## Discovered" as `- [ ] text`.

## Items

- [x] **T1**: Input: cmd/claude-guard/stop.go reads the documented Stop hook input, `last_assistant_message`,
`stop_hook_active`, `session_id`, `transcript_path`, `background_tasks`, `session_crons`, and fills
Transcript.LastAssistantText from last_assistant_message (falling back to the old transcript array only
when last_assistant_message is absent). background_tasks and session_crons: an empty array means known and
nothing running; null, absent or non-array means unknown. Tests: TestStopInput with subtests
last_assistant_message_read, empty_arrays_known_nothing_running, null_fields_unknown,
non_array_fields_unknown.
  - verified
- [x] **T2**: Output: when an ENFORCED rule fires, cmd/claude-guard/stop.go prints {"decision":"block","reason":"<the
rule's message>"} (the documented shape); otherwise {}. End-to-end test that runs the hook's entry point
with a docs-shaped stdin JSON ("Waiting for CI on PR 12.", empty background_tasks and session_crons) and
asserts the block output, plus the same input with one background task asserting {}. Tests: TestStopE2E
with subtests waiting_nothing_running_blocks, background_task_lets_it_stop, stop_hook_active_lets_it_stop.
  - verified
- [x] **T3**: Per-rule mode in internal/stop/stop.go: every rule is `enforce` or `log`, configurable in the existing
claude-guard config (document the key), default log for all rules except waiting-nothing-running, which
defaults to enforce. A log-mode rule that matches writes a "would block" record (rule name, session id,
time) to the decision log and lets the session stop. Tests: TestRuleMode with subtests
default_only_waiting_enforces, log_mode_records_would_block, config_override_enforces.
  - verified
- [x] **T4**: Tighten waiting-nothing-running in internal/stop/rules.go: it matches only when the session says IT is
waiting on a machine process (CI, checks, a build, a deploy, a pipeline, a job, a run, an agent, a test
suite), in English or Dutch. It never matches waiting on a person or a decision (your review, approval,
akkoord, an answer, the owner), negations ("not waiting"), text inside code blocks or quotes, or bare
"zodra" / "wacht op" without a machine target. Tests: TestStopWaitingPhrases with subtests
waiting_for_ci_matches, wacht_op_de_build_matches, waiting_for_your_review_passes,
blocked_on_owner_approval_passes, not_waiting_passes, quoted_text_passes, code_block_passes,
wacht_op_jouw_akkoord_passes, zodra_je_merget_passes.
  - verified
- [x] **T5**: Numbers for the week: add `claude-guard stop-stats [--since 7d]`, which reads the decision log and prints
per rule how often it would have blocked (log mode) or did block (enforce), and in how many distinct
sessions; no message text. Put it in cmd/claude-guard/stopstats.go. Tests: TestStopStats with subtests
counts_per_rule, distinct_sessions, since_filter.
  - verified
- [x] **T6**: README.md: describe what the Stop hook reads and returns, the enforce/log switch and its defaults, that only
waiting-nothing-running enforces by default, and `stop-stats`. Remove any claim that the other rules send a
session back to work while they are in log mode.
  - verified

## Discovered

