# Checklist: guard-stop-waiting-nothing-running

Managed by the agent harness. Tick an item (`- [x]`) only when it is fully done.
Every ticked item is independently verified; items that fail are reopened with the reason.
Do not edit or remove items. Add work you discover under "## Discovered" as `- [ ] text`.

## Items

- [x] **T1**: Parse `background_tasks` and `session_crons` from the Stop hook input in cmd/claude-guard/stop.go
into new fields on stop.Transcript: BackgroundTasks int and SessionCrons int, plus a bool
RunningKnown that is true only when the input contained at least one of the two fields.
Tests: TestParseStopInput with subtests background_tasks_counted, crons_counted, fields_missing_unknown.
  - verified
- [x] **T2**: Add rule `waiting-nothing-running` in internal/stop/rules.go, registered in DefaultRules. It fires when
RunningKnown is true, BackgroundTasks == 0 and SessionCrons == 0, and the last assistant text says the
session is waiting on something to finish (CI, checks, a build, a deploy, a pipeline, a review, an agent,
a run; English and Dutch: "waiting for", "wait for", "once CI", "when the build finishes", "I'll check
back", "wacht op", "zodra"). Its continue message: "You said you are waiting, but nothing is running that
will wake you: start a watcher in the background (for example `gh pr checks <n> --watch --fail-fast`),
or report the item as blocked with what it waits on." MaxContinues 1, not high-confidence.
Tests: TestStopWaiting with subtests waiting_nothing_running_blocks, waiting_with_background_task_passes,
waiting_with_cron_passes, not_waiting_passes, unknown_running_passes, second_stop_passes.
  - verified
- [x] **T3**: Document the rule in README.md's stop-hook rule list (name, what it checks, the message, that it fires
once per session and never when the running fields are missing).
  - verified

## Discovered

