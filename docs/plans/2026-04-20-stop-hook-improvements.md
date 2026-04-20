# Task: Stop Hook Improvements

**Created:** 2026-04-20
**Status:** In Progress
**Context:** The stop hook was being called 402 times/day but never firing on real sessions. Root cause analysis revealed two issues: (1) the `uncommittedChangesRule` TextPreFilter required trigger words like "done"/"shipped" in the last assistant text, but Claude's last turn often ends with a tool_use block (no text), and (2) no diagnostic logging to debug why rules missed.

## Root Cause

Claude Code's stop hook receives the full transcript. The `parseTranscript()` function extracts `LastAssistantText` from text blocks in the last assistant turn. But in practice, the last assistant turn often looks like:

```json
[
  {"type": "text", "text": "Let me push now."},
  {"type": "tool_use", "name": "Bash", "input": {"command": "git push"}}
]
```

The `LastAssistantText` becomes "Let me push now." — which doesn't contain "done", "shipped", or any TextPreFilter trigger words. The rule silently skips the git status check.

**Result:** 402 evaluations, 0 fires on real sessions. Only test sessions (with synthetic "All done" text) ever triggered.

## Changes (implemented)

### 1. Remove TextPreFilter from uncommittedChangesRule
- [x] Changed `TextPreFilter()` from `\b(done|complete|finished|...)` to `""` (empty = always evaluate)
- [x] The rule now always runs `git status` (~5ms) — acceptable cost for reliable detection
- [x] Updated test expectations for dirty-repo environments

### 2. Add diagnostic logging to stop hook
- [x] Added fields to `StopHookRecord`: `transcript_turns`, `last_assistant_len`, `last_assistant_head` (first 200 chars), `bash_call_count`, `has_todo_write`
- [x] Fields are omitted when zero (no noise for existing log consumers)
- [x] Enables post-hoc debugging: `jq 'select(.msg=="stop_hook") | .last_assistant_head'` shows exactly what each rule evaluation saw

### 3. Earlier commit: skip_reason logging
- [x] When LLM budget is exhausted, `skip_reason: "llm_budget_exhausted"` appears in decision records
- [x] Visible in `claude-guard test` output as `skipped:` line

## Verification

```bash
# Test the fix manually
echo '{"session_id":"verify","stop_hook_active":false,"transcript":[]}' | claude-guard stop
# Should fire if git is dirty (no text needed)

# Check diagnostic logging
grep '"verify"' ~/.claude/logs/claude-guard/decisions.jsonl | jq '.'
# Should show transcript_turns, last_assistant_len, last_assistant_head

# Monitor real sessions
claude-guard monitor --json | jq 'select(.msg=="stop_hook" and .injected==true)'
```

## Files Modified

- `internal/stop/rules.go` — removed TextPreFilter from uncommittedChangesRule
- `internal/log/log.go` — added diagnostic fields to StopHookRecord + StopHook logger
- `cmd/claude-guard/stop.go` — populate diagnostic fields from parsed transcript
- `cmd/claude-guard/stop_test.go` — updated empty transcript test for always-on rule

## Future Improvements

- Consider adding a `commitNotPushedRule` — detects commits that weren't pushed
- Consider per-rule latency logging (which shell checks are slow?)
- Consider text analysis rule that fires when assistant text looks like a summary without completing stated work
