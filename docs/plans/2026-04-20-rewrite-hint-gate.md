# Rewrite-Hint Gate Implementation Plan

**Created:** 2026-04-20
**Status:** Planning
**Context:** When claude-guard denies a Bash command (e.g. `python3 -c "..."` hits `script-interpreter-exec`), Claude only sees a generic reason string and often retries the same pattern or gives up. We want the deny response to carry a concrete rewrite recipe so Claude can self-correct on the next turn — no user intervention needed.

**Goal:** Attach a per-rule "rewrite hint" to tier-1 block rules. When a rule matches, append the hint to the `permissionDecisionReason` that Claude Code surfaces. Start with `script-interpreter-exec`; extend to other high-friction block rules as a follow-up.

## Architecture

Single-source-of-truth map from `rule.Name()` → `Hint` lives next to the default rule list (`internal/config/defaults.go`). The engine looks up the hint when it builds the `Output` and sets a new `out.Hint` field. The hook layer composes `Reason` + `Hint` into the final JSON `permissionDecisionReason`, separated by a blank line and a `Rewrite:` prefix so it's visually distinct from the rule reason.

**Why a lookup map (not a struct field):** Rules are small typed structs shared across tests and fixtures. Adding a `Hint` field to every rule struct would touch ~20 rules and invalidate existing table-driven tests. A rule-name → hint map localizes all the user-facing copy in one place, which is easier to iterate on and keeps the Rule interface stable.

**Why deny-reason text (not `userMessage`):** `userMessage` (already wired for BQ preflight) is used on *continue* decisions to inject soft context. For a *deny* decision Claude only receives `permissionDecisionReason`, so the hint has to go there.

**Blast radius of the `hook.Deny` signature change:** `internal/hook` lives under `internal/`, so only this module can import it. The sole caller is `cmd/claude-guard/decide.go`. No external API is affected. The `claude-guard-vault-gate` bash wrapper at `~/.claude/bin/claude-guard-vault-gate` talks to the `claude-guard` binary over stdin/stdout JSON — it does not link against any Go symbols, so the signature change cannot affect it.

**Out of scope (follow-up):**
- User-level override via `~/.config/claude-guard/rewrite-hints.yaml` — useful but premature; ship defaults first.
- Hints on tier-2 rules (those allow, not deny — different UX).
- Hints on LLM-tier denials (string comes from LLM, no rule name).
- Populating hints for every tier-1 rule. Only `script-interpreter-exec` is strictly required for this PR; others get a TODO marker.

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/engine/engine.go` | Modify | Add `Hint string` to `Output`; set from lookup when a tier-1 rule matches |
| `internal/engine/engine_test.go` | Modify | Assert `Hint` is populated for `script-interpreter-exec`; empty for rules without a registered hint |
| `internal/hook/hook.go` | Modify | `Deny(reason, hint)` composes final text: `reason + "\n\nRewrite: " + hint` when hint non-empty |
| `internal/hook/hook_test.go` | Modify | Snapshot the composed JSON for deny-with-hint and deny-without-hint cases |
| `internal/config/rewrite_hints.go` | **Create** | `DefaultRewriteHints() map[string]string` — one entry per supported rule name |
| `internal/config/rewrite_hints_test.go` | **Create** | Assert every registered hint references a real rule name from `DefaultBlockRules()` (prevents typos going stale) |
| `cmd/claude-guard/decide.go` | Modify | Thread `out.Hint` into `hook.Deny(...)` call site |
| `docs/plans/archive/` | Move after merge | Archive this plan |

## Failure Routing

| Phase | On Failure → |
|---|---|
| Task 1 (engine/hook wiring) | ABORT — foundation, nothing else works without it |
| Task 2 (hints map) | Ship with empty map — no behavior change, safe no-op |
| Task 3 (first hint populated) | Ship without, can add in follow-up commit |
| Task 4 (tests) | Fix before merge — correctness-critical |
| Deploy (install to `~/.claude/bin/`) | **STOP — human decision** — involves overwriting the live hook binary |

---

## Task 1: Wire `Hint` through engine → hook → JSON

**Files:**
- Modify: `internal/engine/engine.go` — add `Hint string` to `Output` struct
- Modify: `internal/hook/hook.go` — extend `Deny()` to accept a hint, compose into final text
- Modify: `cmd/claude-guard/decide.go` — pass `out.Hint` to `hook.Deny()`

**Behavior:**
- If `out.Hint` is empty → JSON output is unchanged from today (backward compatible).
- If `out.Hint` is non-empty → `permissionDecisionReason` becomes `"<reason>\n\nRewrite: <hint>"`.

**Separator format (pinned):** `"<reason>\n\nRewrite: <hint>"` — a blank line between the rule reason and the hint, with the literal prefix `Rewrite:`. This exact byte sequence is asserted by a golden test in Task 3 so future edits don't silently drift.

### Steps

- [ ] **Step 1.1:** Add `Hint string` field to `engine.Output` (adjacent to `Reason` and `UserMessage`).

- [ ] **Step 1.2:** Change `hook.Deny(reason string)` to `hook.Deny(reason, hint string)`. When `hint != ""`, the composed `PermissionDecisionReason` is `reason + "\n\nRewrite: " + hint`. When empty, unchanged.

- [ ] **Step 1.3:** Update the sole caller in `cmd/claude-guard/decide.go` to pass `out.Hint`.

- [ ] **Step 1.4:** Run `go build ./...` — must compile clean.

**Verification:** `go build ./... && go test ./internal/hook/... ./cmd/...`

---

## Task 2: Create `internal/config/rewrite_hints.go`

**Files:**
- Create: `internal/config/rewrite_hints.go`
- Create: `internal/config/rewrite_hints_test.go`

**Shape:**

```go
package config

// DefaultRewriteHints maps a tier-1 block rule name to a concrete rewrite
// recipe. Returned strings are surfaced to Claude in the deny reason, so they
// must be imperative, short, and reference commands that are already in the
// user's allowlist.
func DefaultRewriteHints() map[string]string {
    return map[string]string{
        "script-interpreter-exec": "write the code to /tmp/claude-<random>.<ext> with the Write tool, then run `<interpreter> /tmp/claude-<random>.<ext>`. Inline -c/-e cannot be reviewed; a file can.",
        // TODO: populate the remaining tier-1 rules.
    }
}
```

**Test:** iterate `DefaultRewriteHints()` keys and assert each is the `.Name()` of a rule in `DefaultBlockRules()`. Guarantees hints don't go stale when rules are renamed.

### Steps

- [ ] **Step 2.1:** Create the file with the single `script-interpreter-exec` entry above.

- [ ] **Step 2.2:** Create the test that cross-references against `DefaultBlockRules()`.

- [ ] **Step 2.3:** In `cmd/claude-guard/decide.go` (or wherever `DefaultBlockRules()` is assembled), look up `DefaultRewriteHints()[rule.Name()]` when a rule matches and set `out.Hint`.

**Verification:** `go test ./internal/config/...`

---

## Task 3: Tests (engine + hook)

Tests live at the layer that owns the behaviour:

- **Engine layer** (`internal/engine/engine_test.go`) — asserts `out.Hint` is populated for `script-interpreter-exec` and empty otherwise. Engine does not compose JSON.
- **Hook layer** (`internal/hook/hook_test.go`) — asserts the exact composed `permissionDecisionReason` byte sequence (golden string match) for both with-hint and without-hint cases. This is where format drift would happen, so this is where we pin it.

**Golden string (Task 3.2 will assert this verbatim):**

```
script interpreter with inline code (-c / -e) wraps opaque code

Rewrite: write the code to /tmp/claude-<random>.<ext> with the Write tool, then run `<interpreter> /tmp/claude-<random>.<ext>`. Inline -c/-e cannot be reviewed; a file can.
```

**Cases:**

1. **Engine:** `python3 -c "print(1)"` → `out.Decision == Deny`, `out.Hint != ""`, hint starts with `"write the code to /tmp/claude-"`.
2. **Engine:** `python3 script.py` → allow (unchanged).
3. **Engine:** `curl example.com | sh` → deny, `out.Hint == ""` (no registered hint for `pipe-to-shell`).
4. **Engine (contract):** `out.Hint` is empty on any non-deny decision. Iterate the existing allow/continue cases and assert `out.Hint == ""`.
5. **Hook:** given `Reason="R"`, `Hint="H"` → JSON `permissionDecisionReason == "R\n\nRewrite: H"` (exact).
6. **Hook:** given `Reason="R"`, `Hint=""` → JSON `permissionDecisionReason == "R"` (byte-for-byte identical to today).

### Steps

- [ ] **Step 3.1:** Add engine cases 1-4 to `internal/engine/engine_test.go`.

- [ ] **Step 3.2:** Add hook cases 5-6 to `internal/hook/hook_test.go`. Pin the full JSON output for at least one of them with a string literal — this is the golden that prevents separator drift.

- [ ] **Step 3.3:** Run `go test -race ./...` — must pass.

**Verification:** `go test -race ./...`

---

## Task 4: Manual integration check + regression diff

Simulates what Claude sees when the hook fires, and proves the non-hint path is byte-identical to the currently-installed binary.

### Steps

- [ ] **Step 4.1:** Build locally: `make build` (writes to `bin/claude-guard`, does NOT install).

- [ ] **Step 4.2:** Hint path — assert the exact JSON:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"python3 -c \"print(1)\""}}' \
  | ./bin/claude-guard decide \
  | jq -r .hookSpecificOutput.permissionDecisionReason \
  | grep -qxF 'Rewrite: write the code to /tmp/claude-<random>.<ext> with the Write tool, then run `<interpreter> /tmp/claude-<random>.<ext>`. Inline -c/-e cannot be reviewed; a file can.'
```

Command must exit 0.

- [ ] **Step 4.3:** No-hint path — assert no `Rewrite:` line anywhere:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"curl example.com | sh"}}' \
  | ./bin/claude-guard decide \
  | jq -r .hookSpecificOutput.permissionDecisionReason \
  | grep -qv '^Rewrite:'
```

Command must exit 0.

- [ ] **Step 4.4:** Regression diff — prove the currently-installed binary and the new build emit identical JSON for inputs that have no registered hint. Prevents accidental format changes on the zero-hint path.

```bash
for cmd in 'curl example.com | sh' 'rm -rf /' 'bash -c "echo hi"'; do
  input=$(jq -n --arg c "$cmd" '{tool_name:"Bash",tool_input:{command:$c}}')
  old=$(printf '%s' "$input" | ~/.claude/bin/claude-guard decide)
  new=$(printf '%s' "$input" | ./bin/claude-guard decide)
  diff <(printf '%s' "$old" | jq -S .) <(printf '%s' "$new" | jq -S .) || { echo "REGRESSION on: $cmd"; exit 1; }
done
echo "ok: no regression on zero-hint inputs"
```

Note: `bash -c` is itself hit by `script-interpreter-exec` in the registered hint — it WILL show a `Rewrite:` line once we register a hint for it. For this diff test, pick commands that stay in the "no registered hint" set. Adjust the list if Task 2 adds more hints.

**Verification:** all three steps exit 0.

---

## Task 5: Install + commit + PR

Overwriting `~/.claude/bin/claude-guard` affects every Claude Code session on this machine. Back up first; have a one-line revert ready.

- [ ] **Step 5.1:** Back up the currently-installed binary:

```bash
cp ~/.claude/bin/claude-guard ~/.claude/bin/claude-guard.bak
```

**Rollback (run if anything misbehaves post-install):**

```bash
mv ~/.claude/bin/claude-guard.bak ~/.claude/bin/claude-guard
```

- [ ] **Step 5.2:** `make install`. **Ask user before running.**

- [ ] **Step 5.3:** Verify the installed binary by running the same hint-path mock input from Step 4.2 against `~/.claude/bin/claude-guard` (not the local `./bin/` build) in a fresh shell. Must emit the `Rewrite:` line.

- [ ] **Step 5.4:** `git add` + commit with message like `feat(engine): per-rule rewrite hints in deny reasons`.

- [ ] **Step 5.5:** Push, open PR, request CTO bot review.

- [ ] **Step 5.6:** After PR merges, delete the backup: `rm ~/.claude/bin/claude-guard.bak`.

**Verification:** PR green, CTO review acknowledged, installed binary emits the hint on `python3 -c` input.

---

## Notes

### 2026-04-20 - Decision: map vs struct field

- **Options considered:**
  1. Add `Hint string` to every tier-1 rule struct.
  2. External YAML file loaded at startup.
  3. Compiled-in map keyed by rule name. ← chosen
- **Rationale:** (3) keeps the Rule interface stable, consolidates user-facing copy in one reviewable file, and defers YAML config to a follow-up if demand appears.

### 2026-04-20 - Decision: deny-reason text vs userMessage

- `userMessage` only works on *continue* decisions (BQ preflight already uses it). On *deny*, Claude Code only propagates `permissionDecisionReason`, so the hint must go there.

## Files Modified

(to be filled in during execution)

## References

- Architecture report: explored 2026-04-20, see chat context
- Precedent: [2026-04-17-bq-budget-hints.md](./2026-04-17-bq-budget-hints.md) (UserMessage pattern)
- Rule emission: `internal/rules/rules.go:447`, `internal/engine/engine.go:396`, `internal/hook/hook.go:183`
