# Plan: Learning Pipeline Fixes

**Created:** 2026-06-07
**Status:** Planning
**Context:** Data from `claude-guard stats` + `replay` shows three concrete bugs in the
learning pipeline. Cache hit rate is 3.4% (should be 40%+). 353/357 learned entries have
empty `canonical_form`. `git push` approved in 5 repos never reaches global promotion.
These are fixes to what's already built, not new features.

---

## Problem 1 — `rulesHash` Busts the Cache on Every Rule Addition

**Root cause:** `computeRulesHash` in `engine.go` hashes ALL rules (block + allow).
Every time a new allow rule is added (or `make install` runs a new binary), `rulesHash`
changes → all project-scoped LLM cache entries are invalidated.

**Evidence:** 20,873 cache entries, 3.4% hit rate. We've been adding allow rules daily.

**Fix:** Only include block rules in `rulesHash`. Allow rules are additive (they can only
cause MORE auto-approvals, never change safe→unsafe). A new allow rule should not bust
cached LLM verdicts.

```go
// internal/engine/engine.go — computeRulesHash
func computeRulesHash(cfg *config.Config) string {
    var names []string
    for _, r := range cfg.InstantBlock {
        names = append(names, "block:"+r.Name())
    }
    // Allow rules excluded — they are additive and do not invalidate LLM verdicts.
    return cache.HashStrings(names)
}
```

**Expected impact:** Cache hit rate goes from ~3% to ~40%+ immediately after next `make install`.
LLM calls drop proportionally. p95 latency drops from 4s to ~0.2ms for warm commands.

---

## Problem 2 — `canonical_form` Is Empty for 99% of Learned Entries

**Root cause:** `learn.go` calls `normalize.Normalize(bash.Command, nil)` to get the
canonical form. This function requires LLM-supplied variable slots — with `nil`, it returns
`""` for any command that isn't a trivially-structured single call. Compound commands
(`&&` chains, pipes, heredocs) all land with empty canonical.

**Evidence:** `SELECT canonical_form FROM verdicts WHERE tier='learned' ORDER BY match_count DESC LIMIT 10` → all empty.

**Fix:** Fall back to `cache.SessionCanonical(bash.Command)` when `normalize.Normalize`
returns empty. `SessionCanonical` already does the right thing: returns `program + subcommand`
for most commands, just `program` for single-word programs.

```go
// cmd/claude-guard/learn.go
canonical := pending.CanonicalForm
if canonical == "" {
    canonical, _, _ = normalize.Normalize(bash.Command, nil)
}
if canonical == "" {
    canonical = cache.SessionCanonical(bash.Command) // ← new fallback
}
```

Also: the cache KEY for learned entries should be based on `canonical`, not the full
`bash.Command`. Currently:
```go
cacheKey := cache.Key(cache.KeyInputs{Tool: "Bash", Command: canonical, CWD: in.CWD})
```
This IS using canonical already — but canonical is empty, so the key is hash(""). Fix canonical
and the key naturally improves.

**Expected impact:** `git push origin main 2>&1 | tail -3` and `git push` share a cache entry.
Compound commands with same intent share entries. The 3-approval global-promotion counter
accumulates across variants of the same intent.

---

## Problem 3 — `git push` (Non-Force) Should Be Tier 2 After First Approval

**Root cause:** The LLM consistently flags `git push` as "unsafe: modifies remote state."
This is technically correct but creates daily friction. Robin has approved `git push` in 5+
repos. Due to Problem 2, each approval is stored separately and never reaches the 3-approval
global-promotion threshold.

**Data:** `git push 2>&1` (landslide): 166 hits. `git push origin main`: 133 hits. Both in
separate project-scoped entries.

**Fix part A:** After Problem 2 fix, the canonical for all `git push` variants becomes `git push`.
Global promotion (after 3 approvals across any project) will work correctly.

**Fix part B:** Add `git push` (non-force, non-protected-branch) to the compiled-in Tier 2 allow
list. The guard already has `git-force-push-protected` in Tier 1. Non-force pushes to any branch
are safe to auto-allow — the user controls their own repos.

```go
// internal/config/defaults.go — DefaultAllowRules
&rules.AnchoredCommand{
    RuleName:    "git-push-nonforce",
    Programs:    []string{"git"},
    RequireSubcmdAny: []string{"push"},
    ForbidFlags: []string{"--force", "-f"},
},
```

**Note:** `--force-with-lease` is NOT in ForbidFlags — it's a safe force (won't overwrite
commits you haven't seen). Add it separately as allowed. `--force` and `-f` ARE forbidden
so they still go through the LLM / user prompt.

---

## Problem 4 — Prompt Hint for `export VAR=$(gcloud secrets ...)`

**Root cause:** 7+ times in 24h, `export TAUFINITY_ADMIN_TOKEN=$(gcloud secrets versions access ...)` hits the LLM and is flagged as "accessing secrets = exfiltration risk." It's a
normal local dev pattern.

**Fix:** Add a prompt hint (user-specific context added to LLM system prompt) that teaches the
LLM this is a known-safe pattern in Robin's workflow.

```yaml
# ~/.config/claude-guard/prompt-hints.yaml
hints:
  - context: >
      This user's workflow involves fetching admin tokens from Google Cloud Secret Manager
      for local CLI use. The pattern `export VAR=$(gcloud secrets versions access ...)` is
      a standard local developer operation — NOT exfiltration. The exported variable is used
      immediately in the same shell session for CLI tools (taufinity, provision, etc.).
      Classify this pattern as safe when the variable is exported without being piped to a
      network destination.
    reason: repeated false-positive on gcloud secrets fetch (7+ per day)
```

The `review` package already supports `HintRecommendation` and `LoadPromptHints`. This is
writing one entry manually rather than waiting for Opus to generate it.

**Expected impact:** Eliminates the top friction pattern (~7 prompts/day).

---

## Implementation Phases

### Phase 1: rulesHash fix (30 min)
- [ ] `internal/engine/engine.go`: `computeRulesHash` — remove allow rules from hash
- [ ] Test: existing engine tests pass; verify cache keys differ only on block-rule changes
- [ ] Verify: `go test ./internal/engine/...`

### Phase 2: canonical_form fallback (20 min)
- [ ] `cmd/claude-guard/learn.go`: add `cache.SessionCanonical` fallback
- [ ] Test: add test case — approve command with `&&` chain, verify `canonical_form != ""`
- [ ] Verify: `go test ./cmd/claude-guard/...`

### Phase 3: git push Tier 2 rule (30 min)
- [ ] `internal/config/defaults.go`: add `git-push-nonforce` allow rule
- [ ] `internal/corpus/testdata/bash_allow.txt`: add `git push origin main`, `git push`
- [ ] `internal/corpus/testdata/bash_continue.txt`: verify no regressions
- [ ] Test: `go test ./...`

### Phase 4: prompt hint (15 min)
- [ ] Create `~/.config/claude-guard/prompt-hints.yaml` with gcloud secrets hint
- [ ] Verify engine loads it: `claude-guard doctor` shows hint loaded
- [ ] Test: `claude-guard test "export TOKEN=$(gcloud secrets versions access latest --secret=foo)"` — should show LLM tier with hint context

---

## Success Metrics

| Metric | Before | Target |
|---|---|---|
| Cache hit rate | 3.4% | >35% |
| `git push` prompts/day | ~5 | 0 |
| `export VAR=$(gcloud)` prompts/day | ~7 | 0 |
| LLM tier % | 34.2% | <15% |
| p95 latency | 4.1s | <0.5s |
| learned canonical_form empty | 353/357 (99%) | <10% |

Measure with: `claude-guard stats --since 24h` and `claude-guard replay --since 24h`

---

## Files to Touch

| File | Change |
|---|---|
| `internal/engine/engine.go` | `computeRulesHash` — block rules only |
| `cmd/claude-guard/learn.go` | `SessionCanonical` fallback for canonical_form |
| `internal/config/defaults.go` | `git-push-nonforce` allow rule |
| `internal/corpus/testdata/bash_allow.txt` | git push test cases |
| `~/.config/claude-guard/prompt-hints.yaml` | gcloud secrets hint (manual, not in repo) |

---

## Failure Routing

| Phase | On failure → |
|---|---|
| Phase 1 (rulesHash) | Revert — worst case is cache doesn't improve |
| Phase 2 (canonical) | Revert — worst case is no improvement to learned entries |
| Phase 3 (git push rule) | Check corpus for false-positives; remove rule if any |
| Phase 4 (prompt hint) | Malformed YAML falls back to no hint; engine still starts |
