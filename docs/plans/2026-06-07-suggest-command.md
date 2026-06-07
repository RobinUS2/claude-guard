# Plan: `claude-guard suggest` — Replay → Rule Suggestions

**Created:** 2026-06-07
**Status:** Planning
**Context:** `claude-guard replay` shows WHAT still prompts the user. It doesn't show HOW to
fix it. The `suggest` command closes that loop: groups still-continuing commands by pattern,
ranks by frequency, and proposes concrete allow-rule or prompt-hint additions.

---

## Design

```
claude-guard suggest [--since 7d] [--min-count 3] [--output yaml]

Analyses historical Continue decisions and proposes:
  - Tier 2 allow rules for safe, high-frequency patterns
  - Prompt hints for patterns the LLM over-blocks
  - .claude-guard.yml additions for project-specific patterns
```

### Output (human-readable, default)

```
suggest — rule candidates from 7d of Continue decisions

  HIGH CONFIDENCE — safe pattern, appears frequently:
  ─────────────────────────────────────────────────────────
  37×  export VAR=$(gcloud secrets ...)
       → prompt-hint candidate (shell built-in + secrets fetch)
       → add to ~/.config/claude-guard/prompt-hints.yaml

  12×  git push (non-force variants)
       → Tier 2 candidate: git-push-nonforce
       → already compiled-in after this plan; check rule activated

   8×  make provision-diff CUSTOMER=...
       → project allow rule candidate
       → add to /path/to/repo/.claude-guard.yml:
         allow:
           - name: provision-diff
             programs: [make]
             subcommands: [provision-diff]

  MEDIUM CONFIDENCE — check before adding:
  ─────────────────────────────────────────────────────────
   5×  chmod +x scripts/...
       → Tier 2 candidate: chmod-executable
       → Risk: chmod on arbitrary paths; restrict to project dir

  PATTERN GROUPING (program + subcommand clusters):
  ─────────────────────────────────────────────────────────
    gcloud / secrets     37  → see above
    git / push           12  → see above
    make / provision-*    8  → project rule candidate
    chmod / +x            5  → medium confidence
    bq / query            4  → BQ preflight should catch; check parser
    until / [             3  → polling loop; evaluate individually
```

### Output (YAML mode, `--output yaml`)

Machine-readable for scripting or piping into `claude-guard review`:

```yaml
candidates:
  - pattern: "export {VAR}=$(gcloud secrets ...)"
    type: prompt_hint
    count: 37
    confidence: high
    programs: [bash, export]
    hint: "This user fetches admin tokens from gcloud secrets for local dev..."

  - pattern: "git push"
    type: tier2_rule
    count: 12
    confidence: high
    programs: [git]
    subcommands: [push]
    forbid_flags: ["--force", "-f"]

  - pattern: "make provision-diff"
    type: project_rule
    count: 8
    confidence: medium
    programs: [make]
    subcommands: [provision-diff]
    cwd_hint: "/Users/robin/Documents/code/ai-site-gen"
```

---

## Implementation

### Core algorithm

1. Read `decisions.jsonl` filtered to `verdict=continue` in window
2. For each command: extract `program + subcommand` (via `cache.SessionCanonical`)
3. Group by canonical form, count occurrences, collect sample commands
4. For each group with `count >= min_count`:
   - Classify: is the pattern safe? (check against block rules — would Tier 1 catch it?)
   - Assign confidence: HIGH if canonical is a safe read/write pair, MEDIUM if ambiguous
   - Propose: Tier 2 rule / prompt hint / project rule depending on pattern type
5. Sort by count descending, print

### Confidence heuristic

```
HIGH: program in known-safe list (git, make, gcloud read-only) AND no danger flags
MEDIUM: program is common but has write implications (chmod, curl, bq query)
LOW: program is unknown, has shell trickery, or contains credential patterns
```

### Pattern classifier (deterministic, no LLM)

```go
type suggestResult struct {
    canonical  string
    count      int
    samples    []string
    ruleType   string // "tier2", "prompt_hint", "project_rule", "manual"
    confidence string // "high", "medium", "low"
    proposed   string // human-readable rule proposal
}
```

### Key function: `classifyCandidate(canonical string, count int) suggestResult`

Uses a lookup table of known-safe patterns + the existing block-rule set to determine:
- If `eng.Decide(Input{Command: canonical})` returns Deny → already blocked, skip
- If canonical matches known-safe programs (git, make, go, gcloud read-only) → HIGH, Tier 2 candidate
- If canonical has secrets/creds pattern → prompt_hint candidate
- Otherwise → MEDIUM or LOW

---

## Files to Create/Modify

| File | Change |
|---|---|
| `cmd/claude-guard/suggest.go` | New command |
| `cmd/claude-guard/suggest_test.go` | Tests |
| `cmd/claude-guard/main.go` | Wire `suggest` subcommand |
| `cmd/claude-guard/main.go` | Update usage string |

---

## Implementation Phases

- [ ] `cmd/claude-guard/suggest.go` — `cmdSuggest`, `runSuggest`, `classifyCandidate`
- [ ] `cmd/claude-guard/suggest_test.go` — test with fixture log
- [ ] Wire into `main.go`
- [ ] Test: `go test ./cmd/claude-guard/...`
- [ ] Verify: `claude-guard suggest --since 7d` produces useful output on real data

---

## Failure Routing

| Step | On failure → |
|---|---|
| File read | Print error, exit 1 (same as replay) |
| Classification wrong | Confidence degrades to LOW; user must verify |
| No suggestions found | "no recurring patterns found — try --since longer" |

---

## Success Criteria

- Runs on real `decisions.jsonl` without crashing
- Top-3 suggestions match what a human would propose from looking at the data
- YAML output is valid and parseable by `jq`
- Adds at least one actionable suggestion per day of usage

---

## CTO Feedback Applied (2026-06-07)

1. **Confidence heuristic must be deterministic** — replace vague "check against block rules" with a fixed lookup table of program→safety classification. No engine calls during suggest.
2. **Dedup by canonical, not raw occurrence** — count unique (session_id, canonical) pairs to avoid counting the same session's repeated command as N separate events. This prevents skewed counts from a single long session.
3. **Min-count default of 3** documents correctly as "must appear across at least 3 separate sessions OR 3+ times in one session" — clarify in help text.
