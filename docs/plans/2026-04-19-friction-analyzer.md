# Task: Friction Analyzer (`claude-guard hotspots`)

**Created:** 2026-04-19
**Status:** Planning — CTO-reviewed 2026-04-19
**Context:** We want a fast way to answer "what's blocking or prompting me most today?" — a ranked, clustered view of recent friction so the user can prioritize which rules / prompt hints to tune. Today we have raw counters (`stats`) and an autonomous rule-evolution pipeline (`review`), but nothing that gives a human-readable top-N leaderboard of similar commands that caused blocks / unsure prompts.

## Prerequisite (ships as its own commit before this feature)

**P0: Fix missing `msg=stop_hook` writer.** `internal/log/log.go` defines `MsgStopHook` + `StopHookRecord`, and `cmd/claude-guard/stats.go` reads them from `decisions.jsonl`, but no writer ever emits that record — `stats` has been showing zero stop-hook evaluations. The recent `stop_decision` → `app.jsonl` commit (0b5373e) doesn't fill this gap because it writes to the wrong file with the wrong msg. Fix: inject `DecisionLogger` into `cmdStopWithIO`, emit `StopHookRecord` shape via `.LogAttrs(ctx, LevelInfo, MsgStopHook, attrs...)`. Demote the app.jsonl `stop_decision` Info line to Debug or remove it. Then `stats` sees stop events and `hotspots` has one unambiguous source. Standalone PR/commit so the triage change stays scoped.

## Why this is new (and not just `stats` or `review`)

| Tool | Purpose | Gap |
|---|---|---|
| `stats` | Tier / verdict counters, latency percentiles, cache health | No grouping by command shape; no prioritization; no LLM interpretation |
| `review` | Autonomous rule evolution — proposes learned rules, prompt hints, legacy trims; writes YAML | Tuned for auto-apply. Summary output is oriented to "what did I change", not "what are your top friction patterns right now" |
| `explain` | Per-decision inspector | Single record, not aggregate |
| `monitor` | Live tail | No clustering, no summary |

The new `hotspots` subcommand fills a specific gap: **human-in-the-loop prioritization**. Show me the top 10 friction clusters in the last 6 hours so I can decide what's worth a rule vs. what to ignore.

**Naming:** `hotspots` chosen over `triage`/`friction`/`top` — noun, specific, doesn't collide with `review`. Settled before step 4 so docs and settings snippets don't rename later.

## User experience

```
$ claude-guard hotspots
window: last 6h (from decisions.jsonl)
events considered: 412   matched: 87 (21% of traffic caused friction)

#  cnt  category    example                                        last
1  18   block       rm -rf ~/.cache/foo                            3m ago
2  12   unsure      gcloud iam service-accounts add-iam-policy…    14m ago
3   9   stop-cont   stop rule: uncommitted-changes                 28m ago
4   7   block       ssh-keygen -t ed25519                          41m ago
5   6   unsure      bq query "SELECT ..."                          52m ago
…

--since 24h            extend window
--top 20               more rows
--categories block,unsure,stop
--json                 machine-readable
```

Defaults: `--since 6h`, `--top 10`, `--categories block,unsure-shadow,stop-continue,stop-capped,legacy-fallback`.

**LLM enrichment deliberately deferred (not in v1).** Rationale: `review` already uses an Opus-class model to propose concrete rules. A second LLM path returning a 4-way advisory category adds cost + PII surface with modest value. Ship v1 as pure aggregation; add `--llm` only if the plain table proves insufficient. Keeps this PR focused and lets the "clustering heuristic + ranking" be judged on its own.

## Design

### 1. New package `internal/hotspots/`

```
internal/hotspots/
  cluster.go       — group records by canonical shape
  rank.go          — score + top-N selection
  format.go        — table + JSON renderers
  hotspots.go      — Run(opts) entrypoint; pure function of (records, opts) → Report
  hotspots_test.go — table-driven tests
```

Pure package — no I/O. `cmd/claude-guard/hotspots.go` handles flag parsing, log reading, and rendering.

### 2. Shape extraction

Reuse `internal/review/collect.go:commandShape` — "first 3 whitespace tokens, lowercased". That's too coarse for some cases (noted in §2a) but good enough for v1.

**Extraction home: `internal/logshape/shape.go` (new dedicated package).** Not `internal/normalize/` — that package does variable-slot canonicalization (domain/IP/UUID) and adding `CommandShape` there would be a semantic collision. A tiny neutral package with one exported function + one helper is cleaner than bending an existing one.

Cluster key = `(category, toolName, shape)`. Non-Bash tools group by tool name alone.

Stop-hook events (`msg=stop_hook`) cluster by `fired_rule` (they don't have a shell command).

### 2a. Known clustering failure + mitigation

First-3-tokens collapses `bq query "SELECT a FROM t1"` and `bq query "SELECT b FROM t2"` into one bucket where the third token is literally `"SELECT` — the single "example" row becomes misleading. Mitigation in `format.go`: when a cluster has `count >= 5` AND the 3rd token matches `^"?[A-Z_]{3,}` (all-caps or quoted all-caps), show up to 2 example commands instead of 1. No change to bucketing — just a display tweak. Covered by a table test.

### 3. Scoring

Primary: `count`. Ties broken by most recent timestamp, then by alphabetical shape for determinism. This is deliberately simple — we're ranking for human triage, not ML ranking.

Explicit non-goals: no decay, no per-project weighting, no latency weighting. All can be added later if the ranked list is clearly wrong; until then, simplest thing that works.

### 4. Data sources

- `decisions.jsonl` — `msg=decision` records (tier/verdict/rule/reason/command)
- `decisions.jsonl` — `msg=stop_hook` records (StopHookRecord shape)

Single source. The P0 prerequisite commit ensures stop-hook records land in decisions.jsonl, so `hotspots` reads one file and one schema.

### 5. Categories

| Category | How we detect it |
|---|---|
| `block` | verdict=deny |
| `unsafe-shadow` | shadow.tier4_llm starts with "unsafe" |
| `unsure-shadow` | shadow.tier4_llm starts with "unsure" |
| `llm-hit` | tier=llm (latency + cost driver) |
| `llm-repeat` | tier=llm, same shape ≥3× in window |
| `legacy-fallback` | tier=legacy (meaning tier 1/2/3/4 didn't resolve) |
| `stop-continue` | msg=stop_hook, injected=true |
| `stop-capped` | msg=stop_hook, suppressed=max_continues_reached |

Reuse `review.Collect`'s categorization where possible — move the categorization logic into the new shared package so both use it.

### 6. Output

**Text (default):** The table shown above, plus a one-line summary header (`events considered`, `matched`, `%`).

**JSON (`--json`):** Stable schema, `schema_version: 1` from day one so later additions don't break pipelines:

```json
{
  "schema_version": 1,
  "window": "6h",
  "generated_at": "2026-04-19T19:55:00Z",
  "total_events": 412,
  "matched": 87,
  "clusters": [
    {"category": "block", "tool": "Bash", "shape": "rm -rf",
     "count": 18, "examples": ["rm -rf ~/.cache/foo"],
     "example_reason": "…", "example_rule": "rm-rf-system",
     "latest_ts": "2026-04-19T19:52:00Z"}
  ]
}
```

`examples` is always an array (1 or 2 entries per §2a).

### 7. LLM enrichment — deferred

Not in v1. See "User experience" above. If added later: use the same model family as `review` (Opus-class, `review.DefaultModel`) with its own prompt contract — not the hot-path classifier. Also run `redact` over `reason` strings (free-text, may contain paths/hostnames the per-command redactor didn't normalize) and never include `cwd` in the prompt payload (often contains usernames).

## Reuse checklist

- [x] `internal/review/collect.go:readLogFile` — if possible, extract to `internal/log/read.go` so both `review` and `hotspots` share one JSONL reader. Confirm no circular import before moving.
- [x] `internal/review/collect.go:commandShape` + `truncate` — extract to `internal/logshape/shape.go` (new package, neutral name, avoids semantic collision with `internal/normalize/`).
- [x] `internal/review/collect.go:Case` — stays in review; `hotspots` defines its own `Cluster` shape (count/score) since semantics differ.
- [x] Config loader (`internal/config.Load`) for log dir.
- [x] `clog.ReadRecord` + `clog.StopHookRecord` for parsing.

## Plan (steps)

Step 1 is the P0 prerequisite above — ships as a standalone commit/PR **before** this feature branch opens.

| # | Step | Verify |
|---|---|---|
| 1 | **Prerequisite PR:** wire `DecisionLogger` into `cmdStopWithIO`; emit `MsgStopHook` record. Demote or remove the app.jsonl `stop_decision` Info line. | After running stop once: `grep -c '"msg":"stop_hook"' ~/.claude/logs/claude-guard/decisions.jsonl` ≥ 1; `stats` shows non-zero stop-hook counts |
| 2 | Create `internal/logshape/shape.go` (`CommandShape`, `Truncate`). Port `review/collect.go` to use it. | `go test ./internal/logshape/... ./internal/review/...` |
| 3 | `internal/hotspots/`: cluster + rank + format. Pure package, table-driven tests including the §2a all-caps-3rd-token mitigation. | `go test ./internal/hotspots/...` |
| 4 | `cmd/claude-guard/hotspots.go` + main.go dispatch. Text + JSON renderers. `schema_version: 1` baked in. | `claude-guard hotspots` on real logs prints a sane table; `--json` parses with `jq` |
| 5 | Help text + README. | `claude-guard help` lists `hotspots`; README subcommand table updated |
| 6a | Full unit test suite. | `go test ./...` green |
| 6b | End-to-end on real logs (my own `~/.claude/logs/claude-guard/decisions.jsonl`). Manually verify top 10 looks right. | Screenshot / paste top-10 output into PR description |
| 6c | `claude-guard lint` against the corpus — make sure the plan didn't regress rule coverage. | `make lint` clean |

## Failure routing

| Phase | On failure → route to |
|---|---|
| Step 1 | Blocker — don't proceed to step 2 until `stats` shows stop-hook counts from decisions.jsonl |
| Step 2 | If extraction creates an import cycle (review ↔ logshape), keep the function in review and have hotspots import review instead. Single source of truth still preserved. |
| Step 3 | Pure-function bugs → extend table tests, no architectural changes |
| Step 4 | Flag-parsing / rendering bugs → fix in-place; unit tests cover |
| Step 6b | If top-10 looks wrong (obvious bad clustering), capture the failing shape as a test case and tune — do **not** add more heuristics without evidence from real logs |
| Step 6c | Lint regressions → fix, don't skip |

## Out of scope

- **Auto-applying suggestions** — that's what `review --apply` already does. `hotspots` is read-only.
- **LLM enrichment** — deferred to a possible v2; rationale in "User experience" above.
- **Multi-project aggregation** — single project at a time; operator can loop.
- **Web UI / HTML export** — text + JSON is enough for v1.
- **New log file** — reuses existing logs.
- **Historical trend graphs** — point-in-time snapshot only.
- **Absolute-timestamp `--since`** — duration only (`6h`, `24h`, `7d`); absolute-time parsing can come later.

## Resolved (from CTO review)

- **Name:** `hotspots`.
- **Package home for shape helper:** new `internal/logshape/`, not `internal/normalize/` (semantic collision).
- **LLM enrichment:** out of v1.
- **JSON schema:** versioned from day one.

## Files modified / created

- **prerequisite PR (step 1):** `cmd/claude-guard/stop.go`, `internal/log/log.go` (if a new `LogStopHook` method helps), maybe a new writer in `internal/stop/`
- **new** `internal/hotspots/{cluster,rank,format,hotspots,hotspots_test}.go`
- **new** `internal/logshape/shape.go` + test
- **modified** `internal/review/collect.go` (use `logshape.CommandShape`)
- **new** `cmd/claude-guard/hotspots.go`
- **modified** `cmd/claude-guard/main.go` (dispatch)
- **modified** `cmd/claude-guard/stubs.go` or wherever help text lives
- **modified** `README.md` (subcommand table)

## References

- Existing: `internal/review/`, `cmd/claude-guard/stats.go`, `cmd/claude-guard/review.go`
- Log shape: `internal/log/log.go`
- Recent commits: `06bd9bf` (pipeline-readonly), `0b5373e` (stop app-log + Monitor; P0 prereq fixes the missing decisions.jsonl writer that commit left undone)
