# Plan: Flow Quality Metrics — Tool-Calls-to-Interrupt + Long-Term Charting

**Created:** 2026-06-07
**Status:** Planning
**Context:** User request: "measure tokens-to-interrupt and auto-approves-to-interrupt ratios,
long-term charting so we can see how the system improves (or not)."

Current stats show interrupt COUNT and interrupt RATE but not interrupt CONTEXT — how many
uninterrupted operations Claude completed before each prompt, or whether improvements to the
guard are actually showing up in the trend over weeks.

---

## Two New Metrics

### Metric A: Auto-approves-to-interrupt ratio

How many auto-allowed tool calls happen between each user-prompt interrupt. High = good.
Low = the guard is disrupting every other operation.

**Current proxy:** `computeStretches` in `stats.go` measures TIME between interrupts.
This is less useful than COUNT (time varies; a fast Tier 2 allow and a slow LLM allow both
count the same in time but the LLM one was slower).

**Implementation:** Straightforward from `decisions.jsonl`:
- For each session, walk decisions in timestamp order
- Count `verdict=allow` calls between each `verdict=continue` call
- Metrics: median, p95, p99, max

**Example output:**
```
flow quality (last 24h):
  auto-approves between interrupts:
    median:  12 tool-calls
    p95:     47 tool-calls  
    longest: 183 tool-calls
  interrupts per session:
    median:  3
    p95:     12
```

### Metric B: Tool-calls-to-interrupt (proxy for tokens)

Tokens require reading Claude's transcript JSONL files — expensive and fragile.
Tool calls (from `decisions.jsonl`) are a good proxy: more tool calls = more productive work.

`tool-calls-to-interrupt` = same as auto-approves-to-interrupt but includes ALL tool calls
(Bash, Read, Edit, Write, WebFetch, etc.), not just Bash. This gives a fuller picture of
Claude's work rhythm.

**Note:** The hook currently only processes Bash, WebFetch, WebSearch, Read, Write, Edit, and
generic MCP tools. All of these already flow through the guard and are logged. So tool-call
count is already fully captured.

---

## Long-Term Charting

The `metrics_snapshots` SQLite table already has time-series support (used by `claude-guard stats --history`). We need two additions:

### Schema change (schemaVersion bump to 3):

```sql
ALTER TABLE metrics_snapshots ADD COLUMN median_auto_approves_per_interrupt REAL;
ALTER TABLE metrics_snapshots ADD COLUMN p95_auto_approves_per_interrupt REAL;
ALTER TABLE metrics_snapshots ADD COLUMN median_tool_calls_per_interrupt REAL;
```

### `stats --record` enrichment:

The existing `--record` flag already saves snapshots. Extend it to compute and save the new metrics.

### `stats --history` table update:

Add new columns to the trend table:
```
date         decisions  allow%  interrupts  calls/interrupt  learned
2026-06-01       412    91.8%          34             11.2     312
2026-06-07       914    94.3%          60             15.4     357  ← improving
```

---

## Implementation Phases

### Phase 1: Core computation (1h)
- [ ] `cmd/claude-guard/stats.go` — add `computeFlowQuality(agg *aggregation)` function
  - Walk each session's decisions in order
  - Count auto-allows between each Continue
  - Return slice of counts per stretch
- [ ] Output in `cmdStats` under new "flow quality" section
- [ ] `percentileInt` helper (like `percentileMs` but for int counts)

### Phase 2: Snapshot storage (30 min)
- [ ] `internal/store/store.go` — bump `schemaVersion` to 3
  - Additive migration: `ALTER TABLE metrics_snapshots ADD COLUMN ...`
- [ ] `store.MetricsSnapshot` struct — add new fields
- [ ] `store.RecordMetrics` — populate new fields
- [ ] `store.GetMetricsHistory` — scan new columns

### Phase 3: History display (30 min)
- [ ] `stats --history` table: add `calls/int` column
- [ ] `compare`: add "auto-approves/interrupt p50" row
- [ ] Test: run `stats --record`, then `stats --history` shows new columns

---

## Files to Touch

| File | Change |
|---|---|
| `cmd/claude-guard/stats.go` | `computeFlowQuality`, new output section, `--record` enrichment |
| `internal/store/store.go` | schemaVersion 3, new columns |
| `cmd/claude-guard/compare.go` | new metric row |

---

## Success Criteria

- `claude-guard stats` shows "auto-approves between interrupts: median X, p95 Y"
- `claude-guard stats --record` saves new metrics to SQLite
- `claude-guard stats --history` shows trend over time
- After implementing Plan 1 (learning pipeline fixes), the history table shows improvement

---

## Failure Routing

| Step | On failure → |
|---|---|
| Schema migration | Additive ALTER TABLE; existing rows get NULL for new columns |
| computeFlowQuality | Returns zeros; stats still prints without new section |
| History columns missing | Old SQLite DBs with NULL just show 0.0 |

---

## Example Trend (expected after shipping all 4 plans)

```
claude-guard stats --history

trend (last 30 days):
  date         decisions  allow%  interrupts  calls/int  learned
  2026-06-01       412    91.8%          34       11.2      312
  2026-06-07a      914    93.4%          60       12.1      357  ← before fixes
  2026-06-07b      ...    96.2%          22       28.4      360  ← after all plans
                                         ↑ 63%   ↑ 2.4x    ← headline improvement
```

The "calls per interrupt" ratio doubling means Claude can do twice as much work between
each approval prompt — the core goal of the session-aware improvement program.
