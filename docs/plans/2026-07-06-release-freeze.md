# Task: Release Freeze — operator-toggled deploy lock enforced for all agents

**Created:** 2026-07-06
**Status:** Planning
**Context:** Robin sometimes needs a (production) release freeze — a window where no
agent, in any session, may run a deploy/release command. Today this is tribal
knowledge (see the "Monday deploy freeze" memory) enforced by hoping the agent
remembers. We want it enforced deterministically by claude-guard, which already
sits in front of every Bash call from every agent (main loop + subagents fire the
same PreToolUse hook). A freeze is an explicit operator action, not a heuristic,
so it belongs in **Tier 1 (unconditional BLOCK)** — the one tier the approve-only
LLM cannot override. Turn it on, every agent is stopped at the deploy step with a
clear, actionable message. Turn it off, back to normal.

---

## Design summary (the 30-second model)

```
freeze state file  ~/.config/claude-guard/freeze.yaml   (absent = not frozen)
        │
        ▼
Tier 1 (BLOCK) ── FIRST checks: is a freeze active for an env this command targets?
        │              │
        │              ├─ yes → DENY with a freeze-specific reason (how to lift)
        │              └─ no  → fall through to the normal tier-1 deny rules
        ▼
Tier 2..6 (unchanged)
```

Freeze is a **conditional tier-1 rule**: same "always wins, can't be bypassed"
property as `rm -rf /`, but gated on operator state instead of being always-on.
It runs *before* the cache (tier 3), so a stale `allow` verdict can never serve a
frozen command.

Three orthogonal concepts:

1. **State** — is a freeze on, for which envs, why, until when. Lives in one file.
2. **Catalog** — which command shapes count as a "release/deploy", each tagged
   with the env(s) it touches. Compiled-in defaults + config/CLI extensions.
3. **Match** — when state says env E is frozen, any catalog entry tagged E (or
   `all`) denies.

---

## Decisions (recommendation first — veto any before implementation)

### D1. Where does freeze STATE live? → **dedicated `~/.config/claude-guard/freeze.yaml`**
- **Recommended:** standalone YAML file. Presence/contents = the freeze. Mirrors
  how `llm-circuit.json` is a standalone state file. Human-readable, `cat`-able,
  `rm`-to-unfreeze, trivially inspected in `doctor`, atomic write on set.
- Alternatives rejected: (a) a `freeze:` block in `config.yaml` mixes ephemeral
  operational state with durable config; (b) the sqlite store is opaque and
  overkill for a single toggle a human wants to read and edit by hand.
- **Cache-key note:** freeze runs in tier 1, before tier 3, so it does not need to
  be in the cache key. But we still fold the freeze file's mtime+hash into the
  rules-hash so shadow traces and `replay` stay honest.

### D2. Which env(s) can be frozen? → **`prod` by default; `staging`, `dev`, `all` available**
- `claude-guard freeze on` with no `--env` freezes **`prod` only** (the common case).
- `--env prod,staging` freezes both. `--env all` freezes every catalog entry
  regardless of its env tag.
- Every catalog entry declares the env(s) it affects. **Ambiguous commands default
  to the most conservative env (`prod`).** e.g. `terraform apply` with no
  workspace signal is treated as prod-affecting, so a prod freeze catches it.
- Rationale: Robin's whole rule is "prod is careful, staging is relaxed." Freezing
  prod while still shipping to staging is the primary workflow, so env scoping is
  a first-class dimension, not an afterthought.

### D3. Does freeze honor shadow mode? → **No — freeze always enforces**
- Normal tier-1 rules respect `shadow_mode` (log-only bake-in). A freeze is a
  deliberate, explicit human toggle — there is nothing to "bake in." It enforces
  even if the guard is globally in shadow mode.
- `doctor` still surfaces this clearly so there's no surprise.
- (Robin's guard is already in `enforce` mode, so this is belt-and-suspenders, but
  the invariant matters for portability.)

### D4. Git push to `main` — frozen or not? → **frozen for repos that deploy on push**
- `git push origin main|master|production` triggers CloudBuild → prod in several
  repos (ai-site-gen, felix). Under a prod freeze this should DENY.
- But pushing a plan/docs branch, or `main` in a repo with no deploy trigger,
  should not be collateral. So the catalog entry is **repo-scoped**: it only arms
  for repos on an allowlist (`deploy_on_push_repos`, seeded with the known ones),
  or when the current repo has a `.claude-guard.yml` opting in. Everything else
  falls through to the normal smart-git-push tier.
- This reuses the existing repo-risk / git-push context the engine already loads
  (Tier 2.7), so we're not inventing new plumbing.

### D5. Enforcement granularity for subagents? → **global, all agents, no exceptions**
- The freeze file is a single global file; the hook fires for every agent. No
  per-agent carve-out — that's the entire point ("enforce for all agents").

---

## The default freeze catalog (the "include" list)

Compiled-in defaults, each an AST matcher (not a regex on raw text), tagged with envs:

| Rule name                  | Matches                                              | Env(s)  |
|----------------------------|------------------------------------------------------|---------|
| `studio-prod-release`      | `make release`                                       | prod    |
| `studio-merge-prod-pr`     | `make merge-production-pr`                            | prod    |
| `studio-provision-prod`    | `make provision-prod`                                | prod    |
| `make-deploy-prod`         | `make deploy`, `make deploy-prod`, `make release-*`  | prod    |
| `terraform-apply`          | `terraform apply` (+ `-auto-approve`)                | prod\*  |
| `gcloud-run-deploy`        | `gcloud run deploy`, `gcloud run services replace`   | prod    |
| `gcloud-builds-submit`     | `gcloud builds submit`                               | prod    |
| `git-push-deploy-branch`   | `git push <remote> main\|master\|production`         | prod    |
| `make-deploy-staging`      | `make deploy-staging`, `make provision-staging`      | staging |
| `git-push-staging`         | `git push <remote> staging`                          | staging |

\* env-ambiguous → defaults to prod (D2). A repo's `.claude-guard.yml` can retag.

**Explicitly NOT in the catalog (read-only / dry-run — never frozen):**
`make provision-diff`, `terraform plan`, `gcloud ... list|describe`, `bq ... --dry_run`,
`git push origin <feature-branch>`. Freezing dry-runs would defeat the point of a
freeze (you still want to *see* what would deploy).

**Optional include/exclude at set-time (Robin's ask):**
- `--include '<matcher>'` — arm an extra command for this freeze only. Accepts the
  same safe `program + subcommand` shape as `.claude-guard.yml` allow rules (no raw
  regex, no shells). e.g. `--include 'make:publish-content'`.
- `--exclude '<catalog-rule-name>'` — carve a named catalog entry OUT of this
  freeze. e.g. `--exclude studio-provision-prod` to still let config provisioning
  through during a code-only freeze. Excludes are recorded in the state file and
  shown in `status` / the deny message so the carve-out is auditable.

---

## Methods to SET a freeze (Robin's ask)

Three ways, in order of preference:

1. **CLI (primary):**
   ```bash
   claude-guard freeze on \
     --env prod \
     --reason "Release-train blackout — v2 launch prep" \
     --until 2026-07-14T18:00        # optional auto-expiry (local tz)
   # convenience flags:
   #   --include 'make:publish-content'      add an ad-hoc command
   #   --exclude studio-provision-prod       carve a catalog rule out
   ```
   Writes `freeze.yaml` atomically, prints the resulting status + the exact
   `freeze off` command to undo it.

2. **Manual file (scriptable / CI):** drop or edit
   `~/.config/claude-guard/freeze.yaml` directly. Same schema the CLI writes. A CI
   job or a `make freeze` target can `printf` this file. `claude-guard freeze
   validate` lints it.

3. **Env var (single session / one terminal):** `CLAUDE_GUARD_FREEZE=prod` in a
   shell freezes only agents spawned from that shell — useful to freeze one risky
   session without a global lock. Union'd with the file state (either source
   freezing an env → frozen).

> **Phase 2 (not in v1):** recurring time-window auto-freeze in `config.yaml`
> (`freeze_windows:`) to encode the existing "no prod deploy Mondays before 18:00
> CEST" rule declaratively, evaluated lazily per decision. Deliberately deferred to
> keep v1 a simple explicit toggle.

### `freeze.yaml` schema
```yaml
version: 1
frozen_envs: [prod]                 # which envs are locked
reason: "Release-train blackout — v2 launch prep"
set_by: robin
set_at: 2026-07-06T09:00:00+02:00
expires_at: 2026-07-14T18:00:00+02:00   # omit/null = manual, never auto-lifts
include:                            # optional ad-hoc extra commands
  - program: make
    subcommand: publish-content
    envs: [prod]
exclude: [studio-provision-prod]    # optional catalog carve-outs (by rule name)
```

---

## Methods to UNFREEZE (Robin's ask)

1. `claude-guard freeze off` — lift everything (removes the file).
2. `claude-guard freeze off --env staging` — lift ONE env, leave others frozen
   (rewrites `frozen_envs`).
3. **Auto-expiry** — if `expires_at` has passed, the freeze is inactive on the next
   decision (evaluated lazily, no cron). `doctor` flags the stale file and suggests
   `freeze off` to tidy it.
4. **Manual** — `rm ~/.config/claude-guard/freeze.yaml`. Presence-based, so deleting
   the file is always a valid unfreeze.
5. `CLAUDE_GUARD_FREEZE=` (unset the env var) for the session-scoped variant.

---

## Clear error message (Robin's ask — this is the payoff)

When a catalog command is denied by an active freeze, the tier-1 deny reason is:

```
🧊 RELEASE FREEZE ACTIVE (prod) — this command is blocked by claude-guard.

  Command : make release
  Matched : freeze rule "studio-prod-release" (env=prod)
  Reason  : Release-train blackout — v2 launch prep
  Set by  : robin at 2026-07-06 09:00 CEST
  Lifts   : 2026-07-14 18:00 CEST  (in 3d 8h)      # or: "manual — no expiry set"

  Staging/dev deploys are NOT frozen. To ship there, use the staging target.

  To proceed with prod you must lift the freeze first:
    claude-guard freeze status            # see everything that's frozen
    claude-guard freeze off --env prod    # lift prod only
    claude-guard freeze off               # lift all envs

  (This is an explicit operator lock — no agent can bypass it.)
```

Design points:
- Names the exact catalog rule and env so it's debuggable.
- States what is *still allowed* (staging) so the agent can route around it
  productively instead of stalling.
- Gives the literal unfreeze commands — the human reading the transcript can act in
  one copy-paste.
- Last line kills the "let me try a workaround" reflex — makes clear it's
  intentional and unbypassable.

`doctor` row:
```
[warn] freeze   ACTIVE prod — lifts 2026-07-14 18:00 (3d left), 8 rules armed, 1 excluded
# or
[ok]   freeze   none active
# or
[warn] freeze   EXPIRED prod (lapsed 2026-07-14 18:00) — run 'claude-guard freeze off' to tidy
```

---

## Plan

### Phase 1 — State + CLI (no enforcement yet; safe to land)
1. [ ] `internal/freeze/freeze.go` — `State` struct, `Load()` (file + env-var union),
       `Save()` (atomic temp+rename), `IsFrozen(env)`, `ExpiredAt(now)`, `ActiveEnvs(now)`.
       Pure, table-tested. Inject `now` for testability (no `time.Now()` in the pkg).
2. [ ] `cmd/claude-guard/freeze.go` — `freeze on|off|status|validate` subcommand;
       wire into `main.go` dispatch. `--env --reason --until --include --exclude`.
3. [ ] Unit tests: load/save round-trip, env-var union, expiry math, off-one-env,
       malformed-file → clear error (not a panic, fail toward "not frozen" but WARN).
4. [ ] `make build && make test` green.

### Phase 2 — Catalog + engine wiring (enforcement)
5. [ ] `internal/freeze/catalog.go` — compiled-in catalog as AST matchers reusing
       existing rule types (`AnchoredCommand`, `NestedSubcommand`, git-push ctx).
       Each entry: `{name, matcher, envs}`. No raw regex.
6. [ ] Engine: at the TOP of the Tier-1 block loop (before existing deny rules),
       evaluate freeze — if state says an env is frozen and a catalog entry for that
       env matches, return `Deny` with the freeze reason. Honor `exclude`. Respect
       repo-scoping for `git-push-deploy-branch` (D4) via existing git-push context.
7. [ ] Freeze enforces regardless of `shadow_mode` (D3); still records a shadow trace
       entry `freeze:<rule>` for observability.
8. [ ] Fold freeze file mtime+hash into `computeRulesHash` so replay/shadow stay honest.

### Phase 3 — Corpus + observability
9.  [ ] Corpus: add frozen commands to a new `bash_freeze_deny.txt` fixture run under
        a fixture freeze state; add the same commands to `bash_allow`/`continue` under
        NO freeze to prove they're only blocked when frozen. Add an adversarial case
        (`make release` via `bash -c`, env-var'd program) — must still deny.
10. [ ] `doctor` freeze row (active / none / expired) as specified above.
11. [ ] `claude-guard test "<cmd>"` shows `tier: instant_block, rule: freeze:<name>`
        when a freeze is active, so "why blocked" is self-service.
12. [ ] `monitor --file denies` includes freeze denies with the reason (already flows
        through the deny log — verify schema fields present).

### Phase 4 — Docs
13. [ ] Update `references/claude_guard.md` (tier list gains the conditional freeze;
        new subcommand table row; freeze.yaml schema).
14. [ ] Update the `claude-guard` SKILL.md with a "Release freeze" workflow section.
15. [ ] Update the "Monday deploy freeze" memory to point at `claude-guard freeze on`
        as the enforcement mechanism (replacing "hope the agent remembers").

## Failure Routing
| Phase | On Failure → Route To |
|---|---|
| Phase 1 | ABORT if state model unclear — it's the foundation. Bug in save/load → same step. |
| Phase 2 | Enforcement wrong (over/under-blocks) → back to Phase 1 (state) or catalog def. NEVER weaken tier-1 ordering. |
| Phase 3 | Corpus red → root-cause in Phase 2 matcher, not by loosening the test. |
| Deploy of the guard binary (`make install`) | **STOP — human decision.** Robin installs; the guard gates his own commands. |

## Safety invariants (non-negotiable — carry into implementation)
- Freeze **cannot** weaken tier 1. It only ADDS denies. A malformed freeze file
  fails toward "not frozen" but logs a WARN (never a panic, never a broken guard).
- Freeze deny is **unbypassable by agents** — it's tier 1; the LLM tier is
  approve-only and runs later.
- Read-only / dry-run commands are never in the catalog.
- Single global state → every agent in every session is subject to the same freeze.

## Allowed commands (agent-friendly execution)
`cd ~/Documents/code/claude-guard && make build`, `make test`, `make install`,
`go test ./...`, `go vet ./...`, `claude-guard test "<cmd>"`, `claude-guard doctor`,
`claude-guard freeze status`.

## Notes
### 2026-07-06 — Decision: freeze as conditional tier-1, not a new tier
Considered a dedicated "Tier 1.5". Rejected: freeze IS a block and must obey the
"tier 1 always wins" invariant and run before the cache. Slotting it at the top of
the existing tier-1 loop keeps one ordering guarantee instead of two, and reuses the
existing deny plumbing (log schema, shadow trace, `test` output). Lower risk.

### 2026-07-06 — Decision: state in a file, not sqlite/config
See D1. Operational, human-editable, presence-based unfreeze. Matches llm-circuit.json.

## Files to be created / modified
- `internal/freeze/freeze.go` (new) — state model
- `internal/freeze/catalog.go` (new) — compiled-in catalog
- `internal/freeze/*_test.go` (new) — unit + table tests
- `cmd/claude-guard/freeze.go` (new) — CLI subcommand
- `cmd/claude-guard/main.go` — dispatch wiring
- `cmd/claude-guard/doctor.go` — freeze health row
- `internal/engine/engine.go` — tier-1 freeze evaluation + rules-hash fold
- `internal/corpus/testdata/bash_freeze_deny.txt` (new) — fixture
- `references/claude_guard.md`, SKILL.md, Monday-freeze memory — docs

## References
- Existing tier model + invariants: `references/claude_guard.md`
- Repo-risk / smart git-push context (reused for D4): `docs/plans/2026-06-07-smart-git-push.md`
- Monday deploy freeze (the informal rule this formalizes): CTO-as-a-service memory
