# Plan: Smart Git Push — Scope-Aware Risk Scoring

**Created:** 2026-06-07
**Status:** Planning
**Context:** The current `git-push-nonforce` Tier 2 rule auto-allows ALL non-force git
pushes regardless of repo importance, branch, CI/CD presence, or push size. The right
answer is: allow pushes that are demonstrably safe (feature branches to personal repos,
small doc changes) and send high-impact pushes (main branch of production repos, repos
with CI/CD) to the LLM for context-aware review.

---

## The Problem

`git push origin main` to ai-site-gen triggers a Cloud Build pipeline affecting production
customers. `git push origin main` to a 50-line personal experiment repo is inconsequential.
The same rule currently applies to both, which means either:
- Both get auto-allowed (too permissive for production), or
- Both go to the LLM (too slow for trivial repos)

The answer is a risk score computed from context, not a binary rule.

---

## Risk Scoring Model

**Score 0–10. Score ≥ 4 → LLM review. Score < 4 → auto-allow.**

| Factor | Impact | How detected |
|---|---|---|
| Explicit HIGH-risk repo | +5 | `repo-risk.yaml` entry or remote URL pattern |
| Explicit LOW-risk repo | −4 | `repo-risk.yaml` entry |
| Main/master branch | +2 | `git symbolic-ref HEAD` or command arg parsing |
| Protected branch pattern (release/*, prod) | +2 | branch name regex |
| CI/CD detected | +2 | `.github/workflows/` or `cloudbuild.yaml` exists |
| Diff size > 20 files | +2 | `git diff --stat origin/<branch>` count |
| Diff size > 100 files | +3 | same |
| Feature branch (`feature/*`, `fix/*`) | −1 | branch name pattern |
| Worktree push (path includes `.worktrees`) | −1 | CWD path |
| Tag push (`git push origin v*`) | −1 | command arg: `origin v*` |

**Score table:**
- 0–3: Auto-allow (Tier 2.5 "push-safe")
- 4–6: LLM review (Tier 4 with context injected)
- 7+: User prompt (downgrade from LLM-only to explicit require-user)

---

## Repo Risk Registry

`~/.config/claude-guard/repo-risk.yaml` — per-user override file, read at startup:

```yaml
version: 1
repos:
  # HIGH-risk: production customer-facing, always LLM review for main
  - remote_pattern: "github.com/RobinUS2/ai-site-gen"
    risk: high
    reason: "production SaaS, triggers Cloud Build on main push"

  - remote_pattern: "github.com/Brendan-MacKenzie/Mr-Einstein"
    risk: high
    reason: "customer production repo"

  # LOW-risk: personal tools, always auto-allow
  - remote_pattern: "github.com/RobinUS2/cto-as-a-service"
    risk: low
    reason: "personal tooling, no customers affected"

  - remote_pattern: "github.com/RobinUS2/claude-guard"
    risk: medium
    reason: "security tool, main branch installs to production use"
```

**The registry is loaded once at engine startup** (same lifecycle as legacy allow list).
Missing file = all repos are medium risk (fallback to heuristic scoring only).

---

## Implementation

### New rule type: `internal/rules/git_push_risk.go`

Unlike `AnchoredCommand`, this rule needs:
1. Shell access to check diff stats and CI/CD presence
2. CWD to resolve repo context
3. The repo risk registry

```go
type GitPushRiskRule struct {
    RuleName string
    Registry *reporisk.Registry  // loaded from repo-risk.yaml
    // ScoreThresholdAllow: score <= this → auto-allow
    ScoreThresholdAllow int // default 3
}

func (r *GitPushRiskRule) Eval(parsed *shellparse.ParsedCommand) (rules.Verdict, string)
```

But wait — `rules.Rule` only gets the parsed command, not CWD or shell access.

**Better approach: a new "pre-LLM enrichment" step in the engine.**

Instead of a rule, add a `gitPushRisk` evaluator that runs between Tier 2 (instant_allow)
and the LLM tier. If the command is a git push, score it:
- Low score → return Allow immediately (skip LLM, label tier "push-safe")
- High score → inject score context into the LLM prompt, tag as "high-risk-push"
- Score >= 7 → return Continue (require user, don't even try LLM)

This mirrors how `bqBudget` works: a specialized pre-flight that runs between Tier 2 and Tier 4.

### Engine location: Tier 2.7 (after session cache, before global LLM cache)

```
Tier 2 (instant_allow) →
Tier 2.5 (session cache) →
Tier 2.6 (workflow sequences) →
Tier 2.7 (git push risk score) ← NEW
Tier 3 (LLM cache) →
Tier 4 (LLM) ←  if score 4-6: inject risk context into prompt
→ Tier 6 (Continue/user prompt) ← if score >= 7
```

### New package: `internal/reporisk/`

```go
package reporisk

type Level string
const (
    LevelHigh   Level = "high"
    LevelMedium Level = "medium"
    LevelLow    Level = "low"
)

type RepoEntry struct {
    RemotePattern string `yaml:"remote_pattern"`
    Risk          Level  `yaml:"risk"`
    Reason        string `yaml:"reason"`
}

type Registry struct {
    Repos []RepoEntry `yaml:"repos"`
}

func Load(path string) (*Registry, error)
func (r *Registry) Score(remoteURL string) Level
```

### New: `internal/engine/gitpush.go`

```go
// gitPushScore computes a 0-10 risk score for a git push command.
// Called from Decide() when the command is a git push.
func (e *Engine) gitPushScore(in Input) (score int, explanation string)

// extractGitRemoteURL shells out to `git remote get-url origin`
// from the command's CWD. Cached per-CWD for the process lifetime.
func (e *Engine) extractGitRemoteURL(cwd string) string
```

---

## LLM Context Injection for Medium-Risk Pushes

When score is 4–6, the engine adds a `GitPushContext` block to `ClassifyInput`:

```go
// in llm.go ClassifyInput
GitPushContext string // populated for git push commands, empty otherwise
```

The LLM prompt injection:
```
GIT PUSH CONTEXT:
  remote: github.com/RobinUS2/ai-site-gen
  branch: main
  risk-level: high (production SaaS repo, triggers Cloud Build)
  diff-size: 3 files changed
  ci-cd: yes (cloudbuild.yaml present)

This is a push to a production repository's main branch. Evaluate carefully:
approve only if the changes appear routine (doc fixes, minor config) and the
user clearly intends to ship this. Return "unsafe" if this is pushing
experimental/wip code to a production branch.
```

This gives the LLM exactly the context it needs to make a smart decision.

---

## Implementation Phases

### Phase 1: repo risk registry (1h)
- [ ] `internal/reporisk/registry.go` — Load, Score, Level
- [ ] `internal/reporisk/registry_test.go` — load YAML, score known/unknown repos
- [ ] Default registry file at `~/.config/claude-guard/repo-risk.yaml` (create with known repos)

### Phase 2: git push scoring (1.5h)
- [ ] `internal/engine/gitpush.go` — `gitPushScore`, `extractGitRemoteURL`, CWD-cache
- [ ] Integrate into `engine.Decide()` as Tier 2.7 (between session tiers and global cache)
- [ ] Populate `ClassifyInput.GitPushContext` when score 4–6
- [ ] Tests: known-high repo → score ≥4; feature branch personal repo → score <4

### Phase 3: llm.go context field (30min)
- [ ] Add `GitPushContext string` to `ClassifyInput`
- [ ] Update `buildUserMessage` to inject when non-empty

### Phase 4: verify + corpus (30min)
- [ ] `claude-guard test "git push origin main"` (cwd=ai-site-gen) → LLM tier
- [ ] `claude-guard test "git push origin feature-x"` (cwd=cto-as-a-service) → allow
- [ ] Add corpus entries for both scenarios

---

## Success Criteria

| Scenario | Expected |
|---|---|
| `git push origin main` in ai-site-gen | Score ≥ 4 → LLM tier |
| `git push origin feature-branch` in ai-site-gen | Score 2–3 → auto-allow |
| `git push origin main` in cto-as-a-service | Score 1–2 (low-risk in registry) → auto-allow |
| `git push origin v0.6.7` (tag) anywhere | Score ≤ 2 → auto-allow |
| `git push` with CI/CD detected, main branch, >20 files | Score 7+ → user prompt |

---

## Files to Create/Modify

| File | Change |
|---|---|
| `internal/reporisk/registry.go` | New — YAML loader + scorer |
| `internal/reporisk/registry_test.go` | New — tests |
| `internal/engine/gitpush.go` | New — scorer + CWD cache |
| `internal/engine/engine.go` | Tier 2.7 + Options.RepoRisk field |
| `internal/llm/llm.go` | Add `GitPushContext` to ClassifyInput |
| `cmd/claude-guard/decide.go` | Load registry + wire to engine |
| `~/.config/claude-guard/repo-risk.yaml` | Create with known repos |

---

## Failure Routing

| Step | On failure → |
|---|---|
| Registry file missing | All repos = medium risk (heuristic-only scoring) |
| `git remote get-url` fails | Remote URL unknown → +0 score (neutral) |
| `git diff --stat` fails | Diff size unknown → +0 score |
| CI/CD check fails | CI/CD unknown → +0 score |
| Score computed but wrong | Worst case: wrong tier (LLM instead of allow or vice versa) |
| Shell timeout | Skip all shell-based factors, use registry + branch name only |

---

## Open Questions

1. **Score thresholds:** 4 for LLM review, 7 for user-only — these are starting values, 
   tunable based on observed false positive/negative rate via `replay`.

2. **Worktree pushes:** Pushes from within a `.worktrees/` CWD already have less impact
   (isolated branch). Reduce score by 1.

3. **`git push origin main` is always "score +2 for main branch"** — but should there be
   a separate score bump for repos that have `CODEOWNERS` or branch protection rules?
   Those are indicators of organizational importance. Read from `.github/CODEOWNERS` if
   present.

4. **Cross-session learning:** Once the LLM approves `git push origin main` for a specific
   repo+branch combo, cache the verdict project-scoped. Subsequent identical pushes to the
   same repo/branch auto-approve from the LLM cache. This already works with the rulesHash fix.
