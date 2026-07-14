package freeze

import "github.com/RobinUS2/claude-guard/internal/rules"

// Confidence controls what a catalog match does when its env is frozen.
type Confidence int

const (
	// High — the command is unambiguously a release/deploy to the tagged env.
	// A frozen match hard-DENIES (Tier 1, unbypassable by agents).
	High Confidence = iota
	// Ambiguous — the command PLAUSIBLY deploys to the tagged env but the
	// guard can't confirm the target/env. A frozen match ASKS the user (the
	// dialog names the freeze) rather than silently blocking. This is Robin's
	// "in case of doubt, ask" band.
	Ambiguous
)

// Entry is one catalog rule: a command matcher tagged with the env(s) it
// affects and a confidence that decides deny-vs-ask.
type Entry struct {
	Name       string
	Envs       []string
	Confidence Confidence
	Rule       rules.Rule
}

// Catalog is the compiled-in set of release/deploy commands. Each matcher is an
// AST matcher (never a regex on raw text) so `make release && echo done` still
// matches. Read-only / dry-run commands are deliberately absent — you still
// want to SEE what would deploy during a freeze.
//
// Deliberately NOT here: `make provision-diff`, `terraform plan`,
// `gcloud ... list|describe`, `bq ... --dry_run`, feature-branch pushes.
func Catalog() []Entry {
	return []Entry{
		// --- prod, high confidence → DENY ---
		{
			Name:       "make-prod-release",
			Envs:       []string{"prod"},
			Confidence: High,
			// `make <target>` — positional[0] is the target. NestedSubcommand
			// with bare nouns matches the target regardless of trailing args,
			// and scans every top-level call so `make release && x` is caught.
			Rule: &rules.NestedSubcommand{
				RuleName: "make-prod-release",
				Program:  "make",
				Destructive: []string{
					"release", "deploy", "deploy-prod", "release-prod",
					"provision-prod", "merge-production-pr",
				},
				Reason: "make prod release/deploy target",
			},
		},
		{
			Name:       "gcloud-deploy",
			Envs:       []string{"prod"},
			Confidence: High,
			Rule: &rules.NestedSubcommand{
				RuleName: "gcloud-deploy",
				Program:  "gcloud",
				// run/deploy and builds/submit only — NOT run/services (that
				// would also catch `gcloud run services list`, a read).
				Destructive: []string{"run/deploy", "builds/submit"},
				Reason:      "gcloud prod deploy",
			},
		},

		// --- prod, ambiguous → ASK ("in doubt, ask") ---
		{
			Name:       "terraform-apply",
			Envs:       []string{"prod"},
			Confidence: Ambiguous,
			// terraform apply's target env depends on workspace/vars the guard
			// can't see, so it ASKS (surfacing the freeze) rather than blocking.
			Rule: &rules.NestedSubcommand{
				RuleName:    "terraform-apply",
				Program:     "terraform",
				Destructive: []string{"apply"},
				Reason:      "terraform apply (target env unknown)",
			},
		},
		// git push to a protected branch is handled inline in Evaluate (branch
		// resolution needs positional[2] / remote parsing that the generic
		// matchers don't express) — see gitPushDeployEntry.

		// --- staging → only armed under a staging (or all) freeze ---
		{
			Name:       "make-staging-deploy",
			Envs:       []string{"staging"},
			Confidence: High,
			Rule: &rules.NestedSubcommand{
				RuleName:    "make-staging-deploy",
				Program:     "make",
				Destructive: []string{"deploy-staging", "provision-staging"},
				Reason:      "make staging deploy target",
			},
		},
	}
}

// gitPushDeployName is the synthetic catalog rule name for a protected-branch
// push. Ambiguous by design: push-to-main means "deploy" in some repos and
// "just build" in others (e.g. Studio: main = build, `make release` = deploy),
// so it ASKS and names the freeze rather than hard-blocking.
const gitPushDeployName = "git-push-deploy-branch"

// protectedBranches are the branch names whose push is treated as a
// (possibly) deploy-triggering action under a prod freeze.
var protectedBranches = []string{"main", "master", "production", "prod"}
