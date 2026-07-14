package freeze

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateMatrix(t *testing.T) {
	aiSiteGen := "git@github.com:taufinity/ai-site-gen.git"
	felix := "git@github.com:taufinity/felix.git"

	cases := []struct {
		name    string
		cmd     string
		remote  string
		state   *State
		want    Action
		wantRule string
	}{
		// --- confident prod deploys → DENY ---
		{"make release denied", "make release", aiSiteGen, prodState(), Deny, "make-prod-release"},
		{"make provision-prod denied", "make provision-prod", aiSiteGen, prodState(), Deny, "make-prod-release"},
		{"merge-production-pr denied", "make merge-production-pr", aiSiteGen, prodState(), Deny, "make-prod-release"},
		{"gcloud run deploy denied", "gcloud run deploy svc --image x", aiSiteGen, prodState(), Deny, "gcloud-deploy"},
		{"gcloud builds submit denied", "gcloud builds submit .", aiSiteGen, prodState(), Deny, "gcloud-deploy"},
		{"compound command still denied", "make release && echo done", aiSiteGen, prodState(), Deny, "make-prod-release"},

		// --- ambiguous → ASK ("in doubt, ask") ---
		{"terraform apply asks", "terraform apply", aiSiteGen, prodState(), Ask, "terraform-apply"},
		{"terraform apply auto-approve asks", "terraform apply -auto-approve", aiSiteGen, prodState(), Ask, "terraform-apply"},
		{"git push main asks", "git push origin main", aiSiteGen, prodState(), Ask, "git-push-deploy-branch"},
		{"git push master asks", "git push origin master", aiSiteGen, prodState(), Ask, "git-push-deploy-branch"},

		// --- clearly not a frozen-env deploy → PASS ---
		{"dry-run passes", "make provision-diff", aiSiteGen, prodState(), Pass, ""},
		{"terraform plan passes", "terraform plan", aiSiteGen, prodState(), Pass, ""},
		{"gcloud list passes", "gcloud run services list", aiSiteGen, prodState(), Pass, ""},
		{"feature branch push passes", "git push origin feat/x", aiSiteGen, prodState(), Pass, ""},
		{"staging deploy passes under prod freeze", "make deploy-staging", aiSiteGen, prodState(), Pass, ""},
		{"unrelated command passes", "ls -la", aiSiteGen, prodState(), Pass, ""},

		// --- project scoping: felix untouched by ai-site-gen freeze ---
		{"felix not frozen by ai-site-gen scope", "make release", felix,
			&State{FrozenEnvs: []string{"prod"}, Projects: []string{"ai-site-gen"}}, Pass, ""},
		{"ai-site-gen frozen by its scope", "make release", aiSiteGen,
			&State{FrozenEnvs: []string{"prod"}, Projects: []string{"ai-site-gen"}}, Deny, "make-prod-release"},

		// --- staging freeze arms staging entries ---
		{"staging deploy denied under staging freeze", "make deploy-staging", aiSiteGen,
			&State{FrozenEnvs: []string{"staging"}}, Deny, "make-staging-deploy"},
		{"prod deploy passes under staging-only freeze", "make release", aiSiteGen,
			&State{FrozenEnvs: []string{"staging"}}, Pass, ""},

		// --- all-env freeze catches both ---
		{"all freeze catches prod", "make release", aiSiteGen,
			&State{FrozenEnvs: []string{"all"}}, Deny, "make-prod-release"},
		{"all freeze catches staging", "make deploy-staging", aiSiteGen,
			&State{FrozenEnvs: []string{"all"}}, Deny, "make-staging-deploy"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := Evaluate(mustParse(t, tc.cmd), tc.remote, []*State{tc.state}, now)
			if out.Action != tc.want {
				t.Errorf("Evaluate(%q) action = %s, want %s (rule=%q reason=%q)",
					tc.cmd, out.Action, tc.want, out.Rule, out.Reason)
			}
			if tc.wantRule != "" && out.Rule != tc.wantRule {
				t.Errorf("Evaluate(%q) rule = %q, want %q", tc.cmd, out.Rule, tc.wantRule)
			}
		})
	}
}

func TestExcludeCarvesOut(t *testing.T) {
	s := prodState()
	s.Exclude = []string{"make-prod-release"}
	out := Evaluate(mustParse(t, "make release"), "", []*State{s}, now)
	if out.Action != Pass {
		t.Errorf("excluded rule should pass, got %s", out.Action)
	}
}

func TestIncludeAddsDeny(t *testing.T) {
	s := prodState()
	s.Include = []IncludeRule{{Program: "make", Subcommand: "publish-content", Envs: []string{"prod"}}}
	out := Evaluate(mustParse(t, "make publish-content"), "", []*State{s}, now)
	if out.Action != Deny {
		t.Errorf("included command should deny, got %s", out.Action)
	}
}

func TestExpiredFreezeDoesNotBlock(t *testing.T) {
	past := now.Add(-time.Hour)
	s := prodState()
	s.ExpiresAt = &past
	out := Evaluate(mustParse(t, "make release"), "", []*State{s}, now)
	if out.Action != Pass {
		t.Errorf("expired freeze should pass, got %s", out.Action)
	}
}

func TestDenyBeatsAsk(t *testing.T) {
	// A command that both asks (git push main) and denies (make release) must DENY.
	out := Evaluate(mustParse(t, "git push origin main && make release"), "", []*State{prodState()}, now)
	if out.Action != Deny {
		t.Errorf("deny must win over ask, got %s", out.Action)
	}
}

func TestReasonMentionsFreezeAndUnlock(t *testing.T) {
	out := Evaluate(mustParse(t, "make release"), "", []*State{prodState()}, now)
	for _, want := range []string{"RELEASE FREEZE ACTIVE", "freeze off", "test freeze"} {
		if !strings.Contains(out.Reason, want) {
			t.Errorf("reason missing %q:\n%s", want, out.Reason)
		}
	}
}
