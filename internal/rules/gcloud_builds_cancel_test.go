package rules

import "testing"

func evalBuildsCancel(t *testing.T, cmd string) Verdict {
	t.Helper()
	r := &GcloudBuildsCancel{RuleName: "gcloud-builds-cancel", Reason: "x"}
	v, _ := r.Eval(mustParse(t, cmd))
	return v
}

func TestGcloudBuildsCancel_Matches(t *testing.T) {
	for _, cmd := range []string{
		"gcloud builds cancel 1234-abcd",
		"gcloud --project=p beta builds cancel 1234-abcd",
		"timeout 5 sh -c 'gcloud builds cancel x'",
		"for i in $(gcloud builds list --format='value(id)'); do gcloud builds cancel $i; done",
		// REST with expansions, a URL in a variable, host case, encoded colon
		"curl -X POST https://cloudbuild.googleapis.com/v1/projects/p/builds/$ID:cancel",
		"curl -X POST \"https://cloudbuild.googleapis.com/v1/projects/$P/builds/$ID:cancel\"",
		"U=https://cloudbuild.googleapis.com/v1/projects/p/builds/x:cancel; curl -X POST $U",
		"curl -X POST https://CLOUDBUILD.GOOGLEAPIS.COM/v1/projects/p/builds/x:cancel",
		"curl -X POST https://cloudbuild.googleapis.com/v1/projects/p/builds/x%3Acancel",
		// ANSI-C words, brace expansion, globs
		"gcloud $'builds' cancel x",
		"gcloud builds $'can\\x63el' x",
		"gcloud builds {cancel,list} x",
		"gcloud builds c* x",
		"gcloud b* cancel x",
		// unresolved combinations
		"gcloud $BC x",
		"gcloud $A $B",
		"G=gcloud; $G $X",
		"G=gcloud; $G builds $V x",
		// more programs that run a command string
		"env -S 'gcloud builds cancel x'",
		"npx -c 'gcloud builds cancel x'",
		"watchexec 'gcloud builds cancel x'",
		"git rebase --exec 'gcloud builds cancel x' HEAD~1",
		"git -c alias.zz='!gcloud builds cancel x' zz",
		"source <(echo 'gcloud builds cancel x')",
		". /dev/stdin <<< 'gcloud builds cancel x'",
	} {
		if got := evalBuildsCancel(t, cmd); got != Match {
			t.Errorf("%q: got %v, want Match", cmd, got)
		}
	}
}

func TestGcloudBuildsCancel_NoMatches(t *testing.T) {
	for _, cmd := range []string{
		"gcloud builds list --project=p",
		"gcloud builds describe $ID --project=p",
		"gcloud builds log $ID",
		"gcloud run jobs executions cancel $E",
		"gcloud dataflow jobs cancel $J",
		"echo 'gcloud builds cancel'",
		"grep -r 'builds cancel' docs",
		"curl -s https://cloudbuild.googleapis.com/v1/projects/$P/builds/$ID",
		"git commit -m 'mention gcloud builds cancel'",
		"git rebase --exec 'make test' HEAD~1",
		"source <(direnv export bash)",
		". ./venv/bin/activate",
		"$EDITOR $FILE",
	} {
		if got := evalBuildsCancel(t, cmd); got != NoMatch {
			t.Errorf("%q: got %v, want NoMatch", cmd, got)
		}
	}
}

// An ordinary command must not pay for the raw-text checks.
func TestGcloudBuildsCancel_RawChecksAreLazy(t *testing.T) {
	boom := func() bool { t.Fatal("raw-text check ran for an ordinary command"); return false }
	texts := &rawTexts{hit: boom, rest: boom, mentions: boom}
	for _, cmd := range []string{
		"ls -la /tmp",
		"gcloud builds list --project=p",
		"git status",
		"gh pr comment 1 --body 'gcloud builds cancel policy'",
	} {
		for _, c := range mustParse(t, cmd).AllCalls() {
			if callRunsBuildsCancel(c, texts) {
				t.Errorf("%q matched", cmd)
			}
		}
	}
}
