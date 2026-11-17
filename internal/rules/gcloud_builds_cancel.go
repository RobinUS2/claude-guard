package rules

import (
	"path/filepath"
	"regexp"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

// GcloudBuildsCancel matches any call that runs `gcloud builds cancel`, in
// any disguise the parser can see through:
//
//   - gcloud flags before or between the words (--project, --region, ...)
//   - release tracks (`gcloud alpha builds cancel`, `gcloud beta ...`)
//   - an absolute path to gcloud
//   - wrapper programs (env, command, timeout, nohup, time, xargs, ...):
//     the rule scans every argument of every call, so the wrapped gcloud is
//     found wherever it sits in the argument list
//   - any nesting: for/while bodies, $(...) anywhere (also inside arguments),
//     subshells, `time`, process substitution (found by walking the whole AST
//     via Parsed.AllCalls, not only the flattened Parsed.Calls)
//   - shell -c / eval payloads, matched by regex on the argument text
//
// It does NOT match a mention of the words inside a single quoted argument of
// a non-shell program (`echo "gcloud builds cancel"`, `grep "builds cancel"`).
// A `gcloud builds` call whose verb slot is an unresolvable expansion
// (`gcloud builds $verb`) also matches, since the verb could be cancel.
type GcloudBuildsCancel struct {
	RuleName string
	Reason   string
}

func (r *GcloudBuildsCancel) Name() string { return r.RuleName }
func (r *GcloudBuildsCancel) Kind() string { return "gcloud_builds_cancel" }

var buildsCancelText = regexp.MustCompile(`(^|[^A-Za-z0-9_-])gcloud\b.*\bbuilds\b.*\bcancel\b`)

var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "eval": true,
}

func (r *GcloudBuildsCancel) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.AllCalls() {
		if callRunsBuildsCancel(c) {
			return Match, r.Reason
		}
	}
	return NoMatch, ""
}

func callRunsBuildsCancel(c shellparse.Call) bool {
	// Token stream: program then every argument, positions preserved.
	toks := make([]string, 0, len(c.Args)+1)
	toks = append(toks, c.Program)
	toks = append(toks, c.Args...)

	// Shell -c / eval payload: the command text is one argument.
	if shellInterpreters[filepath.Base(c.Program)] {
		for _, a := range c.Args {
			if buildsCancelText.MatchString(a) {
				return true
			}
		}
	}

	for i, t := range toks {
		if t == "" || filepath.Base(t) != "gcloud" {
			continue
		}
		// gcloud found at i (as program or as a wrapped argument). Look for
		// `builds` after it, then `cancel` after that.
		for j := i + 1; j < len(toks); j++ {
			if toks[j] != "builds" {
				continue
			}
			if j+1 < len(toks) && toks[j+1] == "" {
				// Unresolvable expansion right in the verb slot.
				return true
			}
			for k := j + 1; k < len(toks); k++ {
				if toks[k] == "cancel" {
					return true
				}
			}
			break
		}
	}
	return false
}
