package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// GcloudBuildsCancel matches any call that runs `gcloud builds cancel`, in
// any disguise the parser can see through:
//
//   - gcloud flags before or between the words (--project, --region, ...)
//   - release tracks (`gcloud alpha builds cancel`, `gcloud beta ...`)
//   - an absolute path to gcloud, a leading backslash, a zsh `=gcloud`
//   - wrapper programs (env, command, timeout, nohup, time, xargs, ...):
//     the rule scans every argument of every call, so the wrapped gcloud is
//     found wherever it sits in the argument list
//   - any nesting: for/while bodies, $(...) anywhere (also inside arguments),
//     subshells, `time`, process substitution (found by walking the whole AST
//     via Parsed.AllCalls, not only the flattened Parsed.Calls)
//   - a shell interpreter (sh, bash, eval, ...) at ANY token position, so
//     `timeout 5 sh -c '...'`, `xargs sh -c`, a heredoc, a here-string or
//     `echo '...' | sh` is matched by regex on the whole command text
//   - words that cannot be resolved statically (variables, substitutions) in
//     the gcloud, builds or verb position: fail toward Ask
//   - the REST form: curl/wget/http against cloudbuild.googleapis.com
//     .../builds/ID:cancel
//
// It does NOT match a mention of the words inside a single quoted argument of
// a non-shell program (`echo "gcloud builds cancel"`, `grep "builds cancel"`).
type GcloudBuildsCancel struct {
	RuleName string
	Reason   string
}

func (r *GcloudBuildsCancel) Name() string { return r.RuleName }
func (r *GcloudBuildsCancel) Kind() string { return "gcloud_builds_cancel" }

var buildsCancelText = regexp.MustCompile(`(?s)(^|[^A-Za-z0-9_-])gcloud\b.*\bbuilds\b.*\bcancel\b`)

var buildsCancelREST = regexp.MustCompile(`cloudbuild\.googleapis\.com/\S*builds/[^/:\s]+:cancel`)

var restClients = map[string]bool{
	"curl": true, "wget": true, "http": true, "https": true, "xh": true, "httpie": true,
}

var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "eval": true,
	// programs that run a quoted command string
	"watch": true, "tmux": true, "parallel": true, "ssh": true, "script": true,
	"flock": true, "screen": true,
}

// Read-only or otherwise non-cancel verbs of `gcloud builds`. Once the first
// positional is one of these the verb is known and later expansions are
// just arguments.
var buildsKnownVerbs = map[string]bool{
	"list": true, "describe": true, "log": true, "submit": true, "triggers": true,
	"worker-pools": true, "connections": true, "repositories": true,
	"approve": true, "reject": true, "enterprise-config": true,
}

// Global gcloud flags whose value is a separate word, so the value is not
// mistaken for the verb.
var gcloudValueFlags = map[string]bool{
	"--project": true, "--region": true, "--account": true, "--format": true,
	"--filter": true, "--limit": true, "--sort-by": true, "--page-size": true,
	"--impersonate-service-account": true, "--configuration": true,
}

func (r *GcloudBuildsCancel) Eval(p *shellparse.Parsed) (Verdict, string) {
	raw := strings.NewReplacer("\\\n", "", "\\", "", "'", "", `"`, "").Replace(p.Raw)
	rawHit := buildsCancelText.MatchString(raw)
	for _, c := range p.AllCalls() {
		if callRunsBuildsCancel(c, rawHit) {
			return Match, r.Reason
		}
	}
	return NoMatch, ""
}

func norm(t string) string {
	return strings.TrimPrefix(strings.ReplaceAll(t, `\`, ""), "=")
}

// wordUnresolved reports whether the word's value depends on an expansion.
func wordUnresolved(w *syntax.Word) bool {
	for _, part := range w.Parts {
		switch pt := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			for _, in := range pt.Parts {
				if _, ok := in.(*syntax.Lit); !ok {
					return true
				}
			}
		default:
			return true
		}
	}
	return false
}

// wordFlagLike reports whether the word starts with a literal dash, so an
// expansion inside it (--project=$P) is a flag value, not a command word.
func wordFlagLike(w *syntax.Word) bool {
	if len(w.Parts) == 0 {
		return false
	}
	l, ok := w.Parts[0].(*syntax.Lit)
	return ok && strings.HasPrefix(l.Value, "-")
}

func callRunsBuildsCancel(c shellparse.Call, rawHit bool) bool {
	toks := make([]string, 0, len(c.Args)+1)
	toks = append(toks, norm(c.Program))
	for _, a := range c.Args {
		toks = append(toks, norm(a))
	}
	// pos[i]: word i is an unresolved expansion in a command-word position
	// (not a flag such as --project=$P).
	pos := make([]bool, len(toks))
	for i := range toks {
		if c.Expr != nil && i < len(c.Expr.Args) {
			w := c.Expr.Args[i]
			pos[i] = wordUnresolved(w) && !wordFlagLike(w)
		}
	}

	restClient, restURL := false, false
	for _, t := range toks {
		b := filepath.Base(t)
		if shellInterpreters[b] && rawHit {
			return true // -c payload, heredoc, here-string or piped stdin, at any token position
		}
		if restClients[b] {
			restClient = true
		}
		if buildsCancelREST.MatchString(t) {
			restURL = true
		}
	}
	if restClient && restURL {
		return true
	}

	anyPos := func(from, to int) bool {
		for i := from; i < to && i < len(pos); i++ {
			if i >= 0 && pos[i] {
				return true
			}
		}
		return false
	}
	find := func(from int, word string) int {
		for i := from; i < len(toks); i++ {
			if toks[i] == word {
				return i
			}
		}
		return -1
	}

	g := -1
	for i, t := range toks {
		if filepath.Base(t) == "gcloud" {
			g = i
			break
		}
	}

	if g >= 0 {
		b := find(g+1, "builds")
		if b < 0 {
			// builds from an expansion: gcloud $B cancel
			return anyPos(g+1, len(toks)) && find(g+1, "cancel") >= 0
		}
		if verbIsCancel(toks, pos, b) {
			return true
		}
		// xargs feeds the verb on stdin: `... | xargs gcloud builds` with no
		// literal verb could be cancel.
		if find(0, "xargs") >= 0 || strings.HasSuffix(toks[0], "/xargs") {
			for _, t := range toks[b+1:] {
				if buildsKnownVerbs[t] {
					return false
				}
			}
			return true
		}
		return false
	}
	// No literal gcloud: it may hide behind an expansion ($G, $(which gcloud)).
	b := find(0, "builds")
	return b > 0 && anyPos(0, b) && find(b+1, "cancel") >= 0
}

// verbIsCancel decides, for the words after a literal `builds`, whether the
// verb is cancel or could be (an expansion in the verb position).
func verbIsCancel(toks []string, pos []bool, b int) bool {
	for i := b + 1; i < len(toks); i++ {
		if toks[i] == "cancel" {
			return true
		}
	}
	verbKnown := false
	for i := b + 1; i < len(toks); i++ {
		t := toks[i]
		if pos[i] {
			if !verbKnown {
				return true // unresolved word before any known verb
			}
			continue
		}
		if strings.HasPrefix(t, "-") {
			if !strings.Contains(t, "=") && gcloudValueFlags[t] {
				i++ // skip the flag's separate value
			}
			continue
		}
		if t == "" {
			continue
		}
		if !verbKnown {
			if buildsKnownVerbs[t] {
				verbKnown = true
			} else {
				// Unknown literal (maybe a flag value we could not place):
				// any later expansion could be the verb.
				for j := i + 1; j < len(toks); j++ {
					if pos[j] {
						return true
					}
				}
				return false
			}
		}
	}
	return false
}
