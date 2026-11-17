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

var buildsCancelText = regexp.MustCompile(`(?s)gcloud\b.*\bbuilds\b.*\bcancel\b`)

var buildsCancelREST = regexp.MustCompile(`(?i)cloudbuild\.googleapis\.com/\S*builds/[^/:\s]+(:|%3A)cancel`)

// buildsCancelRESTRaw runs over the de-quoted raw text, so a URL whose
// build id or project part is a variable or substitution (which the word
// resolver drops), a URL held in a variable, an upper-case host or a
// percent-encoded colon is still seen.
var buildsCancelRESTRaw = regexp.MustCompile(`(?i)cloudbuild\.googleapis\.com/[^\n]*builds/[^\n]*(:|%3A)cancel`)

var restClients = map[string]bool{
	"curl": true, "wget": true, "http": true, "https": true, "xh": true, "httpie": true,
}

var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "eval": true,
	// programs that run a quoted command string
	"watch": true, "tmux": true, "parallel": true, "ssh": true, "script": true,
	"flock": true, "screen": true,
	// more programs that run a command string
	"watchexec": true, "osascript": true,
}

// Interpreters that run a string given with -c / -e.
var evalFlagPrograms = map[string]bool{
	"python": true, "python3": true, "node": true, "perl": true, "ruby": true,
	"npx": true, "bunx": true, "npm": true, "pnpm": true,
}

// Wrappers that take a command as their arguments; an unresolved word right
// after them can stand for the wrapped program.
var wrapperPrograms = map[string]bool{
	"env": true, "command": true, "exec": true, "xargs": true, "timeout": true,
	"nohup": true, "time": true, "sudo": true, "nice": true, "stdbuf": true, "setsid": true,
}

var envSplitFlag = regexp.MustCompile(`^-[A-Za-z]*S|^--split-string`)

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
	// The raw-text checks are lazy: an ordinary command (no interpreter, no
	// REST client, no unresolved word) never pays for them.
	var (
		raw                  string
		rawDone, hitDone     bool
		hit, restDone, restH bool
	)
	getRaw := func() string {
		if !rawDone {
			raw = strings.NewReplacer("\\\n", "", "\\", "", "'", "", `"`, "").Replace(p.Raw)
			rawDone = true
		}
		return raw
	}
	t := &rawTexts{
		hit: func() bool {
			if !hitDone {
				s := getRaw()
				hit = strings.Contains(s, "cancel") && strings.Contains(s, "builds") &&
					strings.Contains(s, "gcloud") && buildsCancelText.MatchString(s)
				hitDone = true
			}
			return hit
		},
		rest: func() bool {
			if !restDone {
				restH = buildsCancelRESTRaw.MatchString(getRaw())
				restDone = true
			}
			return restH
		},
		mentions: func() bool {
			s := getRaw()
			return strings.Contains(s, "gcloud") || strings.Contains(s, "builds")
		},
	}
	for _, c := range p.AllCalls() {
		if callRunsBuildsCancel(c, t) {
			return Match, r.Reason
		}
	}
	return NoMatch, ""
}

// rawTexts holds the lazily computed whole-command checks.
type rawTexts struct {
	hit      func() bool // gcloud ... builds ... cancel somewhere in the text
	rest     func() bool // a Cloud Build :cancel URL somewhere in the text
	mentions func() bool // the text mentions gcloud or builds at all
}

func norm(t string) string {
	return strings.TrimPrefix(strings.ReplaceAll(t, `\`, ""), "=")
}

// wordUnresolved reports whether the word's value depends on an expansion.
func wordUnresolved(w *syntax.Word) bool {
	for _, part := range w.Parts {
		switch pt := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(pt.Value, "{?*[") {
				return true // brace expansion or glob
			}
		case *syntax.SglQuoted:
			if pt.Dollar {
				return true // $'...' ANSI-C escapes
			}
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

// runsCommandString reports whether the call hands a command string (or a
// script on stdin) to another program: a shell, watch, tmux, ssh, env -S,
// npx -c, git --exec or an alias, `source <(...)` and the like. The caller
// still needs the phrase in the raw text before it acts on this.
func runsCommandString(c shellparse.Call, toks []string) bool {
	for i, t := range toks {
		b := filepath.Base(t)
		if shellInterpreters[b] {
			return true
		}
		rest := toks[i+1:]
		switch {
		case b == "env":
			for _, a := range rest {
				if envSplitFlag.MatchString(a) {
					return true
				}
			}
		case evalFlagPrograms[b]:
			for _, a := range rest {
				if a == "-c" || a == "-e" || strings.HasPrefix(a, "--call") {
					return true
				}
			}
		case b == "git":
			for _, a := range rest {
				if a == "--exec" || strings.HasPrefix(a, "--exec=") || strings.HasPrefix(a, "-x") ||
					strings.HasPrefix(a, "alias.") || strings.HasPrefix(a, "-calias.") ||
					strings.HasPrefix(a, "core.") || a == "foreach" || strings.HasSuffix(a, "-filter") {
					return true
				}
			}
		case b == "awk" || b == "gawk" || b == "mawk":
			for _, a := range rest {
				if strings.Contains(a, "system") {
					return true
				}
			}
		case b == "make" && i == 0:
			for _, a := range rest {
				if a == "-" || a == "/dev/stdin" {
					return true
				}
			}
		case (b == "source" || b == ".") && i == 0:
			for j, a := range rest {
				if strings.HasPrefix(a, "/dev/") || strings.HasPrefix(a, "/proc/") {
					return true
				}
				if c.Expr != nil && j+1 < len(c.Expr.Args) {
					for _, part := range c.Expr.Args[j+1].Parts {
						if _, ok := part.(*syntax.ProcSubst); ok {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func callRunsBuildsCancel(c shellparse.Call, t *rawTexts) bool {
	toks := make([]string, 0, len(c.Args)+1)
	toks = append(toks, norm(c.Program))
	for _, a := range c.Args {
		toks = append(toks, norm(a))
	}
	// pos[i]: word i is an unresolved expansion in a command-word position
	// (not a flag such as --project=$P).
	pos := make([]bool, len(toks))
	anyUnresolved := false
	for i := range toks {
		if c.Expr != nil && i < len(c.Expr.Args) {
			w := c.Expr.Args[i]
			pos[i] = wordUnresolved(w) && !wordFlagLike(w)
			anyUnresolved = anyUnresolved || pos[i]
		}
	}

	restClient := false
	for _, tk := range toks {
		if restClients[filepath.Base(tk)] {
			restClient = true
			break
		}
	}
	if restClient {
		for _, tk := range toks {
			if buildsCancelREST.MatchString(tk) {
				return true
			}
		}
		if t.rest() {
			return true // the URL holds a variable or sits in a variable
		}
	}
	if runsCommandString(c, toks) && t.hit() {
		return true // -c payload, heredoc, here-string or piped stdin, at any token position
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
	for i, tk := range toks {
		if filepath.Base(tk) == "gcloud" {
			g = i
			break
		}
	}

	gLit := g >= 0
	if !gLit && anyUnresolved {
		for i := range pos {
			if pos[i] {
				g = i // unresolved word ($G, $(which gcloud)) may be gcloud
				break
			}
		}
	}
	if g < 0 {
		return false
	}
	// first command word after gcloud (skipping flags and their values)
	first := -1
	for i := g + 1; i < len(toks); i++ {
		if strings.HasPrefix(toks[i], "-") && (c.Expr == nil || i >= len(c.Expr.Args) || wordFlagLike(c.Expr.Args[i])) {
			if !strings.Contains(toks[i], "=") && gcloudValueFlags[toks[i]] {
				i++
			}
			continue
		}
		if toks[i] == "alpha" || toks[i] == "beta" {
			continue
		}
		first = i
		break
	}
	if first >= 0 && pos[first] {
		if gLit {
			return true // gcloud $X ...: group and verb unknown
		}
		// `$G $X`: both words unknown. Only when the program (or the word
		// after a wrapper) is the unresolved one, and the text mentions
		// gcloud, so ordinary `$EDITOR $FILE` calls do not prompt.
		if (g == 0 || wrapperPrograms[filepath.Base(toks[0])]) && t.mentions() {
			return true
		}
	}
	b := find(g+1, "builds")
	if b < 0 {
		return false
	}
	if verbIsCancel(toks, pos, b) {
		return true
	}
	// xargs feeds the verb on stdin: `... | xargs gcloud builds` with no
	// literal verb could be cancel.
	hasXargs := false
	for _, tk := range toks {
		if filepath.Base(tk) == "xargs" {
			hasXargs = true
		}
	}
	if hasXargs {
		for _, tk := range toks[b+1:] {
			if buildsKnownVerbs[tk] {
				return false
			}
		}
		return true
	}
	return false
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
