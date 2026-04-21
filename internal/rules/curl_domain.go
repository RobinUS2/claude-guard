package rules

import (
	"net/url"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

// CurlToDomain allows curl commands targeting trusted API domains.
//
// Mutations (PUT/POST/PATCH) are normal operational work and are allowed.
// DELETE falls through to the user prompt (destructive).
// Forbidden flags (-o, --upload-file, --resolve, etc.) cause NoMatch.
// Data arguments with @file references cause NoMatch (exfiltration risk).
//
// This rule tolerates compound commands (TOKEN=$(cmd) && curl ... | jq)
// which AnchoredCommand refuses due to shell features. Safety:
//   - URL must be a resolved literal (no $URL variables)
//   - Pipe targets must be in SafePipeTargets
//   - Rejects HasSubshell, HasProcSub, HasBackground
//   - Rejects file redirects (allows fd-only like 2>&1)
//   - Tier 1 still catches curl|sh regardless
type CurlToDomain struct {
	RuleName        string
	TrustedDomains  []string // e.g., ["studio.taufinity.io"]
	SafePipeTargets []string // read-only programs allowed in pipe tails
}

func (r *CurlToDomain) Name() string { return r.RuleName }
func (r *CurlToDomain) Kind() string { return "curl_to_domain" }

// curlForbiddenFlags are flags that change curl from a network call into
// a local file operation (write or exfil) or hijack the connection target.
var curlForbiddenFlags = []string{
	"-o", "--output",           // write response to local file
	"--upload-file", "-T",     // upload local file
	"--resolve", "--connect-to", // hijack connection to different host
}

// curlDestructivePaths are URL path segments that indicate destructive
// operations, regardless of HTTP method. Best-effort extra check.
var curlDestructivePaths = []string{
	"/destroy", "/purge", "/truncate", "/drop", "/wipe",
}

// curlDataFlags are flags whose value may start with @ to reference a local file.
var curlDataFlags = []string{
	"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode",
}

func (r *CurlToDomain) Eval(p *shellparse.Parsed) (Verdict, string) {
	f := p.Features

	// Reject shell features that can hide side effects.
	if f.HasSubshell || f.HasProcSub || f.HasBackground {
		return NoMatch, ""
	}
	// Allow fd-only redirects (2>&1) but reject file redirects (> /etc/hosts).
	if f.HasRedirect && !f.HasFdOnlyRedirects {
		return NoMatch, ""
	}

	if len(p.Pipelines) == 0 {
		return NoMatch, ""
	}

	// Find the pipeline containing a curl call and validate it.
	foundCurl := false
	for _, pipeline := range p.Pipelines {
		if len(pipeline) == 0 {
			return NoMatch, ""
		}

		headCall := pipeline[0]

		// Is this the curl pipeline?
		if headCall.Program == "curl" || baseProgram(headCall.Program) == "curl" {
			if foundCurl {
				// Multiple curl calls in one command — too complex, bail.
				return NoMatch, ""
			}
			foundCurl = true

			if ok, reason := r.validateCurlCall(&headCall); !ok {
				return NoMatch, reason
			}

			// Validate pipe targets (jq, head, tail, etc.)
			for _, tailCall := range pipeline[1:] {
				if tailCall.HasUnresolved {
					return NoMatch, ""
				}
				if !stringIn(baseProgram(tailCall.Program), r.SafePipeTargets) {
					return NoMatch, ""
				}
			}
			continue
		}

		// Non-curl pipeline: must be a safe read-only shape or an
		// assignment (empty program). Variable assignments like
		// TOKEN=$(cmd) parse as a Call with empty Program in mvdan/sh.
		if headCall.Program == "" {
			// Assignment or empty statement — safe.
			continue
		}

		// Non-curl, non-assignment pipeline heads: for safety, we only
		// allow known harmless programs (echo for || echo "done" patterns).
		if !stringIn(baseProgram(headCall.Program), safeCompanionPrograms) {
			return NoMatch, ""
		}
	}

	if !foundCurl {
		return NoMatch, ""
	}
	return Match, r.RuleName
}

// safeCompanionPrograms are programs that can appear alongside curl in a
// compound command (e.g., `curl ... || echo "done"`, `true && curl ...`).
var safeCompanionPrograms = []string{
	"echo", "printf", "true", "false", "test", "[",
}

// validateCurlCall checks a single curl Call for trusted domain, safe method,
// no forbidden flags, and no @file data references.
func (r *CurlToDomain) validateCurlCall(c *shellparse.Call) (bool, string) {
	// Extract URL from args — find the first resolved arg that looks like a URL.
	host, path, urlOK := curlExtractURL(c.Args)
	if !urlOK {
		return false, "no resolvable URL found"
	}

	// Check domain.
	if !r.isTrustedHost(host) {
		return false, "host not in trusted domains"
	}

	// Check HTTP method.
	method := curlExtractMethod(c.Args)
	if strings.EqualFold(method, "DELETE") {
		return false, "DELETE method requires human confirmation"
	}

	// Check forbidden flags.
	for _, flag := range curlForbiddenFlags {
		if curlHasFlag(c.Args, flag) {
			return false, "forbidden flag: " + flag
		}
	}

	// Check for @file data references (exfiltration risk).
	if curlHasFileData(c.Args) {
		return false, "data argument references local file (@path)"
	}

	// Check destructive path keywords (best-effort).
	lowerPath := strings.ToLower(path)
	for _, keyword := range curlDestructivePaths {
		if strings.Contains(lowerPath, keyword) {
			return false, "destructive path keyword: " + keyword
		}
	}

	return true, ""
}

// isTrustedHost checks if the host matches any trusted domain.
// Matches exact domain or subdomains (e.g., "studio.taufinity.io"
// matches trusted domain "taufinity.io").
func (r *CurlToDomain) isTrustedHost(host string) bool {
	host = strings.ToLower(host)
	// Strip port if present.
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	for _, trusted := range r.TrustedDomains {
		trusted = strings.ToLower(trusted)
		if host == trusted {
			return true
		}
		// Allow subdomains: "api.studio.taufinity.io" matches "taufinity.io"
		if strings.HasSuffix(host, "."+trusted) {
			return true
		}
	}
	return false
}

// curlExtractMethod finds the HTTP method from -X or --request flag.
// Returns "GET" if no method specified (curl default).
func curlExtractMethod(args []string) string {
	for i, arg := range args {
		if (arg == "-X" || arg == "--request") && i+1 < len(args) {
			return strings.ToUpper(args[i+1])
		}
		// Handle --request=METHOD and -XMETHOD forms.
		if method, ok := strings.CutPrefix(arg, "--request="); ok {
			return strings.ToUpper(method)
		}
		if strings.HasPrefix(arg, "-X") && len(arg) > 2 {
			return strings.ToUpper(arg[2:])
		}
	}
	return "GET"
}

// curlExtractURL finds the first URL-like positional argument and returns
// its host and path. Returns ok=false if no resolvable URL is found.
//
// A URL-like arg must start with http:// or https://. We use net/url.Parse
// for robust host extraction (handles ports, userinfo, etc.).
//
// Only considers args that are NOT preceded by a value-taking flag
// (to avoid matching flag values like header values as URLs).
func curlExtractURL(args []string) (host, path string, ok bool) {
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		// Flags that take a value — skip the next arg.
		if curlIsValueFlag(arg) {
			skipNext = true
			continue
		}
		// Skip flags themselves.
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// Check if this looks like a URL.
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			u, err := url.Parse(arg)
			if err != nil {
				continue
			}
			return u.Host, u.Path, true
		}
	}
	return "", "", false
}

// curlIsValueFlag returns true if this flag takes a value as the next argument.
// This prevents us from accidentally treating a header value or data as a URL.
var curlValueFlags = map[string]bool{
	"-X": true, "--request": true,
	"-H": true, "--header": true,
	"-d": true, "--data": true, "--data-binary": true, "--data-raw": true, "--data-urlencode": true,
	"-o": true, "--output": true,
	"-u": true, "--user": true,
	"-A": true, "--user-agent": true,
	"-e": true, "--referer": true,
	"-b": true, "--cookie": true,
	"-c": true, "--cookie-jar": true,
	"-T": true, "--upload-file": true,
	"-w": true, "--write-out": true,
	"-m": true, "--max-time": true,
	"--connect-timeout": true,
	"--retry": true,
	"--resolve": true,
	"--connect-to": true,
	"--cacert": true, "--cert": true, "--key": true,
}

func curlIsValueFlag(arg string) bool {
	if curlValueFlags[arg] {
		return true
	}
	// Handle --flag=value form — these don't consume the next arg.
	if strings.HasPrefix(arg, "--") && strings.Contains(arg, "=") {
		return false
	}
	return false
}

// curlHasFlag checks if a specific flag is present in the args list.
// Handles combined short flags (e.g., "-so" contains "-o") and --flag=value.
// Uses the same matching logic as anchoredFlagForbidden for consistency.
func curlHasFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag {
			return true
		}
		// Long flag: --flag=value or --flag-variant
		if strings.HasPrefix(flag, "--") {
			if strings.HasPrefix(arg, flag+"=") {
				return true
			}
			continue
		}
		// Short flag (e.g., "-o"): check combined short flags like "-so".
		if strings.HasPrefix(flag, "-") && len(flag) == 2 {
			want := rune(flag[1])
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 2 {
				for _, ch := range arg[1:] {
					if ch == want {
						return true
					}
				}
			}
		}
	}
	return false
}

// curlHasFileData checks if any data flag has an @-prefixed value
// (which reads from a local file).
func curlHasFileData(args []string) bool {
	for i, arg := range args {
		for _, dataFlag := range curlDataFlags {
			if arg == dataFlag && i+1 < len(args) {
				if strings.HasPrefix(args[i+1], "@") {
					return true
				}
			}
			// Handle --data=@file form.
			if strings.HasPrefix(arg, dataFlag+"=@") {
				return true
			}
		}
	}
	return false
}
