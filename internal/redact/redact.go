// Package redact is the privacy gate between the engine and the LLM
// classifier. It scans command text for secret patterns and decides
// whether the command is safe to send to an external API.
//
// Two modes:
//
//   - SKIP patterns:    if matched, the command is NOT sent to the LLM
//     at all. Used for highly sensitive shapes — Bearer tokens, API
//     keys, connection strings with credentials. The command falls
//     through to legacy/default tiers without ever leaving the user's
//     machine.
//
//   - REPLACE patterns: if matched, the matched substring is replaced
//     with a stable placeholder (e.g. "<REDACTED-EMAIL>") and the
//     redacted form is sent to the LLM. Used for less-sensitive shapes
//     where the LLM still benefits from seeing the surrounding
//     structure.
//
// Defaults are compiled in (DefaultSkipPatterns, DefaultReplacePatterns)
// so a missing or broken user config cannot disable the privacy gate.
// Users can EXTEND the defaults via config; they cannot remove them.
package redact

import (
	"fmt"
	"regexp"
	"strings"
)

// Decision is the outcome of scanning a command.
type Decision int

const (
	// Send means the command (possibly after redaction) may be sent to the LLM.
	Send Decision = iota
	// Skip means the command must NOT be sent to the LLM. The engine
	// falls through to the next tier.
	Skip
)

// Result carries the decision and (when Send) the redacted text plus a
// summary of what was replaced.
type Result struct {
	Decision Decision
	// Redacted is the command text with REPLACE patterns substituted.
	// Equal to the input when no replacement was needed.
	Redacted string
	// SkipReason names the matching SKIP pattern (for app-log telemetry).
	SkipReason string
	// ReplacedKinds lists the placeholder kinds that fired (e.g. "EMAIL",
	// "TOKEN"). Used for stats and explain output, never for cache keys.
	ReplacedKinds []string
}

// Pattern is one rule in either the skip or replace set.
type Pattern struct {
	// Name identifies the pattern in logs. Stable across versions.
	Name string
	// Regex is the compiled pattern.
	Regex *regexp.Regexp
	// Placeholder is the substitution string for REPLACE patterns
	// (ignored for SKIP). Convention: "<REDACTED-KIND>" e.g. "<REDACTED-EMAIL>".
	Placeholder string
}

// Redactor evaluates skip and replace patterns against a command string.
// Safe for concurrent use after construction.
type Redactor struct {
	skip    []Pattern
	replace []Pattern
}

// New constructs a Redactor from skip and replace pattern lists. The
// defaults from DefaultSkipPatterns/DefaultReplacePatterns are always
// merged in front of the user-provided patterns so they cannot be
// disabled.
func New(extraSkip, extraReplace []Pattern) *Redactor {
	skip := make([]Pattern, 0, len(DefaultSkipPatterns())+len(extraSkip))
	skip = append(skip, DefaultSkipPatterns()...)
	skip = append(skip, extraSkip...)

	replace := make([]Pattern, 0, len(DefaultReplacePatterns())+len(extraReplace))
	replace = append(replace, DefaultReplacePatterns()...)
	replace = append(replace, extraReplace...)

	return &Redactor{skip: skip, replace: replace}
}

// Scan evaluates the command against all patterns. SKIP patterns are
// checked first — a single match means the command never reaches the
// LLM. Otherwise REPLACE patterns substitute matched substrings and
// the result is returned.
//
// Special case: if a SKIP pattern's match is entirely references to
// shell variables ($VAR, ${VAR}), the literal command text contains
// no secret — only a variable name — and sending it to the LLM is
// harmless. We accept the match but demote to Send. This avoids
// false-positives on patterns like
//
//	Authorization: Bearer $CF_TOKEN
//
// where $CF_TOKEN is resolved by the shell at exec time and never
// appears in the literal command string.
func (r *Redactor) Scan(command string) Result {
	for _, p := range r.skip {
		loc := p.Regex.FindStringIndex(command)
		if loc == nil {
			continue
		}
		matched := command[loc[0]:loc[1]]
		if isShellVarReference(matched) {
			continue // safe — the actual secret isn't in the literal text
		}
		return Result{
			Decision:   Skip,
			SkipReason: p.Name,
		}
	}

	out := command
	var kinds []string
	for _, p := range r.replace {
		replaced := false
		out = p.Regex.ReplaceAllStringFunc(out, func(match string) string {
			// Shell-var references (api_key=$VAR) contain no secret in
			// the literal text — preserve the literal so the LLM sees
			// the shell-var shape, not an opaque placeholder.
			if isShellVarReference(match) {
				return match
			}
			replaced = true
			// If the pattern has a capture group, prepend it to the
			// placeholder so the key name is preserved for the LLM
			// (api_key=realvalue → api_key=<REDACTED-API-KEY>).
			if subs := p.Regex.FindStringSubmatch(match); len(subs) >= 2 {
				return subs[1] + p.Placeholder
			}
			return p.Placeholder
		})
		if replaced {
			kinds = append(kinds, p.Name)
		}
	}
	return Result{
		Decision:      Send,
		Redacted:      out,
		ReplacedKinds: kinds,
	}
}

// shellVarRE matches $VAR or ${VAR} references only. We demote skip-
// pattern matches that consist entirely of shell-variable references
// to Send, because the actual secret isn't in the literal command.
var shellVarRE = regexp.MustCompile(`^\$(\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)$`)

// isShellVarReference returns true when the "secret-looking" portion
// of a skip-pattern match is just a shell variable reference — i.e.
// the literal command text contains no actual credential, only a
// name the shell will expand at execution time.
//
// Heuristic: find the substring AFTER the last `=` or `:` in the
// matched text (that's the "value" portion — everything before is
// the key like "Authorization" or "api_key"). If that trimmed value
// is a single $VAR / ${VAR}, we consider the match safe to send.
//
// We deliberately do NOT try to inspect command substitution
// ($(...)), arithmetic expressions, or anything else — only bare
// variable references. Anything more complex stays conservative.
func isShellVarReference(matched string) bool {
	value := matched
	// 1. Isolate the value portion: after "=" or ":" (whichever is last).
	for _, sep := range []string{"=", ":"} {
		if idx := strings.LastIndex(value, sep); idx >= 0 {
			value = value[idx+1:]
		}
	}
	value = strings.TrimSpace(value)
	// 2. Strip any auth-scheme keyword ("Bearer ", "Basic ", etc.) that
	//    may precede the actual value. Case-insensitive.
	lower := strings.ToLower(value)
	for _, scheme := range []string{"bearer ", "basic ", "digest ", "token "} {
		if strings.HasPrefix(lower, scheme) {
			value = value[len(scheme):]
			break
		}
	}
	// 3. Strip all whitespace and any quote characters from both ends.
	//    Done AFTER scheme strip because scheme keywords might be inside quotes.
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	value = strings.TrimSpace(value)
	// 4. Scheme might have been inside quotes — try stripping again.
	lower = strings.ToLower(value)
	for _, scheme := range []string{"bearer ", "basic ", "digest ", "token "} {
		if strings.HasPrefix(lower, scheme) {
			value = value[len(scheme):]
			break
		}
	}
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	value = strings.TrimSpace(value)
	return shellVarRE.MatchString(value)
}

// MustCompilePatterns is a helper for static pattern lists. Panics on
// regex syntax errors — those are programming errors, not config errors.
func MustCompilePatterns(specs []PatternSpec) []Pattern {
	out := make([]Pattern, 0, len(specs))
	for _, s := range specs {
		re, err := regexp.Compile(s.Regex)
		if err != nil {
			panic(fmt.Sprintf("redact: bad pattern %q: %v", s.Name, err))
		}
		out = append(out, Pattern{
			Name:        s.Name,
			Regex:       re,
			Placeholder: s.Placeholder,
		})
	}
	return out
}

// PatternSpec is the YAML/Go-literal source form of a pattern.
type PatternSpec struct {
	Name        string
	Regex       string
	Placeholder string
}

// DefaultSkipPatterns: highly sensitive shapes that must never leave
// the user's machine. These run before any LLM call. Order is not
// significant (any match wins).
func DefaultSkipPatterns() []Pattern {
	return MustCompilePatterns([]PatternSpec{
		// HTTP Basic auth: base64-encoded creds are directly sensitive
		// (username:password in the value), so SKIP. http-bearer moved
		// to REPLACE — see DefaultReplacePatterns. Bearer values that
		// are themselves high-entropy secrets (anthropic-key, github-pat,
		// aws-access-key, …) are still caught by their specific SKIP
		// patterns below.
		{Name: "http-basic-auth", Regex: `(?i)basic\s+[a-zA-Z0-9+/=]{20,}`},

		// Anthropic API keys
		{Name: "anthropic-key", Regex: `sk-ant-[A-Za-z0-9_\-]{20,}`},

		// OpenAI API keys
		{Name: "openai-key", Regex: `sk-(?:proj-)?[A-Za-z0-9_\-]{32,}`},

		// GitHub tokens
		{Name: "github-pat", Regex: `gh[pousr]_[A-Za-z0-9]{20,}`},
		{Name: "github-fine-grained", Regex: `github_pat_[A-Za-z0-9_]{20,}`},

		// AWS access keys
		{Name: "aws-access-key", Regex: `AKIA[0-9A-Z]{16}`},
		{Name: "aws-secret-key", Regex: `(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*\S+`},

		// Google API keys
		{Name: "google-api-key", Regex: `AIza[0-9A-Za-z\-_]{35}`},

		// Database connection strings with credentials
		{Name: "postgres-uri-creds", Regex: `postgres(?:ql)?://[^:/\s]+:[^@\s]+@`},
		{Name: "mysql-uri-creds", Regex: `mysql://[^:/\s]+:[^@\s]+@`},
		{Name: "mongo-uri-creds", Regex: `mongodb(?:\+srv)?://[^:/\s]+:[^@\s]+@`},

		// Private keys (PEM in command text — unlikely but devastating)
		{Name: "pem-private-key", Regex: `-----BEGIN [A-Z ]*PRIVATE KEY-----`},
	})
}

// DefaultReplacePatterns: less-sensitive shapes that we can show to the
// LLM after substitution. These help the model see the COMMAND STRUCTURE
// without exposing PII.
func DefaultReplacePatterns() []Pattern {
	return MustCompilePatterns([]PatternSpec{
		// Email addresses → <REDACTED-EMAIL>
		{
			Name:        "email",
			Regex:       `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			Placeholder: "<REDACTED-EMAIL>",
		},
		// IPv4 addresses → <REDACTED-IPV4>  (but only public-looking; localhost stays)
		{
			Name:        "ipv4",
			Regex:       `\b(?:[1-9][0-9]{0,2}\.){3}[1-9][0-9]{0,2}\b`,
			Placeholder: "<REDACTED-IPV4>",
		},
		// UUIDs → <REDACTED-UUID>
		{
			Name:        "uuid",
			Regex:       `[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}`,
			Placeholder: "<REDACTED-UUID>",
		},
		// HTTP Authorization / Bearer headers. REPLACE rather than SKIP
		// so commands like curl -H "Authorization: Bearer <opaque-token>"
		// can reach the LLM with the header shape preserved but the
		// token substituted. High-entropy secret patterns (anthropic-key,
		// github-pat, aws-access-key, google-api-key, openai-key) remain
		// in SKIP and run first — a Bearer value that IS one of those
		// keys still never reaches this REPLACE stage.
		//
		// Two capture groups:
		//   $1 = prefix (optional opening quote + "authorization"/"bearer"
		//        + optional closing quote + separator + optional opening
		//        quote + optional "Bearer " scheme word)
		//   $2 = token value (non-whitespace, non-quote chars — quotes
		//        around the value sit OUTSIDE the match and are preserved)
		//
		// Shell-var references ($TOKEN / ${TOKEN}) are preserved literally
		// by the REPLACE loop's isShellVarReference guard, so
		//   Authorization: Bearer $CF_TOKEN
		// keeps the literal $CF_TOKEN (no secret in literal text; the
		// shell expands it at exec time).
		//
		// Placed BEFORE jwt so the `Authorization: Bearer <jwt>` shape
		// emits a single <REDACTED-BEARER> rather than a nested
		// `Authorization: Bearer <REDACTED-JWT>` placeholder. The final
		// output is equivalent — no eyJ fragment or signature leaks —
		// but the LLM sees the outer credential shape directly.
		{
			Name:        "http-bearer",
			Regex:       `(?i)\b(["']?(?:authorization|bearer)["']?\s*[:=]\s*["']?(?:bearer\s+)?)([^"'\s]+)`,
			Placeholder: "<REDACTED-BEARER>",
		},
		// JWT tokens (header.payload.sig where header looks JWT-y).
		// REPLACE rather than SKIP so commands like TOKEN="<jwt>" or
		// curl /api/verify/<jwt> can reach the LLM with the credential
		// shape preserved but the value substituted. The full triple is
		// matched and replaced, so neither the signature nor the
		// base64-encoded payload claims (user IDs, roles, emails) reach
		// the LLM. Bearer-scheme JWTs are caught by the http-bearer
		// REPLACE above first — this entry catches bare JWTs in URL
		// paths, TOKEN="…" env shapes, and other non-bearer contexts.
		//
		// Ordering: placed BEFORE the generic credential-shape block so
		// that when a JWT appears inside token="…"/password="…" the jwt
		// pattern fires first and the specific <REDACTED-JWT> placeholder
		// is emitted. If a later generic pattern also matches, the value
		// is already a placeholder — no secret leak, just placeholder
		// overwrite (pattern-order artifact; asserted in tests).
		{
			Name:        "jwt",
			Regex:       `eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`,
			Placeholder: "<REDACTED-JWT>",
		},
		// Generic credential-shape assignments: api_key=…, password=…,
		// token=…, secret=…. REPLACE rather than SKIP so the LLM can
		// still see the command structure and approve safe shapes
		// (e.g. curl to localhost with an X-API-Key header). The VALUE
		// never leaves the machine — only the placeholder does.
		//
		// Two capture groups per pattern:
		//   $1 = prefix (optional opening quote + key + optional
		//        closing quote + separator + optional opening quote)
		//   $2 = value (one or more chars that are not whitespace or
		//        quote — quotes around the value sit OUTSIDE the
		//        match so they are preserved in the output)
		//
		// Scan()'s REPLACE loop substitutes the match with $1 plus
		// the placeholder, so "api_key=realvalue" → "api_key=<REDACTED-API-KEY>",
		// api_key="realvalue" → api_key="<REDACTED-API-KEY>" (closing
		// quote preserved because it's outside the match), and
		// "api_key":"realvalue" (JSON) → "api_key":"<REDACTED-API-KEY>".
		//
		// Specific high-entropy patterns (anthropic-key, github-pat,
		// aws-access-key, jwt, …) remain in SKIP and run first, so
		// real tokens embedded in a generic shape still never reach
		// the LLM.
		{
			Name:        "generic-api-key",
			Regex:       `(?i)\b(["']?api[_-]?key["']?\s*[:=]\s*["']?)([^"'\s]+)`,
			Placeholder: "<REDACTED-API-KEY>",
		},
		{
			Name:        "generic-password",
			Regex:       `(?i)\b(["']?password["']?\s*[:=]\s*["']?)([^"'\s]+)`,
			Placeholder: "<REDACTED-PASSWORD>",
		},
		{
			Name:        "generic-token",
			Regex:       `(?i)\b(["']?token["']?\s*[:=]\s*["']?)([^"'\s]+)`,
			Placeholder: "<REDACTED-TOKEN>",
		},
		{
			Name:        "generic-secret",
			Regex:       `(?i)\b(["']?secret["']?\s*[:=]\s*["']?)([^"'\s]+)`,
			Placeholder: "<REDACTED-SECRET>",
		},
	})
}
