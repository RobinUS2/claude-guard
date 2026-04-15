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
func (r *Redactor) Scan(command string) Result {
	for _, p := range r.skip {
		if p.Regex.MatchString(command) {
			return Result{
				Decision:   Skip,
				SkipReason: p.Name,
			}
		}
	}

	out := command
	var kinds []string
	for _, p := range r.replace {
		if p.Regex.MatchString(out) {
			out = p.Regex.ReplaceAllString(out, p.Placeholder)
			kinds = append(kinds, p.Name)
		}
	}
	return Result{
		Decision:      Send,
		Redacted:      out,
		ReplacedKinds: kinds,
	}
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
		// HTTP Authorization headers
		{Name: "http-bearer", Regex: `(?i)(?:authorization|bearer)\s*[:=]\s*\S+`},
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

		// Generic api_key=, password=, token=, secret=
		{Name: "generic-api-key", Regex: `(?i)\bapi[_-]?key\s*[:=]\s*[^\s'"]+`},
		{Name: "generic-password", Regex: `(?i)\bpassword\s*[:=]\s*[^\s'"]+`},
		{Name: "generic-token", Regex: `(?i)\btoken\s*[:=]\s*[^\s'"]+`},
		{Name: "generic-secret", Regex: `(?i)\bsecret\s*[:=]\s*[^\s'"]+`},

		// Database connection strings with credentials
		{Name: "postgres-uri-creds", Regex: `postgres(?:ql)?://[^:/\s]+:[^@\s]+@`},
		{Name: "mysql-uri-creds", Regex: `mysql://[^:/\s]+:[^@\s]+@`},
		{Name: "mongo-uri-creds", Regex: `mongodb(?:\+srv)?://[^:/\s]+:[^@\s]+@`},

		// Private keys (PEM in command text — unlikely but devastating)
		{Name: "pem-private-key", Regex: `-----BEGIN [A-Z ]*PRIVATE KEY-----`},

		// JWT tokens (header.payload.sig where header looks JWT-y)
		{Name: "jwt", Regex: `eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`},
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
	})
}
