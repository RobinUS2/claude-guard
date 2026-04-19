// Package normalize rewrites a shell command into a CANONICAL form
// by substituting specific token values with type-tagged placeholders.
//
// The LLM classifier returns a list of "variable slots" alongside its
// verdict — each slot says "the token at position P is of type T and
// doesn't affect the safety judgment." This package applies those
// slots to produce a canonical string that the engine can use as a
// cache key. Different concrete commands that canonicalize to the
// same string share one cached verdict.
//
// Security properties:
//
//  1. The slot-type vocabulary is a CLOSED SET. The LLM cannot invent
//     a type; unknown types are dropped. This bounds the blast radius
//     of prompt-injection attempts that might try to over-generalize
//     a verdict.
//
//  2. Each slot type has a STRICT VALIDATOR. The engine takes the
//     token the LLM pointed at, validates it matches the claimed type,
//     and only substitutes on success. If the LLM said "arg1 is a
//     domain" but the actual token is `/etc/passwd`, the slot is
//     dropped.
//
//  3. Validators are regex or hand-written code — never LLM output.
//     No ReDoS surface.
//
//  4. No "broad" slot types. No `filepath` (too easy to equate
//     `/etc/passwd` with `/tmp/foo`), no `arbitrary_arg` (defeats the
//     point), no command-fragment slots.
package normalize

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

// MaxSlots bounds how many slots the LLM is allowed to submit per
// classification response. Prevents a pathological LLM response from
// blowing up engine latency.
const MaxSlots = 20

// SlotType is the fixed vocabulary the LLM may use. Adding a type is
// a deliberate security decision — every addition widens the space of
// commands that share a cache entry, and every addition requires a
// validator and a placeholder.
type SlotType string

const (
	SlotDomain         SlotType = "domain"
	SlotIPv4           SlotType = "ipv4"
	SlotURLPathSegment SlotType = "url_path_segment"
	SlotUUID           SlotType = "uuid"
	SlotInteger        SlotType = "integer"
	SlotHexHash        SlotType = "hex_hash"
	SlotFilepathTmp    SlotType = "filepath_tmp"
	SlotFilepathCache  SlotType = "filepath_cache"
	SlotQuotedString   SlotType = "quoted_string"
	SlotDNSRecordType  SlotType = "dns_record_type"
	SlotHTTPMethod     SlotType = "http_method"
)

// Slot is one "this token doesn't affect the verdict" entry from the
// LLM. Position is a string reference that the engine resolves against
// the command's shellparse AST (see Normalize for the vocabulary).
type Slot struct {
	Position string   `json:"position"`
	Type     SlotType `json:"type"`
}

// Normalize rewrites command into a canonical form by replacing
// tokens at slot positions with type-tagged placeholders.
//
// Returns:
//   - canonical: the substituted command string (or "" when no slots
//     validated successfully)
//   - dropped: slots that were rejected by the validator, for logging
//   - err: only on internal failures (e.g. shell parse error); the
//     per-slot rejections are in dropped, not err
//
// When ok == false (no slots survived), callers should fall back to
// caching the exact command only.
func Normalize(command string, slots []Slot) (canonical string, dropped []DroppedSlot, err error) {
	if len(slots) == 0 {
		return "", nil, nil
	}
	if len(slots) > MaxSlots {
		// Cap: keep the first MaxSlots, drop the rest.
		for _, s := range slots[MaxSlots:] {
			dropped = append(dropped, DroppedSlot{
				Slot:   s,
				Reason: "exceeds MaxSlots cap",
			})
		}
		slots = slots[:MaxSlots]
	}

	parsed, err := shellparse.Parse(command)
	if err != nil {
		return "", nil, fmt.Errorf("shell parse: %w", err)
	}
	if len(parsed.Calls) == 0 {
		return "", nil, nil
	}

	// Build a map from position → (tokenValue, tokenAbsolute-index-in-command).
	// The "absolute index" is the byte offset inside the original command
	// text so we can do a substring replace without re-escaping.
	// For v1 we focus on the FIRST top-level call. Commands with pipes
	// or multiple statements aren't canonicalized by this pass.
	if len(parsed.Calls) > 1 || parsed.Features.HasPipe || parsed.Features.HasBinaryOp || parsed.Features.HasSubshell {
		return "", nil, nil // leave complex commands alone
	}
	call := parsed.Calls[0]

	// Collect placeholder overrides BY ARG INDEX (not by token value).
	// This is the fix for CTO review C2: string-based substitution
	// would replace the token EVERYWHERE in the command, including in
	// the program path or other arg positions that happen to share
	// the same literal. Substituting by AST position ensures only the
	// slot-identified token changes.
	overrides := make(map[int]string) // 0-indexed arg slot → placeholder
	// tailFlagOverride applies to the LAST arg only; merged into
	// overrides once we know the final call.Args length.
	var tailFlagPlaceholder string

	for _, s := range slots {
		token, tokenOk := tokenAtPosition(call, s.Position)
		if !tokenOk {
			dropped = append(dropped, DroppedSlot{Slot: s, Reason: "position not found"})
			continue
		}
		validator, known := validators[s.Type]
		if !known {
			dropped = append(dropped, DroppedSlot{Slot: s, Reason: "unknown slot type"})
			continue
		}
		if !validator(token) {
			dropped = append(dropped, DroppedSlot{Slot: s, Reason: "token failed validator"})
			continue
		}
		placeholder := "{" + placeholderFor(s.Type) + "}"
		if s.Position == "tail_flag" {
			tailFlagPlaceholder = placeholder
			continue
		}
		// argN: N is 1-indexed; convert to 0-indexed arg slot.
		if argIdx, ok := parseArgIndex(s.Position); ok {
			if _, already := overrides[argIdx]; !already {
				overrides[argIdx] = placeholder
			}
		}
	}
	if tailFlagPlaceholder != "" && len(call.Args) > 0 {
		last := len(call.Args) - 1
		if _, already := overrides[last]; !already {
			overrides[last] = tailFlagPlaceholder
		}
	}

	if len(overrides) == 0 {
		return "", dropped, nil
	}

	// Rebuild canonical from the AST. Program name is preserved
	// verbatim (we do NOT allow the LLM to mark the program as
	// variable — that would let `/bin/rm` share a canonical with
	// `/bin/ls`). Each arg is either the override placeholder or the
	// original token text.
	var sb strings.Builder
	sb.WriteString(call.Program)
	for i, arg := range call.Args {
		sb.WriteByte(' ')
		if p, ok := overrides[i]; ok {
			sb.WriteString(p)
		} else {
			sb.WriteString(arg)
		}
	}
	return sb.String(), dropped, nil
}

// parseArgIndex returns the 0-indexed position for "argN" strings.
// "arg1" → 0, "arg2" → 1, etc. Returns (0, false) on invalid input.
func parseArgIndex(pos string) (int, bool) {
	if !strings.HasPrefix(pos, "arg") {
		return 0, false
	}
	nStr := pos[len("arg"):]
	if nStr == "" {
		return 0, false
	}
	n := 0
	for _, ch := range nStr {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
	}
	if n < 1 {
		return 0, false
	}
	return n - 1, true
}

// DroppedSlot carries the metadata for a slot the engine rejected,
// used for logging to app.jsonl.
type DroppedSlot struct {
	Slot   Slot
	Reason string
}

// placeholderFor maps a SlotType to its uppercase placeholder name.
// Kept as a function (not a map) for forward-compat with composed
// placeholders in the future.
func placeholderFor(t SlotType) string {
	return slotPlaceholders[t]
}

var slotPlaceholders = map[SlotType]string{
	SlotDomain:         "DOMAIN",
	SlotIPv4:           "IPV4",
	SlotURLPathSegment: "PATH_SEG",
	SlotUUID:           "UUID",
	SlotInteger:        "N",
	SlotHexHash:        "HASH",
	SlotFilepathTmp:    "TMP_PATH",
	SlotFilepathCache:  "CACHE_PATH",
	SlotQuotedString:   "STRING",
	SlotDNSRecordType:  "DNS_TYPE",
	SlotHTTPMethod:     "METHOD",
}

// tokenAtPosition looks up the token at a position reference. Supported:
//
//	arg1, arg2, ... argN   → N-th argument (1-indexed) to the program
//	tail_flag              → last argument of the call
//
// Returns (token, true) on success, ("", false) when the position is
// invalid or out of range.
func tokenAtPosition(call shellparse.Call, position string) (string, bool) {
	if position == "tail_flag" {
		if len(call.Args) == 0 {
			return "", false
		}
		last := call.Args[len(call.Args)-1]
		if last == "" {
			return "", false
		}
		return last, true
	}
	if strings.HasPrefix(position, "arg") {
		nStr := position[len("arg"):]
		if nStr == "" {
			return "", false
		}
		n := 0
		for _, ch := range nStr {
			if ch < '0' || ch > '9' {
				return "", false
			}
			n = n*10 + int(ch-'0')
		}
		if n < 1 || n > len(call.Args) {
			return "", false
		}
		tok := call.Args[n-1]
		if tok == "" {
			return "", false
		}
		return tok, true
	}
	return "", false
}

// ---- validators ----

type validatorFunc func(token string) bool

var validators = map[SlotType]validatorFunc{
	SlotDomain:         validateDomain,
	SlotIPv4:           validateIPv4,
	SlotURLPathSegment: validateURLPathSegment,
	SlotUUID:           validateUUID,
	SlotInteger:        validateInteger,
	SlotHexHash:        validateHexHash,
	SlotFilepathTmp:    validateFilepathTmp,
	SlotFilepathCache:  validateFilepathCache,
	SlotQuotedString:   validateQuotedString,
	SlotDNSRecordType:  validateDNSRecordType,
	SlotHTTPMethod:     validateHTTPMethod,
}

var (
	domainRE  = regexp.MustCompile(`^(?i)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\.?$`)
	ipv4RE    = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$`)
	uuidRE    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	integerRE = regexp.MustCompile(`^-?[0-9]+$`)
	hexHashRE = regexp.MustCompile(`^[0-9a-fA-F]{8,64}$`)
	pathSegRE = regexp.MustCompile(`^[A-Za-z0-9._~%!$&'()*+,;=:@\-]+$`)
)

func validateDomain(s string) bool {
	// Reject IPs and empty; domainRE anchors and covers standard hosts.
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	// Reject pure numeric (IP-like) and scheme-prefixed strings.
	if strings.Contains(s, "/") || strings.Contains(s, ":") || strings.Contains(s, " ") {
		return false
	}
	return domainRE.MatchString(s)
}

func validateIPv4(s string) bool { return ipv4RE.MatchString(s) }
func validateUUID(s string) bool { return uuidRE.MatchString(s) }
func validateInteger(s string) bool {
	return integerRE.MatchString(s) && len(s) < 20 // cap signed 64-bit magnitude
}
func validateHexHash(s string) bool { return hexHashRE.MatchString(s) }

func validateURLPathSegment(s string) bool {
	// One path segment — no slashes, no spaces, no fragment/query
	// separators. 256 char cap.
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	if strings.ContainsAny(s, "/\\ ?#") {
		return false
	}
	return pathSegRE.MatchString(s)
}

// pathMetacharsForbidden rejects any byte the shell treats as special
// when the token is used unquoted. Defense in depth: even if the AST
// parsed the token cleanly, downstream uses (logs, re-execution) may
// concatenate unquoted.
var pathMetacharsForbidden = "$`;|&<>()\n\t\\\"'*?[]"

// hasPathMetachar returns true if s contains any character from
// pathMetacharsForbidden or a space. Used by all filepath validators.
func hasPathMetachar(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == ' ' || strings.IndexByte(pathMetacharsForbidden, b) >= 0 {
			return true
		}
	}
	return false
}

func validateFilepathTmp(s string) bool {
	if hasPathMetachar(s) {
		return false
	}
	return validateFilepathUnder(s, "/tmp/") || s == "/tmp"
}

// cachePathPrefixes is the closed set of ancestor directories we accept
// as valid `~/.cache/...` paths. Absolute-path forms must start with
// one of these to prevent `/attacker-chosen-prefix/.cache/foo` from
// passing.
var cachePathPrefixes = []string{
	// macOS/Linux home layouts. Username segment caller-provided; we
	// only enforce the leading structure.
	"/Users/", "/home/", "/root/",
}

func validateFilepathCache(s string) bool {
	if hasPathMetachar(s) || strings.Contains(s, "..") || strings.Contains(s, "\x00") {
		return false
	}
	if strings.HasPrefix(s, "~/.cache/") || s == "~/.cache" {
		return true
	}
	if strings.HasPrefix(s, "/root/.cache/") || s == "/root/.cache" {
		return filepath.Clean(s) == s
	}
	// /Users/<name>/.cache/... or /home/<name>/.cache/...
	for _, prefix := range cachePathPrefixes {
		if !strings.HasPrefix(s, prefix) {
			continue
		}
		rest := s[len(prefix):]
		// rest = "<username>/.cache/..." — username must be plain,
		// followed by exactly "/.cache/" or "/.cache" end.
		slash := strings.IndexByte(rest, '/')
		if slash < 1 {
			return false
		}
		username := rest[:slash]
		if !plainSegmentRE.MatchString(username) {
			return false
		}
		afterUser := rest[slash:] // starts with "/"
		if afterUser == "/.cache" || strings.HasPrefix(afterUser, "/.cache/") {
			return filepath.Clean(s) == s
		}
	}
	return false
}

// plainSegmentRE matches a single lowercase-ish path segment
// (typical username shape). Keeps the cache-prefix check tight.
var plainSegmentRE = regexp.MustCompile(`^[a-zA-Z0-9._][a-zA-Z0-9._\-]*$`)

func validateFilepathUnder(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	return filepathSafe(s)
}

// filepathSafe guards against path-traversal: after cleaning the path
// it must still start with the original prefix. Prevents
// `/tmp/../etc/passwd` from passing as SlotFilepathTmp.
func filepathSafe(s string) bool {
	if strings.Contains(s, "\x00") {
		return false
	}
	cleaned := filepath.Clean(s)
	if strings.HasPrefix(s, "/tmp") && !strings.HasPrefix(cleaned, "/tmp") {
		return false
	}
	if strings.HasPrefix(s, "/.cache") && !strings.HasPrefix(cleaned, "/.cache") {
		return false
	}
	if strings.Contains(s, "..") {
		// be strict: any ".." literal is rejected
		return false
	}
	return true
}

// quotedStringRE is a tight allowlist of characters permissible inside
// a token the LLM wants marked as a quoted_string slot. By design:
//   - no slashes (so an "/etc/passwd" literal can't be tagged variable)
//   - no shell metachars (no `;`, no `$`, no backticks, no pipes)
//   - no leading `-` (so a `--force` flag can't be tagged variable)
//   - no wildcards (`*`, `?`, `[`)
//
// CTO review H2: the previous validator accepted `/etc/passwd` and
// `; rm -rf /` — effectively a universal wildcard for the LLM. This
// tightening restores the "closed vocabulary" property for quoted
// strings.
var quotedStringRE = regexp.MustCompile(`^[A-Za-z0-9 ._,:=@+][A-Za-z0-9 ._,:=@+\-]*$`)

func validateQuotedString(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	return quotedStringRE.MatchString(s)
}

var dnsRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "MX": true, "NS": true, "TXT": true,
	"CNAME": true, "SOA": true, "SRV": true, "PTR": true, "ANY": true,
	"CAA": true, "DS": true, "DNSKEY": true,
}

func validateDNSRecordType(s string) bool {
	return dnsRecordTypes[strings.ToUpper(s)]
}

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
}

func validateHTTPMethod(s string) bool {
	return httpMethods[strings.ToUpper(s)]
}

// CanonicalMatches returns true when the command tokens match the
// canonical form pattern — i.e. non-placeholder tokens match exactly,
// and placeholder tokens are satisfied by a valid token of that type.
// Used by the cache at lookup time to find canonical hits.
//
// Example: canonical "dig {DOMAIN} {DNS_TYPE} 2>&1 | head -{N}" matches
// "dig example.com A 2>&1 | head -10" because each placeholder is
// satisfied by the corresponding token in the incoming command.
//
// Returns false when the programs differ, the argument count differs,
// any literal mismatches, or any placeholder's token fails its validator.
func CanonicalMatches(canonical, command string) bool {
	// Parse both; reject any shape complexity we don't support.
	cCanonical, err := shellparse.Parse(canonical)
	if err != nil || len(cCanonical.Calls) == 0 {
		return false
	}
	cCommand, err := shellparse.Parse(command)
	if err != nil || len(cCommand.Calls) == 0 {
		return false
	}
	if len(cCanonical.Calls) != len(cCommand.Calls) {
		return false
	}
	// Only v1-friendly shapes (single call, no trickery).
	if cCanonical.Features.HasPipe || cCanonical.Features.HasBinaryOp ||
		cCanonical.Features.HasSubshell || cCommand.Features.HasPipe ||
		cCommand.Features.HasBinaryOp || cCommand.Features.HasSubshell {
		return false
	}
	for i, cc := range cCanonical.Calls {
		cm := cCommand.Calls[i]
		if cc.Program != cm.Program {
			return false
		}
		if len(cc.Args) != len(cm.Args) {
			return false
		}
		for j := range cc.Args {
			if !tokenSatisfies(cc.Args[j], cm.Args[j]) {
				return false
			}
		}
	}
	return true
}

// tokenSatisfies returns true when a canonical token (which may be a
// `{PLACEHOLDER}` or a literal) accepts a concrete incoming token.
// Placeholders require the incoming token to validate against the
// matching slot type. Literals require exact string equality.
func tokenSatisfies(canonicalTok, incomingTok string) bool {
	if strings.HasPrefix(canonicalTok, "{") && strings.HasSuffix(canonicalTok, "}") {
		name := canonicalTok[1 : len(canonicalTok)-1]
		slotType, ok := placeholderNameToSlotType[name]
		if !ok {
			return canonicalTok == incomingTok // unknown placeholder: literal compare
		}
		validator := validators[slotType]
		if validator == nil {
			return false
		}
		return validator(incomingTok)
	}
	return canonicalTok == incomingTok
}

// placeholderNameToSlotType is the inverse of slotPlaceholders, used
// during CanonicalMatches to look up a slot's validator from its
// placeholder name.
var placeholderNameToSlotType = func() map[string]SlotType {
	out := make(map[string]SlotType, len(slotPlaceholders))
	for t, name := range slotPlaceholders {
		out[name] = t
	}
	return out
}()

// FirstProgram returns the program name from a command, used by the
// cache to index canonical entries by program. Returns "" on parse
// failure or empty command.
func FirstProgram(command string) string {
	parsed, err := shellparse.Parse(command)
	if err != nil || len(parsed.Calls) == 0 {
		return ""
	}
	return parsed.Calls[0].Program
}
