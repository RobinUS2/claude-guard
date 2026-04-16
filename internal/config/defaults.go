package config

import "github.com/RobinUS2/claude-guard/internal/rules"

// DefaultBlockRules returns the compiled-in tier 1 rule set.
// These are evaluated first, unconditionally, against every Bash call.
// They are written directly in Go so a broken YAML config cannot disable them.
func DefaultBlockRules() []rules.Rule {
	return []rules.Rule{
		// sudo/doas/su always require user review
		&rules.ProgramIs{
			RuleName: "sudo-anything",
			Programs: []string{"sudo", "doas", "su"},
			Reason:   "sudo/doas/su requires explicit user approval",
		},

		// rm -rf on system or home directories
		&rules.BlockedCommand{
			RuleName: "rm-rf-system",
			Programs: []string{"rm"},
			RequireFlagsAny: [][]string{
				{"-r", "-R", "--recursive"},
				{"-f", "--force"},
			},
			TargetPaths: []string{
				"/",
				"/etc", "/usr", "/var", "/opt",
				"/bin", "/sbin",
				"/home", "/Users",
				"/System", "/Library", // macOS
				"/boot", "/lib", "/root",
				// Darwin canonical paths — /etc, /var, /tmp are
				// symlinks into /private on macOS. Listed explicitly
				// so `rm -rf /private/etc` is also blocked (the
				// literal prefix check doesn't follow symlinks).
				"/private/etc", "/private/var", "/private/tmp",
				"/private/var/root", // root's home on darwin
				// `~` normalizes to `$HOME`. BlockedCommand.Eval also
				// consults HasEnvVarArg("HOME","PWD") when any TargetPath
				// starts with `$HOME`, catching `rm -rf "$HOME"` /
				// `rm -rf $HOME` / `rm -rf "$PWD"` which have empty
				// positional slots due to unresolvable ParamExp.
				"~",
			},
			Reason: "rm -rf on system/home directory",
		},

		// find with -delete on protected directories
		&rules.BlockedCommand{
			RuleName: "find-delete-system",
			Programs: []string{"find"},
			// find uses long-form -delete; require it at all, no flag-group needed
			// (BlockedCommand will match if RequireFlagsAny is empty, so we use
			// a single-group spec that accepts any of the destructive flags)
			RequireFlagsAny: [][]string{
				{"-delete", "-exec"},
			},
			TargetPaths: []string{
				"/", "/etc", "/usr", "/var", "/home", "/Users", "/System", "/Library",
				"/private/etc", "/private/var", "/private/tmp", "/private/var/root",
				"~",
			},
			Reason: "find -delete/-exec on system/home directory",
		},

		// curl | sh and variants
		&rules.PipeToShell{
			RuleName:       "curl-pipe-sh",
			SourcePrograms: []string{"curl", "wget", "fetch", "http", "httpie"},
			SinkPrograms:   []string{"sh", "bash", "zsh", "fish", "dash", "ksh", "/bin/sh", "/bin/bash"},
			Reason:         "remote code execution via pipe to shell",
		},

		// bash <(curl ...) and variants
		&rules.ProcSubToShell{
			RuleName:     "procsub-to-shell",
			SinkPrograms: []string{"sh", "bash", "zsh", "fish", "dash", "ksh"},
			Reason:       "remote code execution via process substitution",
		},

		// force push to protected branches
		&rules.GitForcePush{
			RuleName:          "git-force-push-protected",
			ProtectedBranches: []string{"main", "master", "production", "prod", "release", "develop", "trunk"},
			Reason:            "force push to protected branch",
		},

		// SSH private key access from non-ssh programs
		&rules.PathAccess{
			RuleName:        "ssh-private-key",
			Paths:           []string{"~/.ssh/id_*", "**/.ssh/id_*"},
			ExcludePrograms: []string{"ssh", "ssh-add", "ssh-keygen", "ssh-copy-id", "git"},
			Reason:          "access to SSH private key outside of ssh-family tools",
		},

		// GPG/AWS/GCP credential file access
		&rules.PathAccess{
			RuleName:        "credential-files",
			Paths:           []string{"~/.aws/credentials", "~/.gnupg/secring.gpg", "~/.config/gcloud/application_default_credentials.json"},
			ExcludePrograms: []string{"aws", "gpg", "gpg2", "gcloud"},
			Reason:          "access to cloud/pgp credential file",
		},

		// System credential files
		&rules.PathAccess{
			RuleName: "system-credentials",
			Paths:    []string{"/etc/shadow", "/etc/master.passwd", "/etc/sudoers", "/etc/sudoers.d/*"},
			Reason:   "access to system credential file",
		},

		// `<shell> -c '<script>'` — the inner script is opaque to the
		// outer AST parser, so no matcher can reason about what will
		// actually execute. Always prompt the user.
		&rules.ShellDashC{
			RuleName: "shell-dash-c",
			Shells:   []string{"sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh"},
			Reason:   "shell -c wraps an opaque script string that isn't AST-analyzable",
		},

		// terraform state mutations — `state rm`, `state mv`, etc.
		// mutate state without touching infrastructure, which then
		// causes the next `terraform apply` to recreate resources
		// (data loss). `terraform import` is also a state mutation.
		// The outer `terraform-readonly` tier-2 rule approves reads
		// (`terraform plan`, `terraform state list`). This deny list
		// carves out the specific destructive verbs so they prompt
		// the user even though tier-2 would otherwise approve them.
		&rules.NestedSubcommand{
			RuleName: "terraform-state-mutation",
			Program:  "terraform",
			Destructive: []string{
				"state/rm",
				"state/mv",
				"state/push",
				"state/replace-provider",
				"state/rename",
				"import", // any `terraform import` args = deny
			},
			Reason: "terraform state mutation requires user approval",
		},
	}
}

// DefaultAllowRules returns the compiled-in tier 2 rule set. These are
// AST-anchored allow rules — they only match when the command has no
// redirections, pipes, subshells, or command substitution, AND the
// program is fully resolved to a literal.
func DefaultAllowRules() []rules.Rule {
	return []rules.Rule{
		// Read-only POSIX and text tools
		&rules.AnchoredCommand{
			RuleName: "posix-readonly",
			Programs: []string{
				"ls", "cat", "head", "tail", "wc", "sort", "uniq",
				"grep", "rg", "ripgrep", "ack", "ag",
				"find", "tree", "file", "stat",
				"du", "df",
				"which", "whereis", "type",
				"env", "printenv", "id", "whoami", "hostname", "uname", "pwd",
				"echo", "printf", "date",
				"jq", "yq",
				"cmp", "diff",
				"tar", "zcat", "gzcat",
				"xxd", "od", "hexdump",
				"awk", "sed",
			},
			ForbidFlags: []string{
				// awk/sed with inplace flags actually write; exclude them
				"-i", "--in-place",
			},
		},

		// find — safe when no destructive flag
		&rules.AnchoredCommand{
			RuleName:    "find-readonly",
			Programs:    []string{"find"},
			ForbidFlags: []string{"-delete", "-exec", "-execdir"},
		},

		// git read-only subcommands
		&rules.AnchoredCommand{
			RuleName:         "git-readonly",
			Programs:         []string{"git"},
			RequireSubcmdAny: []string{"status", "log", "diff", "show", "branch", "remote", "blame", "rev-parse", "ls-files", "ls-tree", "describe", "config"},
		},

		// gcloud is intentionally NOT in tier 2. Its subcommand tree is too
		// deep for anchored_command to express "must be a read subcommand"
		// — `gcloud run deploy`, `gcloud builds submit`, `gcloud projects
		// delete` would all sneak through a naive `Programs: ["gcloud"]`
		// rule (they're a single anchored call, no pipes, no redirects).
		// Without a nested-subcommand matcher (Phase 2 work), gcloud calls
		// must fall through to the LLM tier where the model can reason
		// about the full command tree.
		//
		// This is a deliberate tradeoff: more LLM cost for gcloud-heavy
		// sessions, but no risk of auto-approving a gcloud mutation.

		// bq (BigQuery) read-only
		&rules.AnchoredCommand{
			RuleName:         "bq-readonly",
			Programs:         []string{"bq"},
			RequireSubcmdAny: []string{"show", "ls", "query", "head"},
		},

		// terraform read-only
		//
		// `state` is intentionally NOT in this list — the subcommand
		// tree is too deep for AnchoredCommand (cannot distinguish
		// `state list` from `state rm`). `terraform state ...` falls
		// to the LLM tier which reasons about the full command.
		// Tier-1 `terraform-state-mutation` still denies the
		// destructive verbs regardless of tier 2.
		&rules.AnchoredCommand{
			RuleName:         "terraform-readonly",
			Programs:         []string{"terraform"},
			RequireSubcmdAny: []string{"plan", "validate", "fmt", "show", "version", "output", "console", "workspace"},
		},

		// docker read-only
		&rules.AnchoredCommand{
			RuleName:         "docker-readonly",
			Programs:         []string{"docker", "podman"},
			RequireSubcmdAny: []string{"ps", "images", "inspect", "logs", "port", "top", "stats", "version", "info", "history", "events"},
		},

		// kubectl read-only
		&rules.AnchoredCommand{
			RuleName:         "kubectl-readonly",
			Programs:         []string{"kubectl", "oc"},
			RequireSubcmdAny: []string{"get", "describe", "logs", "top", "version", "cluster-info", "api-resources", "explain"},
		},

		// go read-only / safe
		&rules.AnchoredCommand{
			RuleName:         "go-readonly",
			Programs:         []string{"go"},
			RequireSubcmdAny: []string{"version", "env", "list", "vet", "fmt", "doc", "help"},
		},

		// npm/yarn/pnpm read-only
		&rules.AnchoredCommand{
			RuleName:         "node-pm-readonly",
			Programs:         []string{"npm", "yarn", "pnpm"},
			RequireSubcmdAny: []string{"list", "ls", "view", "outdated", "audit", "config", "whoami", "why", "info", "version"},
		},

		// gh read-only
		&rules.AnchoredCommand{
			RuleName:         "gh-readonly",
			Programs:         []string{"gh"},
			RequireSubcmdAny: []string{"pr", "issue", "repo", "run", "api", "auth", "release", "search", "status", "version", "help"},
			// Note: "gh pr view" is safe but "gh pr merge" is not. We restrict to the
			// outer subcommand here; the LLM tier refines this.
		},

		// curl with only -I / --head / -o /dev/null (HEAD and discard-body reads)
		// is tricky to express with flag constraints, so it falls through to LLM.

		// make read-only targets
		&rules.AnchoredCommand{
			RuleName:         "make-readonly",
			Programs:         []string{"make"},
			RequireSubcmdAny: []string{"help", "list", "test", "check", "lint", "vet", "fmt", "typecheck", "build"},
		},
	}
}
