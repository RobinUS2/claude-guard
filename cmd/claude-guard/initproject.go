package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RobinUS2/claude-guard/internal/projectconfig"
)

// initProjectConfigTemplate is the commented starter .claude-guard.yml
// we write on `claude-guard init-project-config`. Scoped tight enough
// that a user can copy and edit without needing the reference doc open.
const initProjectConfigTemplate = `# claude-guard per-project configuration
#
# This file extends the TIER 2 allow list with project-specific rules.
# It CANNOT weaken the tier 1 block rules — sudo, rm -rf on system
# dirs, curl|sh, force-push to protected branches, etc. are always
# denied regardless of what this file says.
#
# Rules use the same anchored-command matcher as the built-in defaults:
# single literal program, optional subcommand constraint, optional
# forbidden-flags list. No regex, no globs, no contains-string matching.
#
# Docs: references/claude_guard.md (section "Per-project configuration")

version: 1
project_name: "my-project"

allow:
  # Example: allow 'git push' (to any non-protected branch), but still
  # deny force-push via the ForbidFlags constraint. The default tier 1
  # 'git-force-push-protected' rule already catches force-push to main/
  # master/production, so this entry is just for the non-protected case.
  #
  # - name: git-push-feature
  #   programs: [git]
  #   subcommands: [push]
  #   forbid_flags: ["--force", "-f", "--force-with-lease"]

  # Example: custom make targets your project uses for safe operations.
  #
  # - name: make-ci-targets
  #   programs: [make]
  #   subcommands: [deploy-preview, migrate, seed]

# Optional: commands that should be cached at GLOBAL scope (safe
# everywhere, not just this project). Use sparingly — only for
# commands whose safety is truly independent of project context.
# promote_global:
#   - "git log --oneline -5"
`

// cmdInitProjectConfig writes a starter .claude-guard.yml in cwd.
//
//	claude-guard init-project-config            # creates .claude-guard.yml in cwd
//	claude-guard init-project-config --force    # overwrite existing
//	claude-guard init-project-config --path DIR # write into DIR instead of cwd
func cmdInitProjectConfig(args []string) int {
	fs := flag.NewFlagSet("init-project-config", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var force bool
	var dir string
	fs.BoolVar(&force, "force", false, "overwrite an existing .claude-guard.yml")
	fs.StringVar(&dir, "path", "", "directory to write into (default: cwd)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "init-project-config: cwd: %v\n", err)
			return 1
		}
		dir = cwd
	}

	target := filepath.Join(dir, projectconfig.ConfigFilename)
	// Refuse to follow symlinks on overwrite — otherwise --force against
	// a symlinked .claude-guard.yml would clobber whatever the link
	// points at. Lstat reports the link itself; Stat follows it.
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			fmt.Fprintf(os.Stderr, "init-project-config: %s is a symlink — refusing to overwrite\n", target)
			return 1
		}
		if !force {
			fmt.Fprintf(os.Stderr, "init-project-config: %s already exists (pass --force to overwrite)\n", target)
			return 1
		}
	}
	if err := os.WriteFile(target, []byte(initProjectConfigTemplate), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "init-project-config: write %s: %v\n", target, err)
		return 1
	}
	fmt.Printf("wrote starter config to %s\n", target)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Edit the file to add project-specific allow rules.")
	fmt.Println("  2. Run `claude-guard lint` to validate.")
	fmt.Println("  3. Run `claude-guard doctor` to confirm the file is picked up.")
	return 0
}
