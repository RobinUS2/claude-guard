package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RobinUS2/claude-guard/internal/legacy"
)

// cmdMigrate reads ~/.claude/settings.json, extracts the
// permissions.allow array, parses Bash() entries into structured
// patterns, and writes them to ~/.config/claude-guard/legacy-patterns.yaml.
//
// The migrated YAML powers tier 5 — the safety net during phase 4 of
// the rollout. Once the new config is trusted, the user can shrink
// settings.json's allow list to a minimal set; the migrated YAML keeps
// the historical permissions live.
//
//	claude-guard migrate [--input PATH] [--output PATH] [--verify] [--force]
//
//	--input PATH    settings.json source file (default: ~/.claude/settings.json)
//	--output PATH   destination YAML (default: $XDG_CONFIG_HOME/claude-guard/legacy-patterns.yaml)
//	--verify        round-trip the YAML and fail if any pattern was lost
//	--force         overwrite an existing output file (default: refuse)
func cmdMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	home, _ := os.UserHomeDir()
	defaultInput := filepath.Join(home, ".claude", "settings.json")
	defaultOutput := defaultLegacyPath()

	var input, output string
	var verify, force bool
	fs.StringVar(&input, "input", defaultInput, "settings.json source")
	fs.StringVar(&output, "output", defaultOutput, "legacy-patterns.yaml destination")
	fs.BoolVar(&verify, "verify", false, "round-trip the result and fail on any loss")
	fs.BoolVar(&force, "force", false, "overwrite an existing output file")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if _, err := os.Stat(output); err == nil && !force {
		fmt.Fprintf(os.Stderr, "migrate: %s already exists; pass --force to overwrite\n", output)
		return 1
	}

	data, err := os.ReadFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: read input %s: %v\n", input, err)
		return 1
	}

	file, err := legacy.MigrateSettingsJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 1
	}

	if err := legacy.WriteFile(output, file); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: write %s: %v\n", output, err)
		return 1
	}

	fmt.Printf("migrated %d Bash patterns from %s\n", len(file.Patterns), input)
	fmt.Printf("wrote                   %s\n", output)
	if len(file.Skipped) > 0 {
		fmt.Printf("skipped %d non-Bash or unsupported entries\n", len(file.Skipped))
		const sampleN = 5
		shown := len(file.Skipped)
		if shown > sampleN {
			shown = sampleN
		}
		for _, s := range file.Skipped[:shown] {
			fmt.Printf("  skip: %s\n", s)
		}
		if len(file.Skipped) > sampleN {
			fmt.Printf("  (... %d more)\n", len(file.Skipped)-sampleN)
		}
	}

	if verify {
		loaded, err := legacy.Load(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate: --verify reload failed: %v\n", err)
			return 1
		}
		if len(loaded.Patterns) != len(file.Patterns) {
			fmt.Fprintf(os.Stderr, "migrate: --verify pattern count mismatch: wrote %d, loaded %d\n",
				len(file.Patterns), len(loaded.Patterns))
			return 1
		}
		fmt.Printf("verify OK (%d patterns round-trip cleanly)\n", len(loaded.Patterns))
	}

	return 0
}

// defaultLegacyPath returns the canonical location for the migrated
// legacy YAML file. Tier 5 reads from this same path.
func defaultLegacyPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "claude-guard", "legacy-patterns.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "claude-guard", "legacy-patterns.yaml")
}
