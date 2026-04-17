package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultConfigDir is the standard config location.
func DefaultConfigDir() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "claude-guard")
}

// Apply writes validated changes to config files and logs each
// change to the review log. Returns the count of changes made.
func Apply(plan *ValidatedPlan, configDir string) (int, error) {
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir config: %w", err)
	}

	changes := 0
	logPath := filepath.Join(configDir, "review-log.jsonl")
	now := time.Now()

	// Apply learned rules.
	if len(plan.AcceptedRules) > 0 {
		rulesPath := filepath.Join(configDir, "learned-rules.yaml")
		existing := loadLearnedRules(rulesPath)

		for _, r := range plan.AcceptedRules {
			name := fmt.Sprintf("learned:%s-%s", r.Programs[0], r.Subcommands[len(r.Subcommands)-1])
			// Skip if already exists.
			if hasRule(existing, name) {
				continue
			}
			existing.Rules = append(existing.Rules, LearnedRule{
				Name:          name,
				Programs:      r.Programs,
				Subcommands:   r.Subcommands,
				ForbidFlags:   r.ForbidFlags,
				EvidenceCount: len(r.Evidence),
				AddedAt:       now,
				Reason:        r.Reason,
			})
			logChange(logPath, ReviewLogEntry{
				Timestamp:      now,
				Action:         "add_rule",
				Target:         "learned-rules.yaml",
				Key:            name,
				Reason:         r.Reason,
				RollbackAction: "remove_rule",
			})
			changes++
		}
		existing.GeneratedAt = now
		existing.ReviewModel = DefaultModel
		existing.Version = 1
		if err := writeYAML(rulesPath, existing); err != nil {
			return changes, fmt.Errorf("write learned rules: %w", err)
		}
	}

	// Apply prompt hints.
	if len(plan.AcceptedHints) > 0 {
		hintsPath := filepath.Join(configDir, "prompt-hints.yaml")
		existing := loadPromptHints(hintsPath)

		for _, h := range plan.AcceptedHints {
			existing.Hints = append(existing.Hints, PromptHint{
				Context: h.Context,
				AddedAt: now,
			})
			logChange(logPath, ReviewLogEntry{
				Timestamp:      now,
				Action:         "add_hint",
				Target:         "prompt-hints.yaml",
				Key:            truncate(h.Context, 60),
				Reason:         h.Reason,
				RollbackAction: "remove_hint",
			})
			changes++
		}

		// Enforce 2KB cap — evict oldest hints first.
		existing = enforceHintCap(existing, 2048)
		// Enforce 90-day TTL.
		existing = expireHints(existing, 90*24*time.Hour)

		existing.Version = 1
		if err := writeYAML(hintsPath, existing); err != nil {
			return changes, fmt.Errorf("write prompt hints: %w", err)
		}
	}

	// Apply legacy trims (log but don't modify legacy-patterns.yaml
	// directly — the runtime filter in legacy.Load handles unsafe
	// patterns. Here we just log what the review thinks should be
	// trimmed for visibility).
	for _, t := range plan.AcceptedTrims {
		logChange(logPath, ReviewLogEntry{
			Timestamp:      now,
			Action:         "suggest_trim_legacy",
			Target:         "legacy-patterns.yaml",
			Key:            t.Prefix,
			Reason:         t.Reason,
			RollbackAction: "no_action",
		})
		changes++
	}

	return changes, nil
}

func loadLearnedRules(path string) *LearnedRulesFile {
	data, err := os.ReadFile(path)
	if err != nil {
		return &LearnedRulesFile{}
	}
	var f LearnedRulesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return &LearnedRulesFile{}
	}
	return &f
}

func loadPromptHints(path string) *PromptHintsFile {
	data, err := os.ReadFile(path)
	if err != nil {
		return &PromptHintsFile{}
	}
	var f PromptHintsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return &PromptHintsFile{}
	}
	return &f
}

// LoadLearnedRules loads the learned rules file for engine use.
func LoadLearnedRules(configDir string) *LearnedRulesFile {
	return loadLearnedRules(filepath.Join(configDir, "learned-rules.yaml"))
}

// LoadPromptHints loads the prompt hints file for engine use.
func LoadPromptHints(configDir string) *PromptHintsFile {
	return loadPromptHints(filepath.Join(configDir, "prompt-hints.yaml"))
}

func hasRule(f *LearnedRulesFile, name string) bool {
	for _, r := range f.Rules {
		if r.Name == name {
			return true
		}
	}
	return false
}

func enforceHintCap(f *PromptHintsFile, maxBytes int) *PromptHintsFile {
	total := 0
	for _, h := range f.Hints {
		total += len(h.Context)
	}
	for total > maxBytes && len(f.Hints) > 0 {
		total -= len(f.Hints[0].Context)
		f.Hints = f.Hints[1:] // evict oldest
	}
	return f
}

func expireHints(f *PromptHintsFile, maxAge time.Duration) *PromptHintsFile {
	cutoff := time.Now().Add(-maxAge)
	var kept []PromptHint
	for _, h := range f.Hints {
		if h.AddedAt.After(cutoff) {
			kept = append(kept, h)
		}
	}
	f.Hints = kept
	return f
}

func writeYAML(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func logChange(path string, entry ReviewLogEntry) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	data, _ := json.Marshal(entry)
	f.Write(data)
	f.Write([]byte("\n"))
}
