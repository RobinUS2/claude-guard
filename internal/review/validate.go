package review

import (
	"fmt"
	"strings"
)

// forbiddenLearnedPrograms are programs whose safety depends on file
// content, not command shape. Cannot become learned rules.
var forbiddenLearnedPrograms = map[string]struct{}{
	"go": {}, "npm": {}, "yarn": {}, "pnpm": {}, "cargo": {},
	"make": {}, "just": {}, "rake": {},
	"python": {}, "python3": {}, "perl": {}, "ruby": {}, "node": {},
	"sh": {}, "bash": {}, "zsh": {}, "fish": {}, "dash": {}, "ksh": {},
	"sudo": {}, "su": {}, "doas": {},
	"rm": {}, "dd": {}, "chmod": {}, "chown": {},
	"curl": {}, "wget": {}, "scp": {}, "rsync": {},
}

// Validate checks each recommendation against safety rails and
// returns a ValidatedPlan with accepted + rejected items.
func Validate(report *Report) *ValidatedPlan {
	plan := &ValidatedPlan{Summary: report.Summary}

	for _, r := range report.RecurringShapes {
		if err := validateRule(r); err != nil {
			plan.RejectedRules = append(plan.RejectedRules, RejectedItem{
				Description: fmt.Sprintf("%v %v", r.Programs, r.Subcommands),
				Reason:      err.Error(),
			})
			continue
		}
		plan.AcceptedRules = append(plan.AcceptedRules, r)
	}

	for _, h := range report.PromptHints {
		if err := validateHint(h); err != nil {
			plan.RejectedHints = append(plan.RejectedHints, RejectedItem{
				Description: h.Context[:min(len(h.Context), 80)],
				Reason:      err.Error(),
			})
			continue
		}
		plan.AcceptedHints = append(plan.AcceptedHints, h)
	}

	plan.AcceptedTrims = report.LegacyTrims // trims are always safe
	return plan
}

func validateRule(r ShapeRecommendation) error {
	if len(r.Programs) == 0 {
		return fmt.Errorf("no programs specified")
	}
	for _, p := range r.Programs {
		if _, bad := forbiddenLearnedPrograms[strings.ToLower(p)]; bad {
			return fmt.Errorf("program %q is in forbiddenLearnedPrograms (safety depends on file content)", p)
		}
	}
	if len(r.Subcommands) < 2 {
		return fmt.Errorf("subcommands must have ≥2 elements (concrete noun+verb pair); got %d", len(r.Subcommands))
	}
	if len(r.Evidence) < 3 {
		return fmt.Errorf("need ≥3 evidence instances; got %d", len(r.Evidence))
	}
	return nil
}

func validateHint(h HintRecommendation) error {
	if len(h.Context) == 0 {
		return fmt.Errorf("empty hint context")
	}
	if len(h.Context) > 500 {
		return fmt.Errorf("hint context too long (%d chars, max 500)", len(h.Context))
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
