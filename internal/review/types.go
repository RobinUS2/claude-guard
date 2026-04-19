// Package review implements the self-review loop: periodic analysis of
// guard decisions by an expensive model (Opus) with autonomous rule
// adjustment.
package review

import "time"

// Case is a single decision worth reviewing. Collected from the
// decision + deny + app logs and filtered to "interesting" shapes.
type Case struct {
	Timestamp time.Time `json:"ts"`
	ToolName  string    `json:"tool"`
	Command   string    `json:"command"` // truncated to 200 chars
	Verdict   string    `json:"verdict"` // allow, deny, continue
	Tier      string    `json:"tier"`
	Rule      string    `json:"rule"`
	Reason    string    `json:"reason"`
	Shadow    string    `json:"shadow,omitempty"` // tier4LLM shadow value
	Category  string    `json:"category"`         // deny, unsafe, disagreement, llm_miss, legacy
}

// Report is the structured output from Opus analysis.
type Report struct {
	FalsePositives  []Finding             `json:"false_positives"`
	FalseNegatives  []Finding             `json:"false_negatives"`
	RecurringShapes []ShapeRecommendation `json:"recurring_shapes"`
	PromptHints     []HintRecommendation  `json:"prompt_hints"`
	LegacyTrims     []TrimRecommendation  `json:"legacy_trims"`
	Summary         string                `json:"summary"`
}

// Finding is a specific decision the model flagged as incorrect.
type Finding struct {
	CaseIndex int    `json:"case_index"`
	Command   string `json:"command"`
	Expected  string `json:"expected_verdict"` // what the model thinks it should be
	Reason    string `json:"reason"`
}

// ShapeRecommendation is a proposed learned tier-2 allow rule.
type ShapeRecommendation struct {
	Programs    []string `json:"programs"`
	Subcommands []string `json:"subcommands"` // must be ≥2 (concrete pair)
	ForbidFlags []string `json:"forbid_flags,omitempty"`
	Evidence    []string `json:"evidence"` // sample command strings
	Reason      string   `json:"reason"`
}

// HintRecommendation is a proposed prompt-hint addition.
type HintRecommendation struct {
	Context string `json:"context"` // max 500 chars
	Reason  string `json:"reason"`
}

// TrimRecommendation is a proposed legacy-pattern removal.
type TrimRecommendation struct {
	Prefix string `json:"prefix"` // the legacy pattern to remove
	Reason string `json:"reason"`
}

// LearnedRulesFile is the on-disk YAML shape for
// ~/.config/claude-guard/learned-rules.yaml.
type LearnedRulesFile struct {
	Version     int           `yaml:"version"`
	GeneratedAt time.Time     `yaml:"generated_at"`
	ReviewModel string        `yaml:"review_model"`
	Rules       []LearnedRule `yaml:"rules"`
}

// LearnedRule is a single auto-generated tier-2 allow rule.
type LearnedRule struct {
	Name          string    `yaml:"name"`
	Programs      []string  `yaml:"programs"`
	Subcommands   []string  `yaml:"subcommands"`
	ForbidFlags   []string  `yaml:"forbid_flags,omitempty"`
	EvidenceCount int       `yaml:"evidence_count"`
	AddedAt       time.Time `yaml:"added_at"`
	Reason        string    `yaml:"reason"`
}

// PromptHintsFile is the on-disk YAML shape for
// ~/.config/claude-guard/prompt-hints.yaml.
type PromptHintsFile struct {
	Version int          `yaml:"version"`
	Hints   []PromptHint `yaml:"hints"`
}

// PromptHint is extra LLM classifier context from the review loop.
type PromptHint struct {
	Context string    `yaml:"context"` // max 500 chars
	AddedAt time.Time `yaml:"added_at"`
}

// ReviewLogEntry is one line in review-log.jsonl.
type ReviewLogEntry struct {
	Timestamp      time.Time `json:"ts"`
	Action         string    `json:"action"` // add_rule, add_hint, trim_legacy
	Target         string    `json:"target"` // file name
	Key            string    `json:"key"`    // rule name / hint index / pattern
	Reason         string    `json:"reason"`
	RollbackAction string    `json:"rollback_action"` // remove_rule, remove_hint, add_legacy
	PreviousState  string    `json:"previous_state,omitempty"`
}

// ValidatedPlan is the output of Validate — changes that passed
// safety checks, ready to apply.
type ValidatedPlan struct {
	AcceptedRules []ShapeRecommendation
	AcceptedHints []HintRecommendation
	AcceptedTrims []TrimRecommendation
	RejectedRules []RejectedItem
	RejectedHints []RejectedItem
	Summary       string
}

// RejectedItem is a recommendation that failed validation.
type RejectedItem struct {
	Description string
	Reason      string
}
