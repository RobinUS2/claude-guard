package review

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxCases caps the number of cases sent to the review model.
const MaxCases = 200

// logRecord is the JSON shape of one line in decisions.jsonl.
// We only decode the fields we need for review.
type logRecord struct {
	Timestamp   string `json:"time"`
	ToolName    string `json:"tool_name"`
	Command     string `json:"command"`
	Verdict     string `json:"verdict"`
	Tier        string `json:"tier"`
	Rule        string `json:"rule"`
	Reason      string `json:"reason"`
	Description string `json:"description"`
	Shadow      *struct {
		Tier4LLM string `json:"tier4_llm"`
	} `json:"shadow,omitempty"`
}

// Collect reads the last `hours` of decision logs and filters to
// interesting cases for the review model.
func Collect(logDir string, hours int) ([]Case, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	var cases []Case

	// Read decisions.jsonl for all decisions.
	decPath := filepath.Join(logDir, "decisions.jsonl")
	decisions, err := readLogFile(decPath, cutoff)
	if err != nil {
		return nil, err
	}

	// Categorize each decision.
	// Track command shapes for repeat-LLM detection.
	llmShapeCounts := map[string]int{}

	for _, r := range decisions {
		c := Case{
			ToolName: r.ToolName,
			Command:  truncate(r.Command, 200),
			Verdict:  r.Verdict,
			Tier:     r.Tier,
			Rule:     r.Rule,
			Reason:   r.Reason,
		}
		if r.Shadow != nil {
			c.Shadow = r.Shadow.Tier4LLM
		}
		c.Timestamp, _ = time.Parse(time.RFC3339Nano, r.Timestamp)

		switch {
		case r.Verdict == "deny":
			c.Category = "deny"
			cases = append(cases, c)
		case strings.HasPrefix(c.Shadow, "unsafe"):
			c.Category = "unsafe"
			cases = append(cases, c)
		case strings.HasPrefix(c.Shadow, "unsure"):
			c.Category = "unsure"
			cases = append(cases, c)
		case r.Tier == "llm":
			c.Category = "llm_hit"
			shape := commandShape(r.Command)
			llmShapeCounts[shape]++
			if llmShapeCounts[shape] >= 3 {
				c.Category = "llm_repeat"
				cases = append(cases, c)
			}
		case r.Tier == "legacy":
			c.Category = "legacy"
			cases = append(cases, c)
		case strings.Contains(c.Shadow, "disagree"):
			c.Category = "disagreement"
			cases = append(cases, c)
		}
	}

	// Read denies.jsonl for the audit trail (may overlap with
	// decisions.jsonl but that's OK — we deduplicate by ensuring
	// denies are already included above).

	// Cap to MaxCases. Always include all denies and disagreements;
	// sample the rest.
	if len(cases) > MaxCases {
		// Prioritize: denies first, then disagreements, then rest.
		var priority, rest []Case
		for _, c := range cases {
			if c.Category == "deny" || c.Category == "disagreement" {
				priority = append(priority, c)
			} else {
				rest = append(rest, c)
			}
		}
		remaining := MaxCases - len(priority)
		if remaining < 0 {
			remaining = 0
		}
		if len(rest) > remaining {
			rest = rest[:remaining]
		}
		cases = append(priority, rest...)
	}

	return cases, nil
}

func readLogFile(path string, cutoff time.Time) ([]logRecord, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []logRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 256*1024), 256*1024) // handle long lines
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var r logRecord
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, r.Timestamp)
		if err != nil {
			continue
		}
		if ts.Before(cutoff) {
			continue
		}
		records = append(records, r)
	}
	return records, scanner.Err()
}

// commandShape returns a rough shape of a command for grouping.
// First 3 whitespace-separated tokens, lowercased.
func commandShape(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) > 3 {
		fields = fields[:3]
	}
	return strings.ToLower(strings.Join(fields, " "))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
