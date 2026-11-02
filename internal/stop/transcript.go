package stop

import (
	"encoding/json"
	"strings"
)

// ParseTranscript extracts the Transcript fields claude-guard rules need.
//
// Claude Code transcript format:
//   - role="user":      string or []content-block
//   - role="assistant": string or []content-block, which includes type="text"
//     AND type="tool_use" blocks (this is where Bash/TodoWrite calls live)
//
// Tool calls appear inside assistant content as type="tool_use" — NOT as
// separate role="tool" entries. This is the key structural fact.
func ParseTranscript(raw []json.RawMessage) Transcript {
	var tr Transcript

	type contentBlock struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	}
	type turn struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	type bashInput struct {
		Command string `json:"command"`
	}
	type todoInput struct {
		Todos []TodoItem `json:"todos"`
	}

	var lastAssistantParts []string
	firstUser := true

	for idx, rawTurn := range raw {
		var t turn
		if err := json.Unmarshal(rawTurn, &t); err != nil {
			continue
		}

		switch t.Role {
		case "user":
			if firstUser {
				firstUser = false
				var s string
				if err := json.Unmarshal(t.Content, &s); err == nil {
					tr.FirstUserText = s
				}
			}
			// A user message that is not just tool results starts a new turn.
			toolResultsOnly := false
			var ublocks []contentBlock
			if json.Unmarshal(t.Content, &ublocks) == nil && len(ublocks) > 0 {
				toolResultsOnly = true
				for _, blk := range ublocks {
					if blk.Type != "tool_result" {
						toolResultsOnly = false
					}
				}
			}
			if !toolResultsOnly {
				tr.TurnStart = idx + 1
			}

		case "assistant":
			lastAssistantParts = nil

			var s string
			if err := json.Unmarshal(t.Content, &s); err == nil {
				lastAssistantParts = append(lastAssistantParts, s)
				break
			}

			var blocks []contentBlock
			if err := json.Unmarshal(t.Content, &blocks); err != nil {
				break
			}
			for _, blk := range blocks {
				switch blk.Type {
				case "text":
					if blk.Text != "" {
						lastAssistantParts = append(lastAssistantParts, blk.Text)
					}
				case "tool_use":
					if blk.Name == "Bash" {
						var inp bashInput
						if err := json.Unmarshal(blk.Input, &inp); err == nil && inp.Command != "" {
							tr.BashCalls = append(tr.BashCalls, inp.Command)
							tr.BashCallTurns = append(tr.BashCallTurns, idx+1)
						}
					}
					if blk.Name == "TodoWrite" {
						var inp todoInput
						if err := json.Unmarshal(blk.Input, &inp); err == nil && len(inp.Todos) > 0 {
							tr.HasTodoWrite = true
							tr.LastTodoItems = inp.Todos
						}
					}
				}
			}
		}
		// The last turn that carries assistant text is where a test run
		// would have been proposed.
		if t.Role == "assistant" && len(lastAssistantParts) > 0 {
			tr.LastTextTurn = idx + 1
		}
	}
	tr.LastAssistantText = strings.Join(lastAssistantParts, "\n")
	tr.TurnCount = len(raw)
	// Approximate transcript size — sum of raw JSON bytes.
	for _, r := range raw {
		tr.TranscriptBytes += len(r)
	}
	return tr
}
