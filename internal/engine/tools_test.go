package engine

import (
	"testing"
)

// --- URL deny (SSRF) ---

func TestCheckURLDeny_SSRF(t *testing.T) {
	cases := []struct {
		url     string
		wantDeny bool
	}{
		// Blocked schemes.
		{"file:///etc/passwd", true},
		{"ftp://evil.com/payload", true},
		{"gopher://evil.com/payload", true},
		// Loopback.
		{"http://localhost/admin", true},
		{"http://LOCALHOST/admin", true},       // case
		{"http://127.0.0.1/admin", true},
		{"http://[::1]/admin", true},           // IPv6 loopback
		// Private CIDRs.
		{"http://10.0.0.1/internal", true},
		{"http://172.16.0.1/internal", true},
		{"http://192.168.1.1/admin", true},
		// Cloud metadata.
		{"http://169.254.169.254/latest/meta-data/", true},
		{"http://metadata.google.internal/computeMetadata/v1/", true},
		// 0.0.0.0.
		{"http://0.0.0.0/admin", true},
		// Userinfo bypass — u.Hostname() strips it, host is "localhost".
		{"http://evil.com@localhost/admin", true},
		// Credential paths.
		{"https://example.com/.env", true},
		{"https://example.com/.git/config", true},
		{"https://example.com/etc/passwd", true}, // path matches /etc/passwd
		// Safe URLs.
		{"https://docs.python.org/3/", false},
		{"https://github.com/foo/bar", false},
		{"https://stackoverflow.com/q/123", false},
		{"https://pkg.go.dev/net/http", false},
		{"http://example.com/api", false},
		// NOT substring match — localhost.evil.com is NOT localhost.
		{"http://localhost.evil.com/admin", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			deny, rule, _ := checkURLDeny(tc.url)
			if deny != tc.wantDeny {
				t.Errorf("checkURLDeny(%q) = %v (rule=%s), want deny=%v", tc.url, deny, rule, tc.wantDeny)
			}
		})
	}
}

// --- isWithinCWD ---

func TestIsWithinCWD(t *testing.T) {
	cases := []struct {
		path, cwd string
		want      bool
	}{
		{"/Users/robin/code/project/src/main.go", "/Users/robin/code/project", true},
		{"/Users/robin/code/project", "/Users/robin/code/project", true}, // exact CWD
		{"/Users/robin/code/other/file.go", "/Users/robin/code/project", false},
		{"/etc/passwd", "/Users/robin/code/project", false},
		{"~/.ssh/id_rsa", "/Users/robin/code/project", false},
		{"/tmp/test", "", false},
		{"", "/Users/robin", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := isWithinCWD(tc.path, tc.cwd); got != tc.want {
				t.Errorf("isWithinCWD(%q, %q) = %v, want %v", tc.path, tc.cwd, got, tc.want)
			}
		})
	}
}

// --- MCP action extraction ---

func TestExtractMCPAction(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"mcp__gdrive__gdrive_read_file", "read_file"},
		{"mcp__google-calendar__list-events", "list-events"},
		{"mcp__atlassian__getJiraIssue", "getJiraIssue"},
		{"mcp__claude_ai_Gmail__authenticate", "authenticate"},
		{"Read", "Read"},          // non-MCP
		{"Bash", "Bash"},          // non-MCP
		{"mcp__x__y", "y"},        // short action, no prefix to strip
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			got := extractMCPAction(tc.tool)
			if got != tc.want {
				t.Errorf("extractMCPAction(%q) = %q, want %q", tc.tool, got, tc.want)
			}
		})
	}
}

// --- Read evaluator (engine-level) ---

func TestDecideRead_DeniesProtectedPath(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "Read",
		FilePath: "/Users/robin/.ssh/id_rsa",
		Command:  "Read: /Users/robin/.ssh/id_rsa",
		CWD:      "/tmp",
	})
	if out.Verdict != Deny {
		t.Errorf("Verdict = %v, want Deny for Read of SSH key", out.Verdict)
	}
}

func TestDecideRead_AllowsCWDFile(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "Read",
		FilePath: "/Users/robin/code/project/main.go",
		Command:  "Read: /Users/robin/code/project/main.go",
		CWD:      "/Users/robin/code/project",
	})
	if out.Verdict != Allow {
		t.Errorf("Verdict = %v (tier=%s), want Allow for in-CWD read", out.Verdict, out.Tier)
	}
	if out.Rule != "read-cwd-scope" {
		t.Errorf("Rule = %q, want read-cwd-scope", out.Rule)
	}
}

// --- Write evaluator ---

func TestDecideWrite_DeniesProtectedPath(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "Write",
		FilePath: "/Users/robin/.bashrc",
		Command:  "Write: /Users/robin/.bashrc",
		CWD:      "/tmp",
		IsWrite:  true,
	})
	if out.Verdict != Deny {
		t.Errorf("Verdict = %v, want Deny for Write to .bashrc", out.Verdict)
	}
}

func TestDecideWrite_AllowsCWDFile(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "Write",
		FilePath: "/Users/robin/code/project/output.txt",
		Command:  "Write: /Users/robin/code/project/output.txt",
		CWD:      "/Users/robin/code/project",
		IsWrite:  true,
	})
	if out.Verdict != Allow {
		t.Errorf("Verdict = %v, want Allow for in-CWD write", out.Verdict)
	}
}

// --- WebFetch evaluator ---

func TestDecideWebFetch_DeniesLocalhost(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "WebFetch",
		URL:      "http://localhost:8080/admin",
		Command:  "WebFetch: http://localhost:8080/admin",
		CWD:      "/tmp",
	})
	if out.Verdict != Deny {
		t.Errorf("Verdict = %v, want Deny for localhost WebFetch", out.Verdict)
	}
}

func TestDecideWebFetch_DeniesFileScheme(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "WebFetch",
		URL:      "file:///etc/passwd",
		Command:  "WebFetch: file:///etc/passwd",
		CWD:      "/tmp",
	})
	if out.Verdict != Deny {
		t.Errorf("Verdict = %v, want Deny for file:// WebFetch", out.Verdict)
	}
}

// --- Generic (MCP) evaluator ---

func TestDecideGeneric_ReadVerbAutoAllows(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "mcp__google-calendar__list-events",
		Command:  "MCP tool call (not bash) mcp__google-calendar__list-events: {}",
		CWD:      "/tmp",
	})
	if out.Verdict != Allow {
		t.Errorf("Verdict = %v, want Allow for read-verb MCP tool", out.Verdict)
	}
	if out.Rule != "mcp-read-verb" {
		t.Errorf("Rule = %q, want mcp-read-verb", out.Rule)
	}
}

func TestDecideGeneric_WriteVerbFallsThrough(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "mcp__gdrive__gdrive_update_sheet",
		Command:  "MCP tool call (not bash) mcp__gdrive__gdrive_update_sheet: {}",
		CWD:      "/tmp",
	})
	// No LLM configured in basic test engine → falls through to Continue.
	if out.Verdict != Continue {
		t.Errorf("Verdict = %v, want Continue for write-verb MCP (no LLM)", out.Verdict)
	}
}

func TestDecideGeneric_StructurallySafeTools(t *testing.T) {
	cases := []struct {
		name     string
		toolName string
		wantRule string
	}{
		// Built-ins
		{"Agent subagent spawn", "Agent", "safe-builtin-tool"},
		{"ToolSearch schema fetch", "ToolSearch", "safe-builtin-tool"},
		{"TodoWrite state", "TodoWrite", "safe-builtin-tool"},
		// MCP server prefixes
		{"ccd_session mark_chapter", "mcp__ccd_session__mark_chapter", "safe-mcp-server"},
		{"ccd_session spawn_task", "mcp__ccd_session__spawn_task", "safe-mcp-server"},
		{"mcp-registry search", "mcp__mcp-registry__search_mcp_registry", "safe-mcp-server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newTestEngine(t, false)
			out := e.Decide(Input{
				ToolName: tc.toolName,
				Command:  "MCP tool call (not bash) " + tc.toolName + ": {}",
				CWD:      "/tmp",
			})
			if out.Verdict != Allow {
				t.Errorf("Verdict = %v, want Allow for structurally safe tool %s", out.Verdict, tc.toolName)
			}
			if out.Rule != tc.wantRule {
				t.Errorf("Rule = %q, want %q", out.Rule, tc.wantRule)
			}
			if out.Tier != "instant_allow" {
				t.Errorf("Tier = %q, want instant_allow", out.Tier)
			}
		})
	}
}

// TestDecideGeneric_ScheduledTasksFallsThrough documents that
// scheduled-tasks MCP is NOT in the structural allowlist because
// create_scheduled_task persists intent across sessions.
func TestDecideGeneric_ScheduledTasksFallsThrough(t *testing.T) {
	e, _ := newTestEngine(t, false)
	out := e.Decide(Input{
		ToolName: "mcp__scheduled-tasks__create_scheduled_task",
		Command:  "MCP tool call (not bash) mcp__scheduled-tasks__create_scheduled_task: {}",
		CWD:      "/tmp",
	})
	// "create" is not a read-verb; no structural allow → falls through
	// to LLM → no LLM in test engine → Continue.
	if out.Verdict != Continue {
		t.Errorf("Verdict = %v, want Continue for scheduled-tasks create", out.Verdict)
	}
	if out.Rule == "safe-mcp-server" {
		t.Errorf("scheduled-tasks must NOT be auto-allowed via structural rule")
	}
}
