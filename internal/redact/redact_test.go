package redact

import (
	"strings"
	"testing"
)

func TestSkip_BearerToken(t *testing.T) {
	r := New(nil, nil)
	cases := []string{
		`curl -H "Authorization: Bearer sk-ant-abc123def456ghi789jkl" https://api.example.com`,
		`curl --header 'authorization: bearer ghp_1234567890abcdefghijklmnopqr'`,
		`http POST api.example.com Authorization:"Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"`,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			res := r.Scan(cmd)
			if res.Decision != Skip {
				t.Errorf("Decision = %v, want Skip; reason=%q", res.Decision, res.SkipReason)
			}
		})
	}
}

func TestSkip_AnthropicKey(t *testing.T) {
	r := New(nil, nil)
	res := r.Scan(`export ANTHROPIC_API_KEY=sk-ant-api03-aaabbbcccdddeeefffggghhh`)
	if res.Decision != Skip {
		t.Errorf("Decision = %v, want Skip", res.Decision)
	}
}

func TestSkip_GithubPat(t *testing.T) {
	r := New(nil, nil)
	cases := []string{
		`gh auth login --with-token <<< ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234`,
		`curl -H "Authorization: token github_pat_AAAAAAAAAAAAAAAAAAAA"`,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			if r.Scan(cmd).Decision != Skip {
				t.Errorf("expected Skip")
			}
		})
	}
}

func TestSkip_AWSKey(t *testing.T) {
	r := New(nil, nil)
	if r.Scan(`AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws s3 ls`).Decision != Skip {
		t.Error("expected Skip for AWS access key")
	}
}

func TestSkip_PostgresURI(t *testing.T) {
	r := New(nil, nil)
	cases := []string{
		`psql postgres://user:hunter2@localhost/mydb`,
		`psql postgresql://user:hunter2@db.example.com:5432/prod`,
		`mysql://root:rootpass@127.0.0.1/dev`,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			if r.Scan(cmd).Decision != Skip {
				t.Errorf("expected Skip; got Send")
			}
		})
	}
}

func TestReplace_GenericKeyValue(t *testing.T) {
	r := New(nil, nil)
	cases := []struct {
		cmd             string
		wantKind        string
		wantPlaceholder string
		wantPrefix      string // key prefix that must be preserved
		wantLeak        string // value that must NOT appear in redacted
	}{
		{
			cmd:             `curl -d "api_key=secretvalue123" https://api.example.com`,
			wantKind:        "generic-api-key",
			wantPlaceholder: "<REDACTED-API-KEY>",
			wantPrefix:      "api_key=",
			wantLeak:        "secretvalue123",
		},
		{
			cmd:             `curl -d "password=hunter2"`,
			wantKind:        "generic-password",
			wantPlaceholder: "<REDACTED-PASSWORD>",
			wantPrefix:      "password=",
			wantLeak:        "hunter2",
		},
		{
			cmd:             `TOKEN=abcdef ./run`,
			wantKind:        "generic-token",
			wantPlaceholder: "<REDACTED-TOKEN>",
			wantPrefix:      "TOKEN=",
			wantLeak:        "abcdef",
		},
		{
			cmd:             `SECRET=topsecret123 ./run`,
			wantKind:        "generic-secret",
			wantPlaceholder: "<REDACTED-SECRET>",
			wantPrefix:      "SECRET=",
			wantLeak:        "topsecret123",
		},
		{
			cmd:             `curl -H "X-API-Key: test-api-key-12345" http://localhost:8090/mcp`,
			wantKind:        "generic-api-key",
			wantPlaceholder: "<REDACTED-API-KEY>",
			wantPrefix:      "API-Key:",
			wantLeak:        "test-api-key-12345",
		},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			res := r.Scan(tc.cmd)
			if res.Decision != Send {
				t.Fatalf("Decision = %v (reason=%q), want Send", res.Decision, res.SkipReason)
			}
			if !strings.Contains(res.Redacted, tc.wantPlaceholder) {
				t.Errorf("Redacted = %q (missing %s)", res.Redacted, tc.wantPlaceholder)
			}
			if !strings.Contains(res.Redacted, tc.wantPrefix) {
				t.Errorf("Redacted = %q (missing prefix %q — key name should be preserved)", res.Redacted, tc.wantPrefix)
			}
			if strings.Contains(res.Redacted, tc.wantLeak) {
				t.Errorf("Redacted = %q (leaked %q)", res.Redacted, tc.wantLeak)
			}
			found := false
			for _, k := range res.ReplacedKinds {
				if k == tc.wantKind {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("ReplacedKinds = %v, missing %q", res.ReplacedKinds, tc.wantKind)
			}
		})
	}
}

// Regression: high-entropy tokens embedded in a generic key=value shape
// must still Skip (specific SKIP pattern runs before generic REPLACE).
func TestSpecificPatternsSkipInsideGenericShape(t *testing.T) {
	r := New(nil, nil)
	cases := []string{
		`curl -d "api_key=sk-ant-api03-realtokenaaabbbcccdddeee"`,   // anthropic inside api_key=
		`curl -d "token=ghp_1234567890abcdefghijklmnopqr"`,           // github PAT inside token=
		`curl -d "secret=AKIAIOSFODNN7EXAMPLE"`,                      // AWS inside secret=
		`curl -d "password=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.sig-abc-def-ghi"`, // JWT inside password=
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			res := r.Scan(cmd)
			if res.Decision != Skip {
				t.Errorf("Decision = %v (redacted=%q), want Skip — specific pattern should have fired before generic", res.Decision, res.Redacted)
			}
		})
	}
}

// Custom proprietary token that doesn't match any specific high-entropy
// pattern. Previously SKIP via generic-api-key, now REPLACE: value must
// not leak to the LLM.
func TestReplace_CustomHighEntropyToken_NotLeaked(t *testing.T) {
	r := New(nil, nil)
	leak := "acme_live_a7f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5"
	cmd := `curl -H "X-API-Key: ` + leak + `" https://api.example.com`
	res := r.Scan(cmd)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	if strings.Contains(res.Redacted, leak) {
		t.Errorf("Redacted = %q — leaked proprietary token %q", res.Redacted, leak)
	}
	if !strings.Contains(res.Redacted, "<REDACTED-API-KEY>") {
		t.Errorf("Redacted = %q — missing placeholder", res.Redacted)
	}
}

func TestReplace_MultipleGenericMatches(t *testing.T) {
	r := New(nil, nil)
	cmd := `./cli --api_key=alpha123 --password=beta456 --token=gamma789`
	res := r.Scan(cmd)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	for _, leak := range []string{"alpha123", "beta456", "gamma789"} {
		if strings.Contains(res.Redacted, leak) {
			t.Errorf("Redacted = %q — leaked %q", res.Redacted, leak)
		}
	}
	for _, kind := range []string{"generic-api-key", "generic-password", "generic-token"} {
		found := false
		for _, k := range res.ReplacedKinds {
			if k == kind {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ReplacedKinds = %v, missing %q", res.ReplacedKinds, kind)
		}
	}
}

// Quoted value forms — the regex must handle shell-quoted values
// (api_key="val", api_key='val') and JSON-style ("api_key":"val").
// Without quote support in the regex, the value leaks to the LLM
// because [^\s'"]+ cannot match the opening quote and the whole
// pattern fails.
func TestReplace_QuotedValues(t *testing.T) {
	r := New(nil, nil)
	cases := []struct {
		cmd  string
		leak string
	}{
		{`api_key="secretvalue123"`, "secretvalue123"},
		{`api_key='secretvalue123'`, "secretvalue123"},
		{`curl -d '{"api_key":"secretvalue123"}' https://api.example.com`, "secretvalue123"},
		{`curl -d "{'api_key':'secretvalue123'}" https://api.example.com`, "secretvalue123"},
		{`api_key: "secretvalue123"`, "secretvalue123"},
		{`password="hunter2supersecret"`, "hunter2supersecret"},
		{`{"password": "hunter2supersecret"}`, "hunter2supersecret"},
		{`TOKEN="literal-token-value-xyz"`, "literal-token-value-xyz"},
		{`secret='topsecret-with-dashes'`, "topsecret-with-dashes"},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			res := r.Scan(tc.cmd)
			if res.Decision != Send {
				t.Fatalf("Decision = %v (reason=%q), want Send", res.Decision, res.SkipReason)
			}
			if strings.Contains(res.Redacted, tc.leak) {
				t.Errorf("Redacted = %q — LEAKED value %q", res.Redacted, tc.leak)
			}
			if !strings.Contains(res.Redacted, "<REDACTED-") {
				t.Errorf("Redacted = %q — no placeholder substituted", res.Redacted)
			}
		})
	}
}

// Shell-var refs inside quoted shapes must still be preserved, not
// replaced. The LLM sees $VAR, not a placeholder.
func TestReplace_QuotedShellVarRefPreserved(t *testing.T) {
	r := New(nil, nil)
	cases := []struct {
		cmd     string
		wantVar string
	}{
		{`api_key="$MY_KEY"`, "$MY_KEY"},
		{`api_key="${MY_KEY}"`, "${MY_KEY}"},
		{`curl -d '{"api_key":"$MY_KEY"}'`, "$MY_KEY"},
		{`password="$PW"`, "$PW"},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			res := r.Scan(tc.cmd)
			if res.Decision != Send {
				t.Fatalf("Decision = %v, want Send", res.Decision)
			}
			if !strings.Contains(res.Redacted, tc.wantVar) {
				t.Errorf("Redacted = %q — literal %q should be preserved", res.Redacted, tc.wantVar)
			}
			if strings.Contains(res.Redacted, "<REDACTED-") {
				t.Errorf("Redacted = %q — should NOT substitute shell-var ref", res.Redacted)
			}
		})
	}
}

// When the only match in a command is a shell-var ref (which we
// preserve), the kind must NOT appear in ReplacedKinds — nothing was
// actually redacted.
func TestReplace_OnlyShellVarRef_KindNotRecorded(t *testing.T) {
	r := New(nil, nil)
	cmd := `curl -d "api_key=$MY_KEY" https://api.example.com`
	res := r.Scan(cmd)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	for _, k := range res.ReplacedKinds {
		if k == "generic-api-key" {
			t.Errorf("ReplacedKinds = %v — should NOT include generic-api-key when only a shell-var ref matched", res.ReplacedKinds)
		}
	}
}

// The (?i) flag and [_-]? class must handle API_KEY, API-KEY, api_key, apiKey.
func TestReplace_CaseAndSeparatorVariants(t *testing.T) {
	r := New(nil, nil)
	cases := []string{
		`API_KEY=abc123`,
		`API-KEY=abc123`,
		`apikey=abc123`,
		`ApiKey=abc123`,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			res := r.Scan(cmd)
			if res.Decision != Send {
				t.Fatalf("Decision = %v, want Send", res.Decision)
			}
			if strings.Contains(res.Redacted, "abc123") {
				t.Errorf("Redacted = %q — leaked value", res.Redacted)
			}
			if !strings.Contains(res.Redacted, "<REDACTED-API-KEY>") {
				t.Errorf("Redacted = %q — missing placeholder", res.Redacted)
			}
		})
	}
}

func TestSkip_PrivateKey(t *testing.T) {
	r := New(nil, nil)
	cmd := `echo "-----BEGIN RSA PRIVATE KEY-----" >> ~/.ssh/id_rsa`
	if r.Scan(cmd).Decision != Skip {
		t.Error("expected Skip for PEM private key marker")
	}
}

func TestSkip_JWT(t *testing.T) {
	r := New(nil, nil)
	cmd := `curl -H "Auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
	if r.Scan(cmd).Decision != Skip {
		t.Error("expected Skip for JWT")
	}
}

func TestReplace_Email(t *testing.T) {
	r := New(nil, nil)
	res := r.Scan(`gh issue create --assignee robin@us2.nl --title "bug"`)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	if !strings.Contains(res.Redacted, "<REDACTED-EMAIL>") {
		t.Errorf("Redacted = %q (no email placeholder)", res.Redacted)
	}
	if strings.Contains(res.Redacted, "robin@us2.nl") {
		t.Errorf("Redacted = %q (email leaked)", res.Redacted)
	}
}

func TestReplace_UUID(t *testing.T) {
	r := New(nil, nil)
	res := r.Scan(`curl https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000`)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	if !strings.Contains(res.Redacted, "<REDACTED-UUID>") {
		t.Errorf("Redacted = %q (no uuid placeholder)", res.Redacted)
	}
}

func TestReplace_IPv4(t *testing.T) {
	r := New(nil, nil)
	res := r.Scan(`ssh user@192.168.1.42 ls`)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	if !strings.Contains(res.Redacted, "<REDACTED-IPV4>") {
		t.Errorf("Redacted = %q", res.Redacted)
	}
}

func TestSafe_NoMatchPassesThrough(t *testing.T) {
	r := New(nil, nil)
	cases := []string{
		`git status`,
		`ls -la /tmp`,
		`cat /etc/hosts | grep localhost`,
		`go test ./...`,
		`make build`,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			res := r.Scan(cmd)
			if res.Decision != Send {
				t.Errorf("Decision = %v, want Send (no patterns)", res.Decision)
			}
			if res.Redacted != cmd {
				t.Errorf("Redacted = %q, want %q (no replacement)", res.Redacted, cmd)
			}
		})
	}
}

func TestExtraPatternsAreAdditive(t *testing.T) {
	// User adds a custom skip pattern. Defaults must still be present.
	custom := []PatternSpec{{Name: "internal-token", Regex: `INTERNAL-[A-Z0-9]{8}`}}
	r := New(MustCompilePatterns(custom), nil)

	// Custom pattern fires
	if r.Scan(`call --token INTERNAL-AB12CD34`).Decision != Skip {
		t.Error("custom skip pattern should have fired")
	}
	// Default still fires
	if r.Scan(`curl -H "Authorization: Bearer foo"`).Decision != Skip {
		t.Error("default skip pattern should have fired")
	}
}

func TestSkip_RecordsReason(t *testing.T) {
	r := New(nil, nil)
	res := r.Scan(`AKIAIOSFODNN7EXAMPLE`)
	if res.SkipReason == "" {
		t.Error("SkipReason should be populated")
	}
	if !strings.Contains(res.SkipReason, "aws") {
		t.Errorf("SkipReason = %q, want something AWS-related", res.SkipReason)
	}
}

// --- Shell variable references: literal text contains no secret,
// only a $VAR reference the shell expands at exec time. Sending
// these to the LLM is safe because the secret never appears in the
// literal command string. ---

func TestShellVarRef_BearerWithVar_NotSkipped(t *testing.T) {
	r := New(nil, nil)
	cmd := `curl -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com/zones`
	res := r.Scan(cmd)
	if res.Decision == Skip {
		t.Errorf("Authorization: Bearer $VAR should NOT be skipped; only the var name is in the literal command (got skip reason=%q)", res.SkipReason)
	}
}

func TestShellVarRef_BearerWithBraces_NotSkipped(t *testing.T) {
	r := New(nil, nil)
	cmd := `curl -H "Authorization: Bearer ${CF_TOKEN}" https://api.example.com`
	if r.Scan(cmd).Decision == Skip {
		t.Error(`Bearer ${VAR} form should also be exempt`)
	}
}

func TestShellVarRef_GenericKeyWithVar_NotSkipped(t *testing.T) {
	r := New(nil, nil)
	cmd := `curl -d "api_key=$MY_KEY" https://api.example.com`
	if r.Scan(cmd).Decision == Skip {
		t.Error(`api_key=$VAR should NOT be skipped`)
	}
}

// Shell-var refs through REPLACE: value portion is just $VAR, no secret
// in literal text. Must NOT be substituted — the literal is safer and
// more informative for the LLM than a placeholder.
func TestShellVarRef_GenericKey_LiteralPreserved(t *testing.T) {
	r := New(nil, nil)
	cmd := `curl -d "api_key=$MY_KEY" https://api.example.com`
	res := r.Scan(cmd)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	if !strings.Contains(res.Redacted, "$MY_KEY") {
		t.Errorf("Redacted = %q — literal $MY_KEY should be preserved (no secret in literal text)", res.Redacted)
	}
	if strings.Contains(res.Redacted, "<REDACTED-API-KEY>") {
		t.Errorf("Redacted = %q — should NOT substitute shell-var ref", res.Redacted)
	}
}

func TestShellVarRef_GenericKey_Braces_LiteralPreserved(t *testing.T) {
	r := New(nil, nil)
	cmd := `curl -d "api_key=${MY_KEY}" https://api.example.com`
	res := r.Scan(cmd)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	if !strings.Contains(res.Redacted, "${MY_KEY}") {
		t.Errorf("Redacted = %q — literal ${MY_KEY} should be preserved", res.Redacted)
	}
}

func TestShellVarRef_RealBearerStillSkipped(t *testing.T) {
	// Regression: the real token case must still be skipped.
	r := New(nil, nil)
	cmd := `curl -H "Authorization: Bearer sk-ant-abc123def456ghi789jkl" https://api.anthropic.com`
	res := r.Scan(cmd)
	if res.Decision != Skip {
		t.Errorf("real Bearer token must be skipped; got Decision=%v", res.Decision)
	}
}

// Previously SKIP; now REPLACE must substitute the literal value so it
// never reaches the LLM. This is the core guarantee of the change:
// real secret values are redacted, not sent as literals.
func TestReplace_RealApiKeyLiteralRedactedNotLeaked(t *testing.T) {
	r := New(nil, nil)
	cmd := `curl -d "api_key=literal-value-12345" https://api.example.com`
	res := r.Scan(cmd)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	if strings.Contains(res.Redacted, "literal-value-12345") {
		t.Errorf("Redacted = %q — literal value MUST be substituted", res.Redacted)
	}
	if !strings.Contains(res.Redacted, "<REDACTED-API-KEY>") {
		t.Errorf("Redacted = %q — missing placeholder", res.Redacted)
	}
	if !strings.Contains(res.Redacted, "api_key=") {
		t.Errorf("Redacted = %q — key prefix should be preserved", res.Redacted)
	}
}

func TestShellVarRef_IsShellVarReference(t *testing.T) {
	cases := []struct {
		matched string
		want    bool
	}{
		{"Authorization: Bearer $CF_TOKEN", true},
		{"Authorization: Bearer ${CF_TOKEN}", true},
		{"authorization: Bearer $foo", true},
		{`Authorization: Bearer "$CF"`, true},
		{"api_key=$KEY", true},
		{"api_key=${KEY}", true},
		{"password=$PW", true},
		{"Authorization: Bearer sk-ant-real-token", false},
		{"api_key=actual-literal-value", false},
		{"Authorization: Bearer $(command)", false},      // command substitution — conservative
		{"Authorization: Bearer $VAR$OTHER", false},      // multiple vars concatenated — conservative
		{"Authorization: Bearer prefix$VAR", false},      // var embedded in literal — conservative
	}
	for _, tc := range cases {
		got := isShellVarReference(tc.matched)
		if got != tc.want {
			t.Errorf("isShellVarReference(%q) = %v, want %v", tc.matched, got, tc.want)
		}
	}
}

func TestReplacedKindsListed(t *testing.T) {
	r := New(nil, nil)
	res := r.Scan(`curl https://192.168.1.1/users/550e8400-e29b-41d4-a716-446655440000?email=robin@us2.nl`)
	if res.Decision != Send {
		t.Fatalf("Decision = %v, want Send", res.Decision)
	}
	// Should have kinds for email, ipv4, uuid
	want := map[string]bool{"email": true, "ipv4": true, "uuid": true}
	for _, k := range res.ReplacedKinds {
		delete(want, k)
	}
	if len(want) > 0 {
		t.Errorf("missing replaced kinds: %v (got %v)", want, res.ReplacedKinds)
	}
}
