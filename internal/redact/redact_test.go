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

func TestSkip_GenericKeyValue(t *testing.T) {
	r := New(nil, nil)
	cases := []string{
		`curl -d "api_key=secretvalue123" https://api.example.com`,
		`curl -d "password=hunter2"`,
		`SECRET=topsecret123 ./run`,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			if r.Scan(cmd).Decision != Skip {
				t.Errorf("expected Skip")
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

func TestShellVarRef_RealBearerStillSkipped(t *testing.T) {
	// Regression: the real token case must still be skipped.
	r := New(nil, nil)
	cmd := `curl -H "Authorization: Bearer sk-ant-abc123def456ghi789jkl" https://api.anthropic.com`
	res := r.Scan(cmd)
	if res.Decision != Skip {
		t.Errorf("real Bearer token must be skipped; got Decision=%v", res.Decision)
	}
}

func TestShellVarRef_RealApiKeyStillSkipped(t *testing.T) {
	r := New(nil, nil)
	cmd := `curl -d "api_key=literal-value-12345" https://api.example.com`
	if r.Scan(cmd).Decision != Skip {
		t.Error("real api_key literal must be skipped")
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
