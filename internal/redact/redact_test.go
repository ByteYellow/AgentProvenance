package redact

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRedactQuotedCommandsAcrossJSONLayers(t *testing.T) {
	for _, command := range []string{
		`export SERVICE_API_KEY="${SERVICE_API_KEY:-$BACKUP_TOKEN}"; exec worker --dry-run`,
		`upload --password="correct horse battery staple" --dry-run`,
		`upload --password='correct horse battery staple' --dry-run`,
		`{"authorization":"Bearer opaque-token-value","operation":"inspect"}`,
	} {
		want := RedactString(command)
		if want == command {
			t.Fatalf("fixture did not trigger masking: %q", command)
		}
		for depth := 1; depth <= 3; depth++ {
			t.Run(fmt.Sprintf("%s/depth-%d", command, depth), func(t *testing.T) {
				in := command
				for i := 0; i < depth; i++ {
					raw, err := json.Marshal(map[string]string{"command": in, "id": "keep-this-id"})
					if err != nil {
						t.Fatal(err)
					}
					in = string(raw)
				}
				masked := RedactString(in)
				if again, changed := Redact(masked); changed || again != masked {
					t.Fatalf("masking is not idempotent: %q", masked)
				}
				out := masked
				for i := 0; i < depth; i++ {
					var decoded map[string]string
					if err := json.Unmarshal([]byte(out), &decoded); err != nil {
						t.Fatalf("invalid JSON at layer %d: %v", i, err)
					}
					if decoded["id"] != "keep-this-id" {
						t.Fatal("unrelated identifier changed")
					}
					out = decoded["command"]
				}
				if out != want {
					t.Fatalf("different masking after JSON serialization: got %q, want %q", out, want)
				}
			})
		}
	}
}

// The literal key shape that actually leaked into the committed demo bundles
// (a DeepSeek key: sk- + 32 hex). Kept as a test fixture so a regression that
// stops masking it fails loudly.
const leakedKey = "sk-003fe97861dc48ebba10d6d391e4cebe"

func TestRedactCatchesLeakInEverySerialization(t *testing.T) {
	cases := map[string]string{
		"joined command": `curl .../v1/messages -H content-type: application/json -H x-api-key: ` + leakedKey + ` --data-binary @/tmp/x`,
		"argv array":     `{"argv":["-H","x-api-key:","` + leakedKey + `","--data-binary"]}`,
		"bearer header":  `authorization: Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345`,
		"json body":      `{"model":"claude","api_key":"` + leakedKey + `"}`,
	}
	for name, in := range cases {
		out, changed := Redact(in)
		if !changed {
			t.Errorf("%s: nothing redacted", name)
		}
		if strings.Contains(out, leakedKey) {
			t.Errorf("%s: leaked key survived: %q", name, out)
		}
		if strings.Contains(out, "sk-ant-api03") {
			t.Errorf("%s: bearer token survived: %q", name, out)
		}
	}
}

func TestRedactKeepsBearerScheme(t *testing.T) {
	out, _ := Redact(`authorization: Bearer sk-secretsecretsecret123456`)
	if !strings.Contains(out, "Bearer") {
		t.Errorf("scheme should be preserved, got %q", out)
	}
	if strings.Contains(out, "secretsecret") {
		t.Errorf("token should be masked, got %q", out)
	}
}

func TestRedactDoesNotTouchNonSecrets(t *testing.T) {
	// Policy detection targets must survive untouched, or redaction would blind
	// the very signals the graph exists to produce.
	keep := []string{
		"connect 169.254.169.254",
		"openat /home/agent/.aws/credentials",
		`{"model":"claude-opus-4-8","tools_offered":["bash","read_file"]}`,
		"python3 ../pysnake-helper/setup.py install --user",
	}
	for _, s := range keep {
		out, changed := Redact(s)
		if changed || out != s {
			t.Errorf("false positive on %q -> %q", s, out)
		}
	}
}

func TestRedactPreservesJSONStructure(t *testing.T) {
	in := `{"raw":{"command":"curl -H x-api-key: ` + leakedKey + `","comm":"curl","argv":["curl"]}}`
	out, _ := Redact(in)
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("redacted payload is no longer valid JSON: %v\n%s", err, out)
	}
	if strings.Contains(out, leakedKey) {
		t.Errorf("key survived: %q", out)
	}
}

// A secret embedded in an ESCAPED JSON string (e.g. an LLM request body stored as
// a string field of a provenance object) is immediately followed by a \" escape.
// Redaction must mask the secret without consuming the backslash — otherwise the
// following quote becomes structural and the whole object is corrupted.
func TestRedactPreservesEscapedJSONString(t *testing.T) {
	in := `{"content":"env: access_key=FAKE-secret-do-not-use\",\"role\":\"user\"","semantics":{"host":"api.x.ai"}}`
	out, _ := Redact(in)
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("redacted escaped-JSON payload is no longer valid JSON: %v\n%s", err, out)
	}
	if strings.Contains(out, "FAKE-secret-do-not-use") {
		t.Errorf("secret survived redaction: %q", out)
	}
}

func TestRedactHeadersMasksByName(t *testing.T) {
	h := map[string]string{
		"X-Api-Key":     leakedKey,
		"Authorization": "Bearer abc123def456",
		"Content-Type":  "application/json",
		"Host":          "api.anthropic.com",
	}
	if !RedactHeaders(h) {
		t.Fatal("expected headers to be masked")
	}
	if h["X-Api-Key"] == leakedKey || strings.Contains(h["Authorization"], "abc123") {
		t.Errorf("credential header not masked: %+v", h)
	}
	if h["Content-Type"] != "application/json" || h["Host"] != "api.anthropic.com" {
		t.Errorf("non-credential headers must be untouched: %+v", h)
	}
}

func TestRedactIdempotent(t *testing.T) {
	once, _ := Redact(`x-api-key: ` + leakedKey)
	twice, changed := Redact(once)
	if changed || twice != once {
		t.Errorf("second pass changed already-redacted text: %q -> %q", once, twice)
	}
}

// --- Advisory regression tests (H4, M1..M6) ---
// Each test asserts the PoC input from the corresponding advisory is fully
// masked and that ordinary surrounding text stays readable/valid.

// H4: a truncated PEM (BEGIN + body, no END) must be masked from the marker to
// the end of the key material; complete blocks keep working.
func TestRedactTruncatedPEMPrivateKey(t *testing.T) {
	truncated := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7X9qL2mN8pQrStUvWxYz"
	out, changed := Redact(truncated)
	if !changed || strings.Contains(out, "MIIEpA") || strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("truncated PEM survived: changed=%v out=%q", changed, out)
	}

	// single-line E2E shape from the advisory (argv of a recorded command)
	cmd := `deploy --private-key -----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA7X9qL2mN8pQrStUvWxYz`
	out, changed = Redact(cmd)
	if !changed || strings.Contains(out, "MIIEpA") {
		t.Fatalf("single-line truncated PEM survived: %q", out)
	}

	// embedded in a JSON payload: body gone and document stays valid
	embedded := `{"command":["sh","-c","deploy --private-key -----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA7X9qL2mN8pQrStUvWxYz"]}`
	out, _ = Redact(embedded)
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("embedded truncated PEM broke JSON: %v\n%s", err, out)
	}
	if strings.Contains(out, "MIIEpA") {
		t.Fatalf("embedded truncated PEM body survived: %q", out)
	}

	// complete blocks are still masked in full
	full := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7X9qL2mN8pQrStUvWxYz0A1B2C3D4E5F6G7H8I9\n-----END RSA PRIVATE KEY-----"
	out, changed = Redact(full)
	if !changed || strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, "MIIEpA") {
		t.Fatalf("complete PEM not masked: %q", out)
	}
}

// M1: GitHub fine-grained personal access tokens.
func TestRedactGitHubFineGrainedPAT(t *testing.T) {
	in := "git push with token github_pat_11ABcdEF0aBcDeFgHiJkLm_3xJmQpV7nRtWzY2kL5hG8dF0sBvCcXaNmMoPqQrStUv"
	out, changed := Redact(in)
	if !changed || strings.Contains(out, "github_pat_") {
		t.Fatalf("fine-grained PAT survived: changed=%v out=%q", changed, out)
	}
}

// M2: AWS STS temporary credentials (ASIA/ABIA/ACCA) and the standard
// suffixed secret-key name.
func TestRedactAWSSTSCredentials(t *testing.T) {
	for _, in := range []string{
		"aws sts get-caller-credentials ASIAIOSFODNN7EXAMPLE",
		"token=ABIAIOSFODNN7EXAMPLE",
		"credential=ACCAIOSFODNN7EXAMPLE",
	} {
		out, changed := Redact(in)
		if !changed || strings.Contains(out, "IOSFODNN7") {
			t.Fatalf("STS key survived %q -> %q (changed=%v)", in, out, changed)
		}
	}
	in := "aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCY"
	out, changed := Redact(in)
	if !changed || strings.Contains(out, "wJalrXUtnFEMI") {
		t.Fatalf("aws_secret_access_key value survived: %q", out)
	}
}

// M3: kv values that are nested JSON objects/arrays are masked in full.
func TestRedactNestedJSONValues(t *testing.T) {
	for _, in := range []string{
		`{"tool":"db_query","password":{"enc":"TopSecretPayload123"}}`,
		`{"password":["Hunter2SecretValue"]}`,
	} {
		out, changed := Redact(in)
		if !changed {
			t.Fatalf("nested value not redacted: %s", in)
		}
		var v any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("nested redaction broke JSON %q: %v", out, err)
		}
		if strings.Contains(out, "TopSecretPayload123") || strings.Contains(out, "Hunter2SecretValue") {
			t.Fatalf("nested secret survived: %q", out)
		}
	}
}

// M4: common secret key-name variants.
func TestRedactSecretKeyVariants(t *testing.T) {
	cases := []struct{ in, leak string }{
		{`{"secret_key":"Pl41nV4lue123456"}`, "Pl41nV4lue123456"},
		{`{"private_key":"Pl41nV4lue123456"}`, "Pl41nV4lue123456"},
		{`{"pwd":"Pl41nV4lue123456"}`, "Pl41nV4lue123456"},
		{`{"passphrase":"mykeypass77"}`, "mykeypass77"},
		{`{"api.key":"dotkey123456"}`, "dotkey123456"},
		{"db secret_key=Pl41nV4lue123456 enabled", "Pl41nV4lue123456"},
	}
	for _, c := range cases {
		out, changed := Redact(c.in)
		if !changed || strings.Contains(out, c.leak) {
			t.Fatalf("variant not redacted %q -> %q (changed=%v)", c.in, out, changed)
		}
		if strings.HasPrefix(c.in, "{") {
			var v any
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("variant redaction broke JSON %q: %v", out, err)
			}
		}
	}
}

// M5: passwords containing spaces are masked in full, not just the first chunk.
func TestRedactSpacedPasswordsFullyMasked(t *testing.T) {
	out, changed := Redact(`db_password = "correct horse battery staple"`)
	if !changed || strings.Contains(out, "horse battery staple") || strings.Contains(out, "battery") {
		t.Fatalf("quoted spaced password partially kept: %q", out)
	}
	out, changed = Redact(`{"password":"correct horse battery staple"}`)
	if !changed || strings.Contains(out, "battery staple") {
		t.Fatalf("JSON spaced password partially kept: %q", out)
	}
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("spaced-password redaction broke JSON: %v\n%s", err, out)
	}
	// bare command-line form: everything up to end of line is masked
	out, _ = Redact("upload --password=correct horse battery staple --quiet")
	if strings.Contains(out, "battery") || strings.Contains(out, "horse") {
		t.Fatalf("unquoted spaced password kept: %q", out)
	}
}

// M6: URL userinfo credentials and bare query-string secrets.
func TestRedactURLCredentials(t *testing.T) {
	out, changed := Redact("git clone https://admin:Sup3rS3cretPw@internal.example.com/team/repo.git")
	if !changed || strings.Contains(out, "Sup3rS3cretPw") {
		t.Fatalf("userinfo credential survived: %q", out)
	}
	if !strings.Contains(out, "internal.example.com/team/repo.git") {
		t.Fatalf("URL host/path must stay readable: %q", out)
	}
	out, changed = Redact(`curl "https://api.internal.example.com/v1/lookup?key=Pl41nQuryK3yValue09876"`)
	if !changed || strings.Contains(out, "Pl41nQuryK3yValue09876") {
		t.Fatalf("query key value survived: %q", out)
	}
	if !strings.Contains(out, "api.internal.example.com/v1/lookup?key=") {
		t.Fatalf("query key name must stay readable: %q", out)
	}
	// empty-username userinfo (redis/postgres style)
	out, changed = Redact("redis://:Sup3rS3cretPw@cache.internal:6379/0")
	if !changed || strings.Contains(out, "Sup3rS3cretPw") {
		t.Fatalf("empty-user userinfo survived: %q", out)
	}
}

// Every new masking direction must leave ordinary URLs, hosts and config data
// readable — redaction must not blind the evidence.
func TestRedactKeepsOrdinaryURLsAndConfigs(t *testing.T) {
	keep := []string{
		"https://example.com/docs/guide?page=2&sort=asc",
		"http://127.0.0.1:8080/healthz",
		"https://user@example.com/repo.git",
		`{"metadata":{"key":"display-name","version":"1.2.3"}}`,
		"git@github.com:byteyellow/agentprovenance.git",
	}
	for _, s := range keep {
		if out, changed := Redact(s); changed || out != s {
			t.Fatalf("false positive on %q -> %q", s, out)
		}
	}
}

// All seven fixes together must be idempotent: a second pass is a no-op.
func TestRedactAdvisoryFixesIdempotent(t *testing.T) {
	cases := []string{
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7X9qL2mN8pQrStUvWxYz",
		"token github_pat_11ABcdEF0aBcDeFgHiJkLm_3xJmQpV7nRtWzY2kL5hG8dF0sBvCcXaNmMoPqQrStUv",
		"aws sts get-caller-credentials ASIAIOSFODNN7EXAMPLE",
		`{"password":{"enc":"TopSecretPayload123"}}`,
		`db_password = "correct horse battery staple"`,
		"git clone https://admin:Sup3rS3cretPw@internal.example.com/team/repo.git",
		`curl "https://api.internal.example.com/v1/lookup?key=Pl41nQuryK3yValue09876"`,
	}
	for _, in := range cases {
		once, _ := Redact(in)
		twice, changed := Redact(once)
		if changed || twice != once {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}
