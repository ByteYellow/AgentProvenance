package dashboard

import "testing"

func TestRedactSecretsMasksSecretShapes(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		leak    string // substring that must NOT survive
		wantRed bool
	}{
		{
			name:    "private key block",
			in:      "key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
			leak:    "b3BlbnNzaC1rZXktdjEAAAAA",
			wantRed: true,
		},
		{name: "aws access key", in: "id = AKIAIOSFODNN7EXAMPLE", leak: "AKIAIOSFODNN7EXAMPLE", wantRed: true},
		{name: "password assignment", in: `{"password":"hunter2supersecret"}`, leak: "hunter2supersecret", wantRed: true},
		{name: "token assignment", in: "ANTHROPIC_AUTH_TOKEN=sk-abc123def456", leak: "sk-abc123def456", wantRed: true},
		{name: "benign code", in: "def move(snake):\n    return snake.head + 1\n", leak: "", wantRed: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, red := redactSecrets(c.in)
			if red != c.wantRed {
				t.Fatalf("redacted=%v want %v (out=%q)", red, c.wantRed, out)
			}
			if c.leak != "" && contains(out, c.leak) {
				t.Fatalf("secret %q survived redaction: %q", c.leak, out)
			}
		})
	}
}

func TestIsBinaryContent(t *testing.T) {
	if !isBinaryContent([]byte{0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01}) {
		t.Fatal("NUL-containing bytes should be binary")
	}
	if isBinaryContent([]byte("print('snake')\n")) {
		t.Fatal("utf-8 text should not be binary")
	}
}

func TestLooksLikeDiff(t *testing.T) {
	if !looksLikeDiff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n") {
		t.Fatal("git diff should be detected")
	}
	if looksLikeDiff(`{"schema":"object"}`) {
		t.Fatal("json should not be a diff")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
