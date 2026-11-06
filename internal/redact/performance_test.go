package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialKeyPrefilterPreservesMatches(t *testing.T) {
	for _, key := range []string{
		"authorization", "passphrase", "pass_phrase", "secret_access_key", "access_key_id",
		"client-secret", "secret.key", "private_key", "public.key", "api_key", "access-key",
		"refresh.token", "session_token", "password", "passwd", "credential", "credentials",
		"secret", "secrets", "token", "auth", "pwd", "pa\u017f\u017fword", "api_\u212aey",
	} {
		for _, variant := range []string{key, strings.ToUpper(key)} {
			for _, sep := range []string{"=", ":", "\" \t:\n\"", "'='"} {
				input := variant + sep + "synthetic-credential"
				if !kvKeySepRe.MatchString(input) {
					t.Fatalf("fixture does not match credential rule: %q", input)
				}
				if !mayContainCredentialKey(input) {
					t.Fatalf("prefilter rejected a credential rule match: %q", input)
				}
			}
		}
	}
}

func FuzzCredentialKeyPrefilter(f *testing.F) {
	for _, seed := range []string{"password=value", "AUTH: Bearer example", "api_\u212aey=sample", "pa\u017f\u017fword=x", "ordinary saved output"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if kvKeySepRe.MatchString(input) && !mayContainCredentialKey(input) {
			t.Fatal("prefilter rejected a credential rule match")
		}
	})
}

func TestRedactLargeBodyPreservesLateCredentials(t *testing.T) {
	prefix := strings.Repeat("saved historical line\n", 6000)
	for _, secret := range []string{
		"password=synthetic-credential\n",
		"redis://:synthetic-credential@cache.example/0\n",
		"https://example.test/?key=synthetic-credential&mode=read\n",
	} {
		body := prefix + secret + "END-OF-EVIDENCE"
		want := prefix + RedactString(secret) + "END-OF-EVIDENCE"
		raw, err := json.Marshal(map[string]string{"content": body})
		if err != nil {
			t.Fatal(err)
		}
		out, changed := Redact(string(raw))
		var got map[string]string
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		if !changed || got["content"] != want || strings.Contains(out, "synthetic-credential") {
			t.Fatal("large-body masking lost evidence or retained a late credential")
		}
	}
}

func BenchmarkRedactSavedBody(b *testing.B) {
	body := strings.Repeat("saved historical line\n", 6000)
	raw, err := json.Marshal(map[string]string{"content": body})
	if err != nil {
		b.Fatal(err)
	}
	for name, input := range map[string]string{"text": body, "json": string(raw)} {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(input)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if got, changed := Redact(input); changed || got != input {
					b.Fatal("ordinary evidence changed")
				}
			}
		})
	}
}
