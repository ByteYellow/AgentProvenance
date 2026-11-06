// Package redact masks secrets out of captured evidence before it is stored,
// materialized into content-addressed objects, or exported into a signed
// forensics bundle.
//
// The threat it addresses is concrete: the sensor captures raw agent activity
// verbatim — an execve's full argv (including a `curl -H "x-api-key: sk-..."`),
// and, once full-TLS-body capture lands, the plaintext of the agent's own LLM
// requests. Any of those can carry a live API key. Evidence flows to many sinks
// (the store, the dashboard, `--json` output, and a SIGNED, shareable bundle),
// so masking has to happen at capture/write time, not only when one sink
// renders — a single un-redacted export is a public leak.
//
// Matching strategy: anchored provider-token patterns are PRIMARY. They key on
// the token's own high-entropy prefix (`sk-`, `ghp_`, `github_pat_`, `ASIA`,
// ...) so they fire regardless of serialization — the same key is caught
// whether it sits in a joined command string (`... x-api-key: sk-123 ...`) or
// an argv array where the header name and value are split across separate JSON
// tokens (`["x-api-key:","sk-123"]`). A key/value pattern is SECONDARY, for
// secrets that lack a recognizable prefix but appear next to a telltale field
// name; that pattern is applied by a scanner (not one regex) so it can also
// consume quoted values containing spaces, whole nested JSON objects/arrays,
// URL userinfo credentials and bare `?key=` query parameters.
package redact

import (
	"encoding/json"
	"regexp"
	"strings"
)

const mask = "***REDACTED***"

// tokenRes are anchored on a provider token's own prefix, so they match no
// matter how the surrounding text is serialized. Order does not matter: each is
// self-contained and they do not overlap destructively.
var tokenRes = []*regexp.Regexp{
	// OpenAI / Anthropic / DeepSeek and compatibles: sk-, sk-ant-, sk-proj-…
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`),
	// GitHub personal/OAuth/app/refresh/server tokens.
	regexp.MustCompile(`gh[porsu]_[A-Za-z0-9]{20,}`),
	// GitHub fine-grained personal access tokens (M1): github_pat_ + version
	// prefix + "_" + secret, all word characters.
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	// GitLab personal access tokens.
	regexp.MustCompile(`glpat-[A-Za-z0-9_-]{16,}`),
	// Slack tokens.
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
	// AWS access key ids: the long-lived AKIA prefix plus the STS-issued ASIA
	// and the ABIA/ACCA issue prefixes (M2).
	regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}`),
	// Google API key.
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	// Hugging Face user access token.
	regexp.MustCompile(`hf_[A-Za-z0-9]{30,}`),
	// Complete PEM private key block. A TRUNCATED block (BEGIN header plus body
	// but no END marker, the common sensor-capture shape) is handled after this
	// pass by maskTruncatedPEMs (H4).
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
}

// pemBeginRe finds the header of a PEM private key block. Complete blocks are
// already masked by tokenRes, so any header left after that pass begins a
// truncated block whose body must be masked too (H4).
var pemBeginRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

// maxTruncatedPEMBytes bounds how much follows a truncated BEGIN marker before
// masking stops; real key bodies are a few KB.
const maxTruncatedPEMBytes = 16 << 10

// kvKeySepRe matches a telltale key name plus its separator, up to and
// including an opening value quote when one is present, so replacements can
// preserve those quotes and keep JSON documents well formed. The key
// alternation is ordered longest-first (leftmost-first semantics) and covers
// the standard suffixed spellings (M4): secret_key, private_key, pwd,
// passphrase, api.key/dot forms, aws_access_key_id, aws_secret_access_key,
// credentials, auth.
var kvKeySepRe = regexp.MustCompile(`(?i)(authorization|pass[_\-.]?phrase|secret[_\-.]?access[_\-.]?key|access[_\-.]?key[_\-.]?id|client[_\-.]?secret|secret[_\-.]?key|private[_\-.]?key|public[_\-.]?key|api[_\-.]?key|access[_\-.]?key|refresh[_\-.]?token|session[_\-.]?token|password|passwd|credentials?|secrets?|token|auth|pwd)(["']?\s*[:=]\s*["']?)`)

// kvSchemeRe strips a Bearer/Basic scheme so the SCHEME is kept and only the
// TOKEN is masked.
var kvSchemeRe = regexp.MustCompile(`(?i)\A(?:bearer|basic)[ \t]+`)

// minKvValueLen keeps the old noise floor: short values next to a telltale key
// are usually not secrets.
const minKvValueLen = 6

// urlUserinfoRe masks the password of `scheme://user:pass@host` URLs (M6). The
// scheme, username and host stay readable. The empty-username form
// (`redis://:pass@host`) is covered by the `*`; the pass class excludes quotes
// and backslashes so a match can never run through a JSON string boundary.
var urlUserinfoRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)([^/\s:@]*):([^@\s"'\\]+)@`)

// urlQueryKeyRe masks bare query-string secrets (M6): `?key=` / `&key=` plus
// the signature variants no other rule covers (api_key/token/secret/password
// are already handled by the kv scanner). The value ends at the next `&`,
// whitespace or quote so the rest of the URL stays readable.
var urlQueryKeyRe = regexp.MustCompile(`(?i)([?&](?:key|signature|sig)=)([^&\s"'}\\]{6,})`)

// kvPlan describes one value span to replace.
type kvPlan struct {
	start  int  // start of the value content to replace (after key+sep+quote/scheme)
	end    int  // end of the span, exclusive
	quoted bool // wrap the replacement in quotes (JSON object/array values)
}

// Redact masks secrets in s and reports whether anything was replaced. It is
// safe to run over a JSON payload string: token patterns match only the secret
// substrings, and the kv/URL scanners stop at quotes, backslashes and
// structural bytes, so the surrounding document stays well-formed.
func Redact(s string) (string, bool) {
	// Mask decoded strings before their enclosing JSON. A command must have the
	// same representation in a table column and a content-addressed object.
	stringsChanged := false
	if json.Valid([]byte(s)) {
		s, stringsChanged = redactJSONStrings(s)
	}
	out, changed := redactText(s)
	return out, stringsChanged || changed
}

func redactJSONStrings(s string) (string, bool) {
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		end := closeQuote(s, i+1, '"') + 1
		var decoded string
		// The caller has validated the complete JSON document.
		if err := json.Unmarshal([]byte(s[i:end]), &decoded); err != nil {
			return s, false
		}
		if masked, changed := Redact(decoded); changed {
			encoded, _ := json.Marshal(masked)
			b.WriteString(s[last:i])
			b.Write(encoded)
			last = end
		}
		i = end - 1
	}
	if last == 0 {
		return s, false
	}
	b.WriteString(s[last:])
	return b.String(), true
}

func redactText(s string) (string, bool) {
	changed := false
	for _, re := range tokenRes {
		if re.MatchString(s) {
			s = re.ReplaceAllString(s, mask)
			changed = true
		}
	}
	if out, c := maskTruncatedPEMs(s); c {
		s, changed = out, true
	}
	if out, c := redactKVs(s); c {
		s, changed = out, true
	}
	if out, c := redactURLCredentials(s); c {
		s, changed = out, true
	}
	return s, changed
}

// maskTruncatedPEMs masks every remaining `-----BEGIN … PRIVATE KEY-----`
// header (complete blocks were already replaced above, so what is left is
// truncated) from the marker to the end of the key material: the next blank
// line, the next quote/backslash (a JSON string boundary; base64 never
// contains either), or the end of the buffer (H4). `\n`-style escapes are
// consumed so multi-line bodies embedded in escaped JSON stay covered.
func maskTruncatedPEMs(s string) (string, bool) {
	changed := false
	for {
		loc := pemBeginRe.FindStringIndex(s)
		if loc == nil {
			return s, changed
		}
		start := loc[0]
		end := pemBodyEnd(s, start, len(s))
		s = s[:start] + mask + s[end:]
		changed = true
	}
}

// pemBodyEnd finds where truncated key material following the BEGIN marker at
// start should stop.
func pemBodyEnd(s string, start, limit int) int {
	i := start
	for i < limit {
		switch c := s[i]; {
		case c == '"':
			return i
		case c == '\n':
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r') {
				j++
			}
			if j >= len(s) || s[j] == '\n' {
				return min(j, limit)
			}
			i = j
		case c == '\\' && i+1 < len(s) && (s[i+1] == 'n' || s[i+1] == 't' || s[i+1] == 'r' || s[i+1] == '\\'):
			i += 2 // consume a line-break escape, the body continues
		case c == '\\':
			return i
		default:
			i++
		}
	}
	return limit
}

// redactKVs walks every telltale key match and masks the whole value that
// follows it: quoted values through their closing quote (M5), nested JSON
// objects/arrays in full (M3), and bare values to end of line (M5).
func redactKVs(s string) (string, bool) {
	matches := kvKeySepRe.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s, false
	}
	var b strings.Builder
	last := 0
	changed := false
	for _, m := range matches {
		keyStart, sepEnd := m[0], m[5]
		if keyStart < last {
			continue // inside an already-masked span
		}
		plan := kvValuePlan(s, sepEnd)
		if plan == nil {
			continue
		}
		if s[plan.start:plan.end] == mask {
			continue // already masked by a token pattern; keep as is
		}
		b.WriteString(s[last:plan.start]) // key, separator, quotes, scheme
		if plan.quoted {
			b.WriteByte('"')
			b.WriteString(mask)
			b.WriteByte('"')
		} else {
			b.WriteString(mask)
		}
		last = plan.end
		changed = true
	}
	if !changed {
		return s, false
	}
	b.WriteString(s[last:])
	return b.String(), true
}

// kvValuePlan locates the value following a key+separator match ending at sep.
// It returns nil when there is nothing value-like to mask.
func kvValuePlan(s string, sep int) *kvPlan {
	if sep >= len(s) {
		return nil
	}
	// Nested JSON object/array (M3): consume the balanced structure.
	if c := s[sep]; c == '{' || c == '[' {
		if end := jsonSpanEnd(s, sep); end > 0 {
			return &kvPlan{start: sep, end: end, quoted: true}
		}
		return nil
	}
	// Quoted value (M5): consume through the closing quote.
	if c := s[sep]; c == '"' || c == '\'' {
		if end := closeQuote(s, sep+1, c); end >= 0 {
			return &kvPlan{start: sep, end: end}
		}
		return &kvPlan{start: sep, end: len(s)} // unterminated: to end of buffer
	}
	// Bare value, optionally after a preserved Bearer/Basic scheme.
	start := sep
	if m := kvSchemeRe.FindStringIndex(s[sep:]); m != nil {
		start = sep + m[1]
		if start >= len(s) {
			return nil
		}
		if c := s[start]; c == '"' || c == '\'' {
			if end := closeQuote(s, start+1, c); end >= 0 {
				return &kvPlan{start: start, end: end}
			}
			return &kvPlan{start: start, end: len(s)}
		}
	}
	// Noise gate on the first non-structural chunk (the old behaviour) …
	n := 0
	for i := start; i < len(s) && !isKvValueStop(s[i]); i++ {
		n++
	}
	if n < minKvValueLen {
		return nil
	}
	// … then extend over spaces/commas to the end of the line (M5), stopping at
	// bytes that would corrupt an escaped JSON string or a URL query.
	end := start
	for end < len(s) && !kvRegionStop(s[end]) {
		end++
	}
	if end == start {
		return nil
	}
	return &kvPlan{start: start, end: end}
}

// isKvValueStop bounds the gate chunk: whitespace and JSON structural bytes.
func isKvValueStop(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '\v', '\f', ',', '"', '\'', '}', '\\':
		return true
	}
	return false
}

// kvRegionStop bounds the extended bare-value region: end of line, a JSON
// string boundary, or a query-string separator.
func kvRegionStop(c byte) bool {
	return c == '"' || c == '\'' || c == '\\' || c == '\r' || c == '\n' || c == '&'
}

// closeQuote returns the index of the first unescaped closing quote of kind q
// at or after i, or -1.
func closeQuote(s string, i int, q byte) int {
	for i < len(s) {
		if s[i] == '\\' {
			i += 2
			continue
		}
		if s[i] == q {
			return i
		}
		i++
	}
	return -1
}

// jsonSpanEnd returns the index just past the balanced `{…}` / `[…]` structure
// opening at start, honouring double-quoted strings with escapes, or -1.
func jsonSpanEnd(s string, start int) int {
	open := s[start]
	closing := byte('}')
	if open == '[' {
		closing = ']'
	}
	depth := 0
	inStr := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case open:
			depth++
		case closing:
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// redactURLCredentials masks credentials embedded in URLs (M6): userinfo
// passwords and bare `?key=`/`?signature=` query values.
func redactURLCredentials(s string) (string, bool) {
	changed := false
	if out := urlUserinfoRe.ReplaceAllStringFunc(s, func(m string) string {
		g := urlUserinfoRe.FindStringSubmatch(m)
		if g[3] == mask {
			return m
		}
		return g[1] + g[2] + ":" + mask + "@"
	}); out != s {
		s, changed = out, true
	}
	if out := urlQueryKeyRe.ReplaceAllStringFunc(s, func(m string) string {
		g := urlQueryKeyRe.FindStringSubmatch(m)
		if g[2] == mask {
			return m
		}
		return g[1] + mask
	}); out != s {
		s, changed = out, true
	}
	return s, changed
}

// RedactString is Redact without the changed flag, for call sites that just want
// the safe string.
func RedactString(s string) string {
	out, _ := Redact(s)
	return out
}

// RedactHeaders masks the values of credential-bearing headers in place and
// reports whether anything was masked. Used by tlsintent on a reassembled HTTP
// message's header map, where masking by name is precise.
func RedactHeaders(headers map[string]string) bool {
	changed := false
	for k := range headers {
		if sensitiveHeaders[canonLower(k)] {
			if headers[k] != mask {
				headers[k] = mask
				changed = true
			}
		}
	}
	return changed
}

// sensitiveHeaders are TLS/HTTP headers whose entire value is a credential.
// tlsintent masks these structurally (by name) rather than by regex, which is
// precise and never touches the message body.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"api-key":             true,
	"cookie":              true,
	"set-cookie":          true,
	"x-goog-api-key":      true,
}

func canonLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
