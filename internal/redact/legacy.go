package redact

import "regexp"

// This file freezes the masking rule set of v0.10.0 (commit a80af7d) as
// RedactLegacy. It exists ONLY so that evidence produced and signed under the
// v0.10.0 rules remains verifiable after the rules were tightened: the signed
// record_manifest objects inside shipped bundles were masked with these exact
// rules, so comparing a rebuild against such an object must reproduce the same
// masking. DO NOT extend or "fix" the patterns here — every change to masking
// belongs in redact.go (current rules), which all capture/display paths use.
// New evidence is always masked with the current rules; the legacy set is a
// compatibility shim for verification of historical artifacts, nothing else.

// legacyTokenRes is the v0.10.0 anchored provider-token pattern set.
var legacyTokenRes = []*regexp.Regexp{
	// OpenAI / Anthropic / DeepSeek and compatibles: sk-, sk-ant-, sk-proj-…
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`),
	// GitHub personal/OAuth/app/refresh/server tokens.
	regexp.MustCompile(`gh[porsu]_[A-Za-z0-9]{20,}`),
	// GitLab personal access tokens.
	regexp.MustCompile(`glpat-[A-Za-z0-9_-]{16,}`),
	// Slack tokens.
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
	// AWS access key id.
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	// Google API key.
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	// Hugging Face user access token.
	regexp.MustCompile(`hf_[A-Za-z0-9]{30,}`),
	// PEM private key block (complete BEGIN+END pairs only).
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
}

// legacyKvSecretRe is the v0.10.0 key/value secret pattern.
var legacyKvSecretRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|authorization)(["']?\s*[:=]\s*["']?)(?:(bearer|basic)\s+)?([^\s"',}\\]{6,})`)

// RedactLegacy masks secrets in s exactly as v0.10.0 did and reports whether
// anything was replaced. See the file comment: frozen compatibility shim for
// verifying historical evidence, never used on newly captured data.
func RedactLegacy(s string) (string, bool) {
	changed := false
	for _, re := range legacyTokenRes {
		if re.MatchString(s) {
			s = re.ReplaceAllString(s, mask)
			changed = true
		}
	}
	if legacyKvSecretRe.MatchString(s) {
		out := legacyKvSecretRe.ReplaceAllStringFunc(s, func(m string) string {
			g := legacyKvSecretRe.FindStringSubmatch(m)
			// g[4] already == mask when a token pattern replaced it above;
			// avoid double-masking and avoid masking our own placeholder.
			if g[4] == mask {
				return m
			}
			scheme := ""
			if g[3] != "" {
				scheme = g[3] + " "
			}
			return g[1] + g[2] + scheme + mask
		})
		if out != s {
			s = out
			changed = true
		}
	}
	return s, changed
}
