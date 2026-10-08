package agentcontext

import "strings"

// A session directory can retain earlier generations after a format upgrade.
// Compare decimal strings so even an unknown, oversized generation prevents
// silently falling back to an older supported log.
func deepseekGeneration(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".zstd")
	if !strings.HasPrefix(name, "session.v") || !strings.HasSuffix(name, ".jsonl") {
		return "", false
	}
	version := strings.TrimSuffix(strings.TrimPrefix(name, "session.v"), ".jsonl")
	if version == "" {
		return "", false
	}
	for _, digit := range version {
		if digit < '0' || digit > '9' {
			return "", false
		}
	}
	version = strings.TrimLeft(version, "0")
	if version == "" {
		version = "0"
	}
	return version, true
}

func newerGeneration(a, b string) bool {
	return len(a) > len(b) || len(a) == len(b) && a > b
}
