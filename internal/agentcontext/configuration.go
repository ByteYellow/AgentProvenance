package agentcontext

import (
	"encoding/json"
	"strings"
)

// This is field presence in source snapshots, not a merged effective policy.
// In particular, false, null and empty collections must not become "missing".
var configurationPaths = []struct {
	field string
	paths []string
}{
	{"model", []string{"model"}},
	{"provider", []string{"provider", "model_provider", "model_provider_id"}},
	{"application_version", []string{"application_version", "cli_version", "claude_code_version"}},
	{"workdir", []string{"cwd", "workdir"}},
	{"permission_mode", []string{"permission_mode", "permissionMode"}},
	{"approval_policy", []string{"approval_policy"}},
	{"sandbox_policy", []string{"sandbox_policy", "sandbox", "permission_profile"}},
	{"directory_restrictions", []string{"sandbox_policy.writable_roots", "sandbox_policy.readable_roots", "permission_profile.file_system.entries"}},
	{"network_restrictions", []string{"sandbox_policy.network_access", "network_access", "permission_profile.network"}},
	{"mcp_servers", []string{"mcp_servers", "mcpServers"}},
	{"tools", []string{"tools"}},
	{"skills", []string{"skills"}},
	{"plugins", []string{"plugins"}},
}

func missingSnapshots(harness string, records []Record) []string {
	seen := map[string]bool{}
	for _, record := range records {
		seen[record.Kind] = record.Body != nil || seen[record.Kind]
		if record.Kind == "task" || record.Kind == "message" && record.Role == "user" {
			seen["task"] = record.Body != nil || seen["task"]
		}
		if record.Kind == "approval" && record.Status == "decision_recorded" && record.Body != nil {
			seen["approval_decision"] = hasConfigurationPath(obj(json.RawMessage(*record.Body)), "decision") || seen["approval_decision"]
		}
		if record.Kind != "configuration" || record.Body == nil {
			continue
		}
		body := obj(json.RawMessage(*record.Body))
		for _, spec := range configurationPaths {
			for _, path := range spec.paths {
				if hasConfigurationPath(body, path) {
					seen["configuration."+spec.field] = true
				}
			}
		}
		if harness == "claude" && record.Status == "permission_mode" && hasConfigurationPath(body, "mode") {
			seen["configuration.permission_mode"] = true
		}
		if harness == "deepseek" {
			switch record.Status {
			case "request/header":
				for _, field := range []string{"model", "provider"} {
					if hasConfigurationPath(body, "header.config."+field) {
						seen["configuration."+field] = true
					}
				}
				if hasConfigurationPath(body, "header.tools") {
					seen["configuration.tools"] = true
				}
			case "permission/preset":
				seen["configuration.permission_mode"] = hasConfigurationPath(body, "preset") || seen["configuration.permission_mode"]
			case "sandbox/mode":
				seen["configuration.sandbox_policy"] = hasConfigurationPath(body, "mode") || seen["configuration.sandbox_policy"]
			case "approval/policy":
				seen["configuration.approval_policy"] = hasConfigurationPath(body, "policy") || seen["configuration.approval_policy"]
			}
		}
	}
	// Source snapshots can show changes but cannot establish that every change
	// was logged. Keep this coverage gap even when all configuration values exist.
	missing := []string{"configuration.change_history_completeness"}
	for _, kind := range []string{"task", "configuration", "approval", "approval_decision"} {
		if !seen[kind] {
			missing = append(missing, kind)
		}
	}
	for _, spec := range configurationPaths {
		if key := "configuration." + spec.field; !seen[key] {
			missing = append(missing, key)
		}
	}
	return missing
}

func hasConfigurationPath(value row, path string) bool {
	parts := strings.Split(path, ".")
	for i, part := range parts {
		raw, exists := value[part]
		if !exists {
			return false
		}
		if i == len(parts)-1 {
			return true
		}
		value = obj(raw)
	}
	return false
}
