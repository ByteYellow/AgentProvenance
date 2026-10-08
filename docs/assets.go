// Package docs embeds the public documentation shared by local and online demos.
package docs

import (
	"embed"
	"strings"
)

// Files excludes acceptance reports, internal plans and implementation proposals.
//
//go:embed release-start.md capabilities.md agent-context.md graph-commands.md amd64-kvm-k3s.md native-capture-spool.md deployment-modes.md security-commands.md compliance.md python-sdk.md ai-tools.md ai-access.md telemetry-schema.md comparisons.md supply-chain-demo.md falco-receiver.md openapi.yaml agent-context-api.yaml releases/*.md zh-CN/release-start.md zh-CN/capabilities.md zh-CN/agent-context.md zh-CN/graph-commands.md zh-CN/amd64-kvm-k3s.md zh-CN/native-capture-spool.md zh-CN/deployment-modes.md zh-CN/security-commands.md zh-CN/compliance.md zh-CN/python-sdk.md zh-CN/ai-tools.md zh-CN/ai-access.md zh-CN/telemetry-schema.md zh-CN/comparisons.md zh-CN/supply-chain-demo.md zh-CN/falco-receiver.md zh-CN/openapi.yaml zh-CN/releases/*.md img/*.png img/*.gif assets/*.svg assets/*.png
var Files embed.FS

type Entry struct{ ID, Title, Path, Group string }
type Group struct {
	Title   string
	Entries []Entry
}

func (e Entry) Source(chinese bool) string {
	if !chinese {
		return e.Path
	}
	if strings.HasPrefix(e.Path, "docs/") {
		return "docs/zh-CN/" + strings.TrimPrefix(e.Path, "docs/")
	}
	return strings.TrimSuffix(e.Path, ".md") + ".zh-CN.md"
}

func Catalog() []Entry {
	return []Entry{
		{"start", "Project overview", "README.md", "Start here"},
		{"quickstart", "Getting started", "docs/release-start.md", "Start here"},
		{"capabilities", "Capabilities and architecture", "docs/capabilities.md", "Start here"},
		{"agent-session", "Agent session", "docs/agent-context.md", "Record and deploy"},
		{"capture", "Linux, KVM and Kubernetes", "docs/amd64-kvm-k3s.md", "Record and deploy"},
		{"deployment", "Deployment modes", "docs/deployment-modes.md", "Record and deploy"},
		{"durable-capture", "Continuous capture and recovery", "docs/native-capture-spool.md", "Record and deploy"},
		{"graph", "Trace and compare", "docs/graph-commands.md", "Investigate evidence"},
		{"security", "Security and policies", "docs/security-commands.md", "Investigate evidence"},
		{"compliance", "Compliance evidence", "docs/compliance.md", "Investigate evidence"},
		{"supply-chain", "Supply-chain investigation", "docs/supply-chain-demo.md", "Investigate evidence"},
		{"ai-tools", "AI tools and MCP", "docs/ai-tools.md", "Integrate"},
		{"ai-access", "API access and permissions", "docs/ai-access.md", "Integrate"},
		{"python", "Python integration", "docs/python-sdk.md", "Integrate"},
		{"telemetry", "Telemetry schema", "docs/telemetry-schema.md", "Integrate"},
		{"comparisons", "Related projects", "docs/comparisons.md", "Reference"},
		{"falco", "Falco compatibility", "docs/falco-receiver.md", "Reference"},
		{"release-notes", "Release notes", "docs/releases/v0.9.0.md", "Reference"},
		{"changelog", "Release history", "CHANGELOG.md", "Reference"},
	}
}
func Groups() []Group {
	var groups []Group
	for _, entry := range Catalog() {
		if len(groups) == 0 || groups[len(groups)-1].Title != entry.Group {
			groups = append(groups, Group{Title: entry.Group})
		}
		groups[len(groups)-1].Entries = append(groups[len(groups)-1].Entries, entry)
	}
	return groups
}

// Pages also includes linked historical release notes without crowding navigation.
func Pages() []Entry {
	pages := Catalog()
	for _, version := range []string{"v0.7.2", "v0.8.0", "v0.8.1", "v0.8.2-rc.1", "v0.8.2-rc.2", "v0.8.2"} {
		pages = append(pages, Entry{"release-" + version, version, "docs/releases/" + version + ".md", "Reference"})
	}
	return pages
}
