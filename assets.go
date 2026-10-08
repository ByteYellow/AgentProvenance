// Package agentprovenance embeds the project's public overview and release history.
package agentprovenance

import "embed"

// Documentation is shared by GitHub, the local demo and the published website.
//
//go:embed README.md README.zh-CN.md CHANGELOG.md CHANGELOG.zh-CN.md LICENSE
var Documentation embed.FS
