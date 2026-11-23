//go:build !agentprov_tools

package cli

import (
	"github.com/byteyellow/agentprovenance/internal/companion"
	"github.com/spf13/cobra"
)

const bundledTools = false

func runSandboxWatch(*cobra.Command, *string, watchOptions) error { return companion.Exec() }
