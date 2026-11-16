package cli

import (
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/viewverify"
	"github.com/spf13/cobra"
)

func evidenceVerifyViewCmd() *cobra.Command {
	var policy string
	cmd := &cobra.Command{
		Use: "verify-view <directory-or-zip>", Short: "verify an exported reader offline using recipient-owned trust",
		Args: cobra.ExactArgs(1), SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if value, _ := cmd.Flags().GetString("daemon-url"); value != "" {
				return fmt.Errorf("verify-view reads local files; omit --daemon-url")
			}
			_, err := viewverify.Verify(cmd.Context(), args[0], policy, cmd.OutOrStdout())
			return err
		},
	}
	cmd.Flags().StringVar(&policy, "trust-policy", "", "recipient-owned JSON trust policy outside the evidence package")
	return cmd
}
