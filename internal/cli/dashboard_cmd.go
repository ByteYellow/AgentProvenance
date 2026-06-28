package cli

import (
	"fmt"
	"net"
	"net/http"

	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/spf13/cobra"
)

// dashboardCmd serves the local read-only web dashboard over the verifiable
// provenance graph (runs, timeline, signals, verify+signature, and the
// causality DAG). It opens the same local store the CLI uses; nothing is
// written. See internal/dashboard.
func dashboardCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "local read-only web dashboard over the verifiable provenance graph",
	}
	var addr string
	serve := &cobra.Command{
		Use:   "serve",
		Short: "serve the dashboard (read-only) and print its URL",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen %s: %w", addr, err)
			}
			url := fmt.Sprintf("http://%s/", ln.Addr().String())
			fmt.Fprintf(cmd.OutOrStdout(), "AgentProvenance dashboard: %s\n(read-only; Ctrl-C to stop)\n", url)
			return http.Serve(ln, dashboard.Server{DB: db}.Handler())
		},
	}
	serve.Flags().StringVar(&addr, "addr", "127.0.0.1:7396", "listen address (host:port)")
	cmd.AddCommand(serve)
	return cmd
}
