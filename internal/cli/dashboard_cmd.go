package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/spf13/cobra"
)

// dashboardCmd serves the local read-only web dashboard over the verifiable
// provenance graph (runs, timeline, signals, verify+signature, and the
// causality DAG). It opens the same local store the CLI uses; nothing is
// written to the evidence store. Export previews use private temporary files.
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
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return commandErrorf("listen %s: %w", addr, err)
			}
			defer ln.Close()
			exports := dashboard.NewReplayExports(dashboard.Server{DB: db})
			defer exports.Close()
			server := &http.Server{Handler: dashboard.Server{DB: db, ReplayExports: exports}.Handler(), ReadHeaderTimeout: 5 * time.Second}
			defer server.Close()
			url := commandURL(cmd, fmt.Sprintf("http://%s/", ln.Addr().String()))
			fmt.Fprintf(cmd.OutOrStdout(), commandText(cmd, "AgentProvenance dashboard: %s\n(read-only; Ctrl-C to stop)\n"), url)
			done := make(chan error, 1)
			go func() { done <- server.Serve(ln) }()
			select {
			case err := <-done:
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := server.Shutdown(shutdown); err != nil {
					_ = server.Close()
				}
				<-done
				return nil
			}
		},
	}
	serve.Flags().StringVar(&addr, "addr", "127.0.0.1:7396", "listen address (host:port)")
	cmd.AddCommand(serve, dashboardExportCmd(dataDir))
	return cmd
}
