package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/launch"
	"github.com/spf13/cobra"
)

func internalRemoteHookCmd() *cobra.Command {
	var route string
	cmd := &cobra.Command{Use: "remote-hook", Hidden: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), agentcontext.MaxLineBytes+1))
			if err != nil {
				return err
			}
			out, err := launch.RemoteHookOutput(route, raw)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return err
		}}
	cmd.Flags().StringVar(&route, "route", "", "saved operator-owned launch route")
	_ = cmd.MarkFlagRequired("route")
	return cmd
}

func internalRemoteCommandCmd() *cobra.Command {
	var route, request, command string
	cmd := &cobra.Command{Use: "remote-command", Hidden: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			exit, err := launch.ExecuteRemoteCall(ctx, route, request, command, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if exit != 0 {
				os.Exit(exit)
			}
			return nil
		}}
	cmd.Flags().StringVar(&route, "route", "", "saved operator-owned launch route")
	cmd.Flags().StringVar(&request, "request", "", "prepared native tool call")
	cmd.Flags().StringVar(&command, "native-command", "", "original command displayed for approval")
	for _, flag := range []string{"route", "request", "native-command"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}
