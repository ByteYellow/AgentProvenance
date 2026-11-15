package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/spf13/cobra"
)

func sealExecutions(ctx context.Context, delivery *handoff.DeliveryService, principal handoff.Principal, operation string, output io.Writer) error {
	encoder := json.NewEncoder(output)
	summary, err := delivery.SealStopped(ctx, principal, operation, func(result handoff.SealResult) error {
		return encoder.Encode(result)
	})
	return errors.Join(err, encoder.Encode(summary))
}

func forensicsSealExecutionsCmd(dataDir, daemonURL *string) *cobra.Command {
	var configPath, operation string
	cmd := &cobra.Command{Use: "seal-executions", Short: "prepare signed execution packages in a stopped local store", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if *daemonURL != "" {
				return fmt.Errorf("execution sealing requires the stopped local store; remove --daemon-url")
			}
			f, err := os.Open(configPath)
			if err != nil {
				return err
			}
			config, readErr := handoff.ReadConfig(f)
			if err := errors.Join(readErr, f.Close()); err != nil {
				return err
			}
			if config.Delivery == nil {
				return fmt.Errorf("execution sealing requires delivery configuration")
			}
			server, closeDB, err := daemon.NewServer(*dataDir)
			if err != nil {
				return err
			}
			defer closeDB()
			if _, active := daemon.ActiveLock(*dataDir); active {
				return fmt.Errorf("execution sealing requires a stopped daemon")
			}
			release, err := daemon.AcquireLock(*dataDir, "execution-seal")
			if err != nil {
				return err
			}
			defer release()
			delivery, err := config.DeliveryService(filepath.Dir(configPath), handoff.Ledger{DB: server.DB, Target: config.Target}, server.Paths)
			if err != nil {
				return err
			}
			return sealExecutions(cmd.Context(), delivery, config.Principal(), operation, cmd.OutOrStdout())
		}}
	cmd.Flags().StringVar(&configPath, "execution-config", "", "trusted caller, target and delivery signing configuration")
	cmd.Flags().StringVar(&operation, "operation", "", "stable sealing operation ID; retry the same operation to reuse immutable packages")
	_ = cmd.MarkFlagRequired("execution-config")
	_ = cmd.MarkFlagRequired("operation")
	return cmd
}
