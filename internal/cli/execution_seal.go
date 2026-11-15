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

func sealExecutions(ctx context.Context, delivery *handoff.DeliveryService, principal handoff.Principal, operation string, requireReceipts bool, output io.Writer) error {
	encoder := json.NewEncoder(output)
	summary, err := delivery.SealStopped(ctx, principal, operation, func(result handoff.SealResult) error {
		return encoder.Encode(result)
	})
	if err == nil && requireReceipts && !summary.DeliveryComplete {
		err = fmt.Errorf("%w: %d sealed packages await receiver receipts", handoff.ErrConflict, summary.ReceiptsPending)
	}
	return errors.Join(err, encoder.Encode(summary))
}

func forensicsSealExecutionsCmd(dataDir, daemonURL *string) *cobra.Command {
	var configPath, operation string
	var requireReceipts bool
	cmd := &cobra.Command{Use: "seal-executions", Short: "prepare signed execution packages in a stopped local store", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if *daemonURL != "" {
				return fmt.Errorf("execution sealing requires the stopped local store; remove --daemon-url")
			}
			return withStoppedDelivery(*dataDir, configPath, "execution sealing", func(delivery *handoff.DeliveryService, principal handoff.Principal) error {
				return sealExecutions(cmd.Context(), delivery, principal, operation, requireReceipts, cmd.OutOrStdout())
			})
		}}
	cmd.Flags().StringVar(&configPath, "execution-config", "", "trusted caller, target and delivery signing configuration")
	cmd.Flags().StringVar(&operation, "operation", "", "stable sealing operation ID; retry the same operation to reuse immutable packages")
	cmd.Flags().BoolVar(&requireReceipts, "require-receipts", false, "fail unless every package in this sealing operation has a verified receiver receipt")
	_ = cmd.MarkFlagRequired("execution-config")
	_ = cmd.MarkFlagRequired("operation")
	return cmd
}

func withStoppedDelivery(dataDir, configPath, action string, run func(*handoff.DeliveryService, handoff.Principal) error) error {
	f, err := os.Open(configPath)
	if err != nil {
		return err
	}
	config, readErr := handoff.ReadConfig(f)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return err
	}
	if config.Delivery == nil {
		return fmt.Errorf("%s requires delivery configuration", action)
	}
	server, closeDB, err := daemon.NewServer(dataDir)
	if err != nil {
		return err
	}
	defer closeDB()
	if _, active := daemon.ActiveLock(dataDir); active {
		return fmt.Errorf("%s requires a stopped daemon", action)
	}
	release, err := daemon.AcquireLock(dataDir, "execution-offline")
	if err != nil {
		return err
	}
	defer release()
	delivery, err := config.DeliveryService(filepath.Dir(configPath), handoff.Ledger{DB: server.DB, Target: config.Target}, server.Paths)
	if err != nil {
		return err
	}
	return run(delivery, config.Principal())
}

func forensicsAcknowledgeExecutionCmd(dataDir, daemonURL *string) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{Use: "acknowledge-execution <delivery-id> <receipt.json>",
		Short: "verify and persist a receiver receipt in a stopped execution store", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if *daemonURL != "" {
				return fmt.Errorf("execution acknowledgment requires the stopped local store; remove --daemon-url")
			}
			receipt, err := readExecutionEnvelope(args[1])
			if err != nil {
				return err
			}
			return withStoppedDelivery(*dataDir, configPath, "execution acknowledgment", func(service *handoff.DeliveryService, principal handoff.Principal) error {
				delivery, err := service.Acknowledge(cmd.Context(), principal, args[0], receipt)
				if err != nil {
					return err
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(daemon.ExecutionDeliveryResponse{SchemaVersion: handoff.DeliverySchema, Delivery: delivery})
			})
		}}
	cmd.Flags().StringVar(&configPath, "execution-config", "", "trusted caller, target and delivery signing configuration")
	_ = cmd.MarkFlagRequired("execution-config")
	return cmd
}
