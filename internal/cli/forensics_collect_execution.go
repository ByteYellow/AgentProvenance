package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func forensicsCollectExecutionCmd(dataDir, daemonURL *string) *cobra.Command {
	var configPath, receiverID, signKeyPath, pubKeyPath, operation string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "collect-execution <admission.json>",
		Short: "receive signed execution evidence and acknowledge its persisted receipt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if *daemonURL == "" || timeout <= 0 {
				return commandErrorf("execution collection requires --daemon-url and a positive --timeout")
			}
			configFile, err := os.Open(configPath)
			if err != nil {
				return err
			}
			config, readErr := handoff.ReadConfig(configFile)
			if err := errors.Join(readErr, configFile.Close()); err != nil {
				return err
			}
			admission, err := readExecutionAdmission(args[0])
			if err != nil {
				return err
			}
			if config.Target != admission.Attempt.Request.Target || config.Principal().Authorize(admission.Attempt.Request.Source, config.Target) != nil {
				return handoff.ErrForbidden
			}
			key, err := attest.LoadPrivateKeyHex(signKeyPath)
			if err != nil {
				return err
			}
			pub, err := attest.LoadPublicKeyHex(pubKeyPath)
			if err != nil {
				return err
			}
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			receiver := &handoff.DeliveryReceiver{DB: db, Paths: paths, ID: receiverID, SignKey: key, Target: config.Target, TargetKey: pub, Caller: config.Principal()}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			client := daemon.NewClient(*daemonURL, *dataDir)
			result, err := client.CollectExecution(ctx, handoff.IdentityOf(admission.Attempt), operation, receiver)
			if err == nil || len(result.Receipt) != 0 {
				if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(result); encodeErr != nil {
					return errors.Join(err, encodeErr)
				}
			}
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "execution-config", "", "trusted caller and target configuration for evidence collection")
	cmd.Flags().StringVar(&receiverID, "receiver", "", "receiver identity pinned by the execution server")
	cmd.Flags().StringVar(&signKeyPath, "sign-key", "", "hex ed25519 private key file for signing the receiving receipt")
	cmd.Flags().StringVar(&pubKeyPath, "pub-key", "", "pinned execution server public key file (hex ed25519)")
	cmd.Flags().StringVar(&operation, "operation", "", "stable delivery operation id; reuse it when retrying the same package")
	cmd.Flags().DurationVar(&timeout, "timeout", 3*time.Minute, "total timeout for evidence collection and acknowledgment")
	for _, flag := range []string{"execution-config", "receiver", "sign-key", "pub-key", "operation"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}

// Admission is captured from the authenticated submit response, not extracted
// from the package being imported. Check its request digest before network I/O.
func readExecutionAdmission(path string) (daemon.ExecutionAdmission, error) {
	var admission daemon.ExecutionAdmission
	f, err := os.Open(path)
	if err != nil {
		return admission, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return admission, err
	}
	if len(raw) > 2<<20 {
		return admission, fmt.Errorf("execution admission exceeds 2 MiB")
	}
	if err := json.Unmarshal(raw, &admission); err != nil {
		return admission, err
	}
	a := admission.Attempt
	_, _, hash, err := a.Request.Canonical()
	if err != nil || admission.SchemaVersion != handoff.SchemaVersion || a.SchemaVersion != handoff.SchemaVersion ||
		a.DigestVersion != handoff.DigestVersion || a.RequestHash != hash || a.ID == "" || a.LocalRunID == "" {
		return admission, fmt.Errorf("invalid saved execution admission")
	}
	return admission, nil
}
