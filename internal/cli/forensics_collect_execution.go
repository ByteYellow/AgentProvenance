package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func forensicsCollectExecutionCmd(dataDir, daemonURL *string) *cobra.Command {
	var configPath, receiverID, signKeyPath, pubKeyPath, operation, packageDir string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "collect-execution <admission.json>",
		Short: "receive signed execution evidence from a server or saved package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (*daemonURL == "") == (packageDir == "") || timeout <= 0 {
				return fmt.Errorf("execution collection requires exactly one of --daemon-url or --package-dir and a positive --timeout")
			}
			if packageDir == "" && operation == "" {
				return fmt.Errorf("HTTP execution collection requires --operation")
			}
			if packageDir != "" && operation != "" {
				return fmt.Errorf("--operation applies only to HTTP collection; a saved package already has its identity")
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
			if receiver.SourceAdmissionRef, err = receiver.RecordAdmission(ctx, admission.Attempt.Request, admission.Attempt); err != nil {
				return err
			}
			var result daemon.ExecutionCollection
			if packageDir != "" {
				result, err = collectExecutionPackage(ctx, handoff.IdentityOf(admission.Attempt), packageDir, receiver)
			} else {
				client := daemon.NewClient(*daemonURL, *dataDir)
				result, err = client.CollectExecution(ctx, handoff.IdentityOf(admission.Attempt), operation, receiver)
			}
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
	cmd.Flags().StringVar(&packageDir, "package-dir", "", "local sealed package directory containing bundle.json and manifest.dsse.json; no sender contact")
	cmd.Flags().DurationVar(&timeout, "timeout", 3*time.Minute, "total timeout for evidence collection and acknowledgment")
	for _, flag := range []string{"execution-config", "receiver", "sign-key", "pub-key"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}

func readExecutionEnvelope(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > handoff.MaxEnvelopeBytes {
		return nil, fmt.Errorf("execution envelope requires a regular file of at most 64 KiB")
	}
	raw, err := io.ReadAll(io.LimitReader(f, handoff.MaxEnvelopeBytes+1))
	if err == nil && len(raw) > handoff.MaxEnvelopeBytes {
		err = fmt.Errorf("execution envelope exceeds 64 KiB")
	}
	return raw, err
}

// The package is only a transport. Independent admission and pinned keys retain
// the same authority as HTTP collection; the receipt still needs sender delivery.
func collectExecutionPackage(ctx context.Context, expected handoff.ExecutionIdentity, directory string, receiver *handoff.DeliveryReceiver) (daemon.ExecutionCollection, error) {
	out := daemon.ExecutionCollection{SchemaVersion: handoff.DeliverySchema, LocalRunID: expected.LocalRunID, Status: "pending"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	envelope, err := readExecutionEnvelope(filepath.Join(directory, "manifest.dsse.json"))
	if err != nil {
		return out, err
	}
	m, err := receiver.VerifyManifest(expected, envelope)
	if err != nil {
		return out, err
	}
	f, err := os.Open(filepath.Join(directory, "bundle.json"))
	if err != nil {
		return out, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return out, err
	}
	if !info.Mode().IsRegular() || info.Size() != m.BundleBytes {
		return out, fmt.Errorf("execution package body size or type mismatch")
	}
	receipt, err := receiver.Receive(ctx, expected, envelope, f)
	if err != nil {
		return out, err
	}
	out.DeliveryID, out.ManifestSHA256, out.BundleSHA256 = m.ID, attest.DigestSHA256(envelope), m.BundleSHA256
	out.Status, out.Receipt = "receipt_persisted", receipt
	return out, nil
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
