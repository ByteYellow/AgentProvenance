package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/spf13/cobra"
)

func dashboardExportCmd(dataDir *string) *cobra.Command {
	var run, output, harness, session, selectionFile string
	var excludeRecords, excludeCategories []string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "export selected saved evidence as an unsigned, offline replay ZIP",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" || (run == "" && selectionFile == "") {
				return fmt.Errorf("--output and either --run or --selection-file are required")
			}
			selection := dashboard.ReplaySelection{RunID: run, Scope: "whole_run", Harness: harness, SessionID: session,
				ExcludeRecords: excludeRecords, ExcludeCategories: excludeCategories}
			if harness != "" || session != "" {
				selection.Scope = "session"
			}
			selections := []dashboard.ReplaySelection{selection}
			if selectionFile != "" {
				for _, flag := range []string{"run", "harness", "session", "exclude-record", "exclude-category"} {
					if cmd.Flags().Changed(flag) {
						return fmt.Errorf("--selection-file cannot be combined with --%s", flag)
					}
				}
				var err error
				selections, err = readReplaySelections(selectionFile)
				if err != nil {
					return err
				}
			}
			if value, _ := cmd.Flags().GetString("daemon-url"); value != "" {
				return fmt.Errorf("dashboard export reads a local store; omit --daemon-url")
			}
			target, err := filepath.Abs(output)
			if err != nil {
				return err
			}
			if _, err = os.Lstat(target); err == nil {
				return fmt.Errorf("output already exists: %s", target)
			} else if !os.IsNotExist(err) {
				return err
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			prepared, err := (dashboard.Server{DB: db}).PrepareOfflineReplaySet(cmd.Context(), selections)
			if err != nil {
				return err
			}
			defer prepared.Close()
			if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return err
			}
			stage, err := os.CreateTemp(filepath.Dir(target), ".agentprov-replay-*.zip")
			if err != nil {
				return err
			}
			defer os.Remove(stage.Name())
			defer stage.Close()
			if err = prepared.WriteZIP(cmd.Context(), stage); err != nil {
				return err
			}
			if err = stage.Sync(); err != nil {
				return err
			}
			info, err := stage.Stat()
			if err != nil {
				return err
			}
			if err = stage.Close(); err != nil {
				return err
			}
			// Linking a completed sibling file publishes without overwriting a
			// target created since the initial check.
			if err = os.Link(stage.Name(), target); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s scope=%s signed=false events=%d files=%d zip_bytes=%d inventory_sha256=%s output=%s\n", prepared.Inventory.RunID, prepared.Inventory.Scope, prepared.Inventory.Events, len(prepared.Inventory.Files)+1, info.Size(), prepared.InventorySHA256, target)
			return nil
		},
	}
	cmd.Flags().StringVar(&run, "run", "", "run to export; all saved and unassigned records are included by default")
	cmd.Flags().StringVar(&selectionFile, "selection-file", "", "JSON array of explicit run/session selections; exclusive with single-run selection flags")
	cmd.Flags().StringVar(&output, "output", "", "new ZIP file; unzip and open index.html offline")
	cmd.Flags().StringVar(&harness, "harness", "", "limit to a native session; requires --session")
	cmd.Flags().StringVar(&session, "session", "", "native session ID; requires --harness")
	cmd.Flags().StringArrayVar(&excludeRecords, "exclude-record", nil, "omit a search catalog record ID and its linked readers (repeatable)")
	cmd.Flags().StringArrayVar(&excludeCategories, "exclude-category", nil, "omit messages, tools, configuration, files, or runtime (repeatable)")
	return cmd
}

func readReplaySelections(path string) ([]dashboard.ReplaySelection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("replay selection file exceeds 1 MiB")
	}
	var inputs []dashboard.ReplaySelection
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&inputs); err != nil {
		return nil, fmt.Errorf("decode replay selection file: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("replay selection file must contain one JSON array")
	}
	return inputs, nil
}
