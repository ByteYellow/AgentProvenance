package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/spf13/cobra"
)

func dashboardExportCmd(dataDir *string) *cobra.Command {
	var run, output string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "export one complete run as an unsigned, offline replay ZIP",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if run == "" || output == "" {
				return fmt.Errorf("--run and --output are required")
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
			prepared, err := (dashboard.Server{DB: db}).PrepareOfflineReplay(cmd.Context(), run)
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
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s scope=whole_run signed=false events=%d files=%d zip_bytes=%d inventory_sha256=%s output=%s\n", run, prepared.Inventory.Events, len(prepared.Inventory.Files)+1, info.Size(), prepared.InventorySHA256, target)
			return nil
		},
	}
	cmd.Flags().StringVar(&run, "run", "", "run to export, including all saved content and unassigned records")
	cmd.Flags().StringVar(&output, "output", "", "new ZIP file; unzip and open index.html offline")
	return cmd
}
