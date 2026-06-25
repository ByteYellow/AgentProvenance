package cli

import (
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func forensicsCmd(dataDir *string) *cobra.Command {
	var jsonOut bool
	export := &cobra.Command{
		Use:   "export <run_id>",
		Short: "export a forensics bundle for a run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			bundle, err := (forensics.Service{DB: db, Paths: paths}).ExportBundle(args[0])
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(bundle)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "bundle_id=%s path=%s sha256=%s size_bytes=%d\n", bundle.ID, bundle.Path, bundle.SHA256, bundle.SizeBytes)
			return nil
		},
	}
	export.Flags().BoolVar(&jsonOut, "json", false, "emit structured forensics export JSON")
	cmd := &cobra.Command{Use: "forensics", Short: "forensics bundle commands"}
	cmd.AddCommand(export)
	return cmd
}
