package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/adapter"
	"github.com/spf13/cobra"
)

func adapterCmd() *cobra.Command {
	var kind string
	var withJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "list registered AgentProvenance adapters",
		RunE: func(cmd *cobra.Command, args []string) error {
			items := adapter.ListByKind(kind)
			if withJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(items)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "KIND\tNAME\tSTATUS\tAVAILABLE\tCAPABILITIES\tIDENTITY_KEYS\tQBS_IMPACT")
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\t%s\t%s\n",
					item.Kind, item.Name, item.Status, item.Available, capabilitySummary(item.Capabilities), strings.Join(item.IdentityKeys, ","), strings.Join(item.QBSImpact, ","))
			}
			return w.Flush()
		},
	}
	list.Flags().StringVar(&kind, "kind", "", "filter by adapter kind: agent, sandbox, telemetry, artifact, snapshot")
	list.Flags().BoolVar(&withJSON, "json", false, "emit adapter list as JSON")

	var inspectJSON bool
	inspect := &cobra.Command{
		Use:   "inspect <adapter>",
		Short: "inspect an adapter capability contract",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			item, err := adapter.Inspect(args[0])
			if err != nil {
				return err
			}
			if inspectJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(item)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "name=%s\nkind=%s\nstatus=%s\navailable=%t\nboundary=%s\ninputs=%s\noutputs=%s\nidentity_keys=%s\nqbs_impact=%s\nnotes=%s\n",
				item.Name, item.Kind, item.Status, item.Available, item.Boundary, strings.Join(item.Inputs, ","), strings.Join(item.Outputs, ","), strings.Join(item.IdentityKeys, ","), strings.Join(item.QBSImpact, ","), item.Notes)
			for _, cap := range item.Capabilities {
				fmt.Fprintf(cmd.OutOrStdout(), "capability=%s supported=%t level=%s notes=%q\n", cap.Name, cap.Supported, cap.Level, cap.Notes)
			}
			return nil
		},
	}
	inspect.Flags().BoolVar(&inspectJSON, "json", false, "emit adapter contract as JSON")

	cmd := &cobra.Command{Use: "adapter", Short: "adapter capability contracts"}
	cmd.AddCommand(list)
	cmd.AddCommand(inspect)
	return cmd
}

func capabilitySummary(caps []adapter.Capability) string {
	var parts []string
	for _, cap := range caps {
		marker := "-"
		if cap.Supported {
			marker = "+"
		}
		parts = append(parts, marker+cap.Name+":"+cap.Level)
	}
	return strings.Join(parts, ",")
}
