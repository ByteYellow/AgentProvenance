package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/compliance"
	"github.com/spf13/cobra"
)

func complianceCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "map run evidence to security framework controls",
		Long:  "Map AgentProvenance run evidence to security framework controls as evidence-backed self-assessment. This is not certification or legal advice.",
	}
	cmd.AddCommand(complianceFrameworksCmd())
	cmd.AddCommand(complianceValidateCmd())
	cmd.AddCommand(complianceMapCmd(dataDir, "map"))
	cmd.AddCommand(complianceMapCmd(dataDir, "report"))
	return cmd
}

func complianceValidateCmd() *cobra.Command {
	var ruleSetPath string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "validate a custom compliance ruleset YAML",
		RunE: func(cmd *cobra.Command, args []string) error {
			if ruleSetPath == "" {
				return fmt.Errorf("--ruleset is required")
			}
			ruleSet, err := compliance.LoadRuleSet(ruleSetPath)
			if err != nil {
				return err
			}
			frameworks := compliance.Frameworks(ruleSet)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"schema_version":  "agentprovenance.compliance_ruleset_validation/v1",
					"status":          "valid",
					"ruleset_id":      ruleSet.ID,
					"rules":           len(ruleSet.Rules),
					"mappings":        len(ruleSet.Mappings),
					"merged_profiles": frameworks,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "status=valid ruleset=%s rules=%d mappings=%d frameworks=%d\n",
				ruleSet.ID, len(ruleSet.Rules), len(ruleSet.Mappings), len(frameworks))
			return nil
		},
	}
	cmd.Flags().StringVar(&ruleSetPath, "ruleset", "", "custom compliance ruleset YAML")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func complianceFrameworksCmd() *cobra.Command {
	var jsonOut bool
	var ruleSetPath string
	cmd := &cobra.Command{
		Use:   "frameworks",
		Short: "list built-in compliance evidence mapping profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			var ruleSets []compliance.RuleSet
			if ruleSetPath != "" {
				ruleSet, err := compliance.LoadRuleSet(ruleSetPath)
				if err != nil {
					return err
				}
				ruleSets = append(ruleSets, ruleSet)
			}
			frameworks := compliance.Frameworks(ruleSets...)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"schema_version": "agentprovenance.compliance_frameworks/v1",
					"frameworks":     frameworks,
				})
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTITLE\tCONTROLS\tDISCLAIMER")
			for _, framework := range frameworks {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", framework.ID, framework.Title, len(framework.Controls), framework.Disclaimer)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	cmd.Flags().StringVar(&ruleSetPath, "ruleset", "", "optional custom compliance ruleset YAML")
	return cmd
}

func complianceMapCmd(dataDir *string, use string) *cobra.Command {
	var frameworkID, runID string
	var jsonOut bool
	var ruleSetPath string
	var onlyCSV, excludeCSV string
	cmd := &cobra.Command{
		Use:   use,
		Short: "map run evidence to a compliance/security framework",
		RunE: func(cmd *cobra.Command, args []string) error {
			if frameworkID == "" {
				return fmt.Errorf("--framework is required")
			}
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			var ruleSet *compliance.RuleSet
			if ruleSetPath != "" {
				loaded, err := compliance.LoadRuleSet(ruleSetPath)
				if err != nil {
					return err
				}
				ruleSet = &loaded
			}
			report, err := compliance.MapRun(db, compliance.MappingOptions{
				Framework: frameworkID,
				RunID:     runID,
				RuleSet:   ruleSet,
				Only:      csvList(onlyCSV),
				Exclude:   csvList(excludeCSV),
			})
			if err != nil {
				return err
			}
			if jsonOut || use == "report" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "framework=%s run=%s schema=%s covered=%d partial=%d missing=%d not_applicable=%d total=%d\n",
				report.Framework, report.RunID, report.SchemaVersion, report.Summary.Covered, report.Summary.Partial,
				report.Summary.Missing, report.Summary.NotApplicable, report.Summary.Total)
			fmt.Fprintf(cmd.OutOrStdout(), "disclaimer=%q\n", report.Disclaimer)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "CONTROL\tSTATUS\tEVIDENCE\tGAP\tNEXT_STEP")
			for _, item := range report.Items {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", item.ControlID, item.Status, len(item.EvidenceRefs), item.Gap, item.RecommendedNextStep)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&frameworkID, "framework", "", "framework id, such as owasp-asi or nist-rfi-2026-00206")
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&ruleSetPath, "ruleset", "", "optional custom compliance ruleset YAML")
	cmd.Flags().StringVar(&onlyCSV, "only", "", "comma-separated control ids to evaluate")
	cmd.Flags().StringVar(&excludeCSV, "exclude", "", "comma-separated control ids to skip")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func csvList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
