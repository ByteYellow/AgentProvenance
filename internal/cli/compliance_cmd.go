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
		Short: "map run evidence to security framework items",
		Long:  "Map AgentProvenance run evidence to security framework items as evidence-backed self-assessment. This is not certification or legal advice.",
	}
	cmd.AddCommand(complianceFrameworksCmd())
	cmd.AddCommand(complianceValidateCmd())
	cmd.AddCommand(complianceMapCmd(dataDir, "map"))
	cmd.AddCommand(complianceMapCmd(dataDir, "report"))
	cmd.AddCommand(complianceExplainCmd(dataDir))
	cmd.AddCommand(complianceGapsCmd(dataDir))
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
			fmt.Fprintln(w, "ID\tTITLE\tITEMS\tDISCLAIMER")
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
			fmt.Fprintln(w, "ITEM\tSTATUS\tEVIDENCE\tGAP\tNEXT_STEP")
			for _, item := range report.Items {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", item.ItemID, item.Status, len(item.EvidenceRefs), item.Gap, item.RecommendedNextStep)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&frameworkID, "framework", "", "framework id, such as owasp-asi or nist-rfi-2026-00206")
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&ruleSetPath, "ruleset", "", "optional custom compliance ruleset YAML")
	cmd.Flags().StringVar(&onlyCSV, "only", "", "comma-separated item ids to evaluate")
	cmd.Flags().StringVar(&excludeCSV, "exclude", "", "comma-separated item ids to skip")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func complianceExplainCmd(dataDir *string) *cobra.Command {
	var frameworkID, runID, itemID, legacyControlID string
	var jsonOut bool
	var ruleSetPath string
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "explain evidence for one compliance/security item",
		RunE: func(cmd *cobra.Command, args []string) error {
			if frameworkID == "" {
				return fmt.Errorf("--framework is required")
			}
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			if itemID == "" {
				itemID = legacyControlID
			}
			if itemID == "" {
				return fmt.Errorf("--item is required")
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
				Only:      []string{itemID},
			})
			if err != nil {
				return err
			}
			item, ok := compliance.FindItem(report, itemID)
			if !ok {
				return fmt.Errorf("item %q not found in framework %q", itemID, frameworkID)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"schema_version": "agentprovenance.compliance_explain/v1",
					"framework":      report.Framework,
					"framework_name": report.FrameworkName,
					"run_id":         report.RunID,
					"item":           item,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "framework=%s run=%s item=%s status=%s evidence=%d\n",
				report.Framework, report.RunID, item.ItemID, item.Status, len(item.EvidenceRefs))
			fmt.Fprintf(cmd.OutOrStdout(), "title=%q\n", item.Title)
			fmt.Fprintf(cmd.OutOrStdout(), "reason=%q\n", item.Reason)
			if item.Gap != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "gap=%q\n", item.Gap)
			}
			if item.RecommendedNextStep != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "next_step=%q\n", item.RecommendedNextStep)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "REF\tKIND\tID\tSUMMARY")
			for _, ref := range item.EvidenceRefs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ref.Ref, ref.Kind, ref.ID, ref.Summary)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&frameworkID, "framework", "", "framework id, such as owasp-asi or nist-rfi-2026-00206")
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&itemID, "item", "", "framework item id")
	cmd.Flags().StringVar(&legacyControlID, "control", "", "deprecated alias for --item")
	cmd.Flags().StringVar(&ruleSetPath, "ruleset", "", "optional custom compliance ruleset YAML")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func complianceGapsCmd(dataDir *string) *cobra.Command {
	var frameworkID, runID string
	var jsonOut, missingOnly bool
	var ruleSetPath string
	var limit int
	cmd := &cobra.Command{
		Use:   "gaps",
		Short: "list missing or partial evidence items for one run",
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
			})
			if err != nil {
				return err
			}
			gaps := compliance.Gaps(report, missingOnly, limit)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(gaps)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "framework=%s run=%s schema=%s partial=%d missing=%d total=%d\n",
				gaps.Framework, gaps.RunID, gaps.SchemaVersion, gaps.Summary.Partial, gaps.Summary.Missing, gaps.Summary.Total)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ITEM\tSTATUS\tEVIDENCE\tGAP\tNEXT_STEP")
			for _, item := range gaps.Items {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", item.ItemID, item.Status, len(item.EvidenceRefs), item.Gap, item.RecommendedNextStep)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&frameworkID, "framework", "", "framework id, such as owasp-asi or nist-rfi-2026-00206")
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&ruleSetPath, "ruleset", "", "optional custom compliance ruleset YAML")
	cmd.Flags().BoolVar(&missingOnly, "missing-only", false, "only list items with no matching evidence")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum number of gap items to return")
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
