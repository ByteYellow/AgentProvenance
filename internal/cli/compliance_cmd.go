package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/compliance"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/spf13/cobra"
)

func complianceCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "map a run's detection-rule coverage to security framework items",
		Long:  "Map AgentProvenance detection rules to security framework items as an evidence-backed self-assessment: per control, whether a mapped rule fired this run and whether it enforced (blocked) or only detected. This is not certification or legal advice.",
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

// complianceMappingOptions assembles the shared options (custom framework
// catalogs via --ruleset, custom detection rules via --rules, control filters)
// so every subcommand maps the same way.
func complianceMappingOptions(frameworkID, runID, ruleSetPath, rulesPath, onlyCSV, excludeCSV string) (compliance.RuleMappingOptions, error) {
	opts := compliance.RuleMappingOptions{
		Framework: frameworkID,
		RunID:     runID,
		Only:      csvList(onlyCSV),
		Exclude:   csvList(excludeCSV),
	}
	if ruleSetPath != "" {
		ruleSet, err := compliance.LoadRuleSet(ruleSetPath)
		if err != nil {
			return opts, err
		}
		opts.RuleSets = []compliance.RuleSet{ruleSet}
	}
	if rulesPath != "" {
		engine, err := security.LoadEngine(rulesPath)
		if err != nil {
			return opts, err
		}
		opts.Rules = engine.Rules
	}
	return opts, nil
}

func complianceMapCmd(dataDir *string, use string) *cobra.Command {
	var frameworkID, runID string
	var jsonOut bool
	var ruleSetPath, rulesPath string
	var onlyCSV, excludeCSV string
	cmd := &cobra.Command{
		Use:   use,
		Short: "map run detection-rule coverage to a compliance/security framework",
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
			opts, err := complianceMappingOptions(frameworkID, runID, ruleSetPath, rulesPath, onlyCSV, excludeCSV)
			if err != nil {
				return err
			}
			report, err := compliance.MapRunRules(db, opts)
			if err != nil {
				return err
			}
			if jsonOut || use == "report" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			s := report.Summary
			fmt.Fprintf(cmd.OutOrStdout(), "framework=%s run=%s schema=%s enforced=%d detected=%d not_triggered=%d no_rule=%d total=%d\n",
				report.Framework, report.RunID, report.SchemaVersion, s.Enforced, s.Detected, s.NotTriggered, s.NoRule, s.Total)
			fmt.Fprintf(cmd.OutOrStdout(), "disclaimer=%q\n", report.Disclaimer)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ITEM\tSTATUS\tRULES\tHITS\tGAP\tNEXT_STEP")
			for _, item := range report.Items {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", item.ControlID, item.Status, len(item.Rules), ruleHitTotal(item), item.Gap, item.NextStep)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&frameworkID, "framework", "", "framework id, such as owasp-asi or nist-rfi-2026-00206")
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&ruleSetPath, "ruleset", "", "optional custom compliance ruleset YAML (adds frameworks/controls)")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "optional custom detection rule YAML (security engine rules with controls:)")
	cmd.Flags().StringVar(&onlyCSV, "only", "", "comma-separated item ids to evaluate")
	cmd.Flags().StringVar(&excludeCSV, "exclude", "", "comma-separated item ids to skip")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func complianceExplainCmd(dataDir *string) *cobra.Command {
	var frameworkID, runID, itemID, legacyControlID string
	var jsonOut bool
	var ruleSetPath, rulesPath string
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "explain the detection rules and hits behind one framework item",
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
			opts, err := complianceMappingOptions(frameworkID, runID, ruleSetPath, rulesPath, itemID, "")
			if err != nil {
				return err
			}
			report, err := compliance.MapRunRules(db, opts)
			if err != nil {
				return err
			}
			item, ok := compliance.FindRuleItem(report, itemID)
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
			fmt.Fprintf(cmd.OutOrStdout(), "framework=%s run=%s item=%s status=%s rules=%d hits=%d\n",
				report.Framework, report.RunID, item.ControlID, item.Status, len(item.Rules), ruleHitTotal(item))
			fmt.Fprintf(cmd.OutOrStdout(), "title=%q\n", item.Title)
			fmt.Fprintf(cmd.OutOrStdout(), "reason=%q\n", item.Reason)
			if item.Gap != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "gap=%q\n", item.Gap)
			}
			if item.NextStep != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "next_step=%q\n", item.NextStep)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "RULE\tMODE\tINTENDED\tFIRED\tENFORCED")
			for _, r := range item.Rules {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%t\n", r.ID, r.Mode, r.Intended, r.Fired, r.Enforced)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			// Individual hits (each firing) so a reviewer sees every occurrence.
			hw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			hasHits := false
			for _, r := range item.Rules {
				for _, h := range r.Hits {
					if !hasHits {
						fmt.Fprintln(hw, "HIT_RULE\tTIME\tDECISION\tREF")
						hasHits = true
					}
					fmt.Fprintf(hw, "%s\t%s\t%s\t%s\n", r.ID, h.CreatedAt, h.Decision, h.Ref)
				}
			}
			if hasHits {
				return hw.Flush()
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&frameworkID, "framework", "", "framework id, such as owasp-asi or nist-rfi-2026-00206")
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&itemID, "item", "", "framework item id")
	cmd.Flags().StringVar(&legacyControlID, "control", "", "deprecated alias for --item")
	cmd.Flags().StringVar(&ruleSetPath, "ruleset", "", "optional custom compliance ruleset YAML")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "optional custom detection rule YAML")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func complianceGapsCmd(dataDir *string) *cobra.Command {
	var frameworkID, runID string
	var jsonOut, noRuleOnly bool
	var ruleSetPath, rulesPath string
	var limit int
	cmd := &cobra.Command{
		Use:   "gaps",
		Short: "list controls that need attention: detected-not-blocked or no-rule",
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
			opts, err := complianceMappingOptions(frameworkID, runID, ruleSetPath, rulesPath, "", "")
			if err != nil {
				return err
			}
			report, err := compliance.MapRunRules(db, opts)
			if err != nil {
				return err
			}
			gaps := compliance.RuleGaps(report, noRuleOnly, limit)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(gaps)
			}
			s := gaps.Summary
			fmt.Fprintf(cmd.OutOrStdout(), "framework=%s run=%s schema=%s detected=%d no_rule=%d total=%d\n",
				gaps.Framework, gaps.RunID, gaps.SchemaVersion, s.Detected, s.NoRule, s.Total)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ITEM\tSTATUS\tRULES\tHITS\tGAP\tNEXT_STEP")
			for _, item := range gaps.Items {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", item.ControlID, item.Status, len(item.Rules), ruleHitTotal(item), item.Gap, item.NextStep)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&frameworkID, "framework", "", "framework id, such as owasp-asi or nist-rfi-2026-00206")
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&ruleSetPath, "ruleset", "", "optional custom compliance ruleset YAML")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "optional custom detection rule YAML")
	cmd.Flags().BoolVar(&noRuleOnly, "no-rule-only", false, "only list controls with no mapped detector")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum number of gap items to return")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func ruleHitTotal(item compliance.RuleControlResult) int {
	total := 0
	for _, r := range item.Rules {
		total += r.Fired
	}
	return total
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
