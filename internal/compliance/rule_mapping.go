package compliance

// Rule-based compliance mapping.
//
// The older evidence-class mapping (framework.go::MapRun) answers "does the run
// contain ANY evidence of class X?" -- which marks a control "covered" merely
// because some policy_decision and some risk_signal exist anywhere in the run,
// regardless of whether they pertain to that threat. That is not a defensible
// compliance claim.
//
// This file answers the question the owner actually wants: map each concrete
// detection RULE (security.Rule, with its Controls tags) onto the framework's
// controls, then report -- per control -- whether a mapped rule actually fired
// in this run, and if so whether it ENFORCED (blocked) or only DETECTED
// (observed, detect-mode default). Four honest states result:
//
//	enforced       a mapped rule fired AND blocked (deny/quarantine/kill)
//	detected       a mapped rule fired but was detect-only (not blocked)
//	not_triggered  mapped rule(s) exist but none fired this run
//	no_rule        no detection rule maps to this control (no event source yet)
//
// "no_rule" is deliberately distinct from "not_triggered": a control with no
// rule is an honest coverage gap, NOT a clean pass. Authoring a phantom rule for
// a control whose triggering event the system never emits would make it show a
// permanent (fake) not_triggered -- worse than admitting there is no detector.

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/security"
)

const RuleMappingSchemaVersion = "agentprovenance.compliance_rule_mapping/v1"

type RuleStatus string

const (
	RuleStatusEnforced     RuleStatus = "enforced"
	RuleStatusDetected     RuleStatus = "detected"
	RuleStatusNotTriggered RuleStatus = "not_triggered"
	RuleStatusNoRule       RuleStatus = "no_rule"
)

// RuleView is one detection rule mapped to a control, plus how it behaved this
// run. Mode/Intended come from the rule definition; Fired/Enforced from the
// run's policy_decisions.
type RuleView struct {
	ID       string `json:"id"`
	Reason   string `json:"reason"`
	Mode     string `json:"mode"`              // enforce | detect
	Intended string `json:"intended_decision"` // deny | quarantine | kill
	Fired    int    `json:"fired"`
	Enforced bool   `json:"enforced"`
}

type RuleControlResult struct {
	ControlID    string        `json:"control_id"`
	Title        string        `json:"title"`
	Description  string        `json:"description"`
	Status       RuleStatus    `json:"status"`
	Rules        []RuleView    `json:"rules"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
	Gap          string        `json:"gap"`
	NextStep     string        `json:"recommended_next_step"`
	Reason       string        `json:"reason"`
}

type RuleMappingSummary struct {
	Enforced     int `json:"enforced"`
	Detected     int `json:"detected"`
	NotTriggered int `json:"not_triggered"`
	NoRule       int `json:"no_rule"`
	Total        int `json:"total"`
}

type RuleMappingReport struct {
	SchemaVersion string              `json:"schema_version"`
	Framework     string              `json:"framework"`
	FrameworkName string              `json:"framework_name"`
	RunID         string              `json:"run_id"`
	Disclaimer    string              `json:"disclaimer"`
	Summary       RuleMappingSummary  `json:"summary"`
	Items         []RuleControlResult `json:"items"`
}

type RuleMappingOptions struct {
	Framework string
	RunID     string
	// Rules is the detection rule set to map from. When nil it defaults to
	// security.DefaultRules(). A deployment running a custom YAML engine should
	// pass that engine's rules so custom rules (with their own controls: tags)
	// participate in the mapping.
	Rules []security.Rule
}

func ruleMode(r security.Rule) string {
	if strings.EqualFold(r.Mode, "detect") {
		return "detect"
	}
	return "enforce"
}

// MapRunRules maps the configured detection rules onto a framework's controls
// for one run and reports the four-state coverage above.
func MapRunRules(db *sql.DB, opts RuleMappingOptions) (RuleMappingReport, error) {
	if opts.Framework == "" {
		return RuleMappingReport{}, fmt.Errorf("framework is required")
	}
	if opts.RunID == "" {
		return RuleMappingReport{}, fmt.Errorf("run is required")
	}
	framework, ok := GetFramework(opts.Framework)
	if !ok {
		return RuleMappingReport{}, fmt.Errorf("unknown framework %q", opts.Framework)
	}
	rules := opts.Rules
	if rules == nil {
		rules = security.DefaultRules()
	}
	rulesByControl := map[string][]security.Rule{}
	for _, r := range rules {
		for _, c := range r.Controls {
			rulesByControl[c] = append(rulesByControl[c], r)
		}
	}

	decisions, err := security.ListDecisions(db, opts.RunID)
	if err != nil {
		return RuleMappingReport{}, err
	}
	firedByRule := map[string][]security.DecisionRecord{}
	for _, d := range decisions {
		if d.RuleID == "" {
			continue
		}
		firedByRule[d.RuleID] = append(firedByRule[d.RuleID], d)
	}
	// Index linked risk signals by the policy decision that produced them so a
	// fired control can also surface its risk_signal refs (clickable in the UI).
	risks, err := security.ListRiskSignals(db, opts.RunID)
	if err != nil {
		return RuleMappingReport{}, err
	}
	risksByDecision := map[string][]security.RiskSignalRecord{}
	for _, rs := range risks {
		if rs.PolicyDecisionID != "" {
			risksByDecision[rs.PolicyDecisionID] = append(risksByDecision[rs.PolicyDecisionID], rs)
		}
	}

	report := RuleMappingReport{
		SchemaVersion: RuleMappingSchemaVersion,
		Framework:     framework.ID,
		FrameworkName: framework.Title,
		RunID:         opts.RunID,
		Disclaimer:    framework.Disclaimer,
	}
	for _, control := range framework.Controls {
		res := mapControlByRules(control, rulesByControl[control.ID], firedByRule, risksByDecision)
		report.Items = append(report.Items, res)
		switch res.Status {
		case RuleStatusEnforced:
			report.Summary.Enforced++
		case RuleStatusDetected:
			report.Summary.Detected++
		case RuleStatusNotTriggered:
			report.Summary.NotTriggered++
		case RuleStatusNoRule:
			report.Summary.NoRule++
		}
	}
	report.Summary.Total = len(report.Items)
	return report, nil
}

func mapControlByRules(control Control, mapped []security.Rule, firedByRule map[string][]security.DecisionRecord, risksByDecision map[string][]security.RiskSignalRecord) RuleControlResult {
	res := RuleControlResult{
		ControlID:   control.ID,
		Title:       control.Title,
		Description: control.Description,
		NextStep:    control.NextStep,
	}
	if len(mapped) == 0 {
		res.Status = RuleStatusNoRule
		res.Gap = "no detection rule maps to this control yet"
		res.Reason = "no rule maps to this control, so this run can neither confirm nor deny it"
		// control.NextStep already describes how to start covering it.
		return res
	}

	anyFired := false
	anyEnforced := false
	seenRef := map[string]bool{}
	for _, r := range mapped {
		fired := firedByRule[r.ID]
		view := RuleView{ID: r.ID, Reason: r.Reason, Mode: ruleMode(r), Intended: r.Decision, Fired: len(fired)}
		for _, d := range fired {
			if security.IsEnforcingDecision(d.Decision) {
				view.Enforced = true
				anyEnforced = true
			}
			ref := "policy_decision/" + d.ID
			if !seenRef[ref] {
				seenRef[ref] = true
				res.EvidenceRefs = append(res.EvidenceRefs, EvidenceRef{
					Ref:     ref,
					Kind:    "policy_decision",
					ID:      d.ID,
					Summary: fmt.Sprintf("decision=%s rule=%s reason=%s", d.Decision, d.RuleID, d.Reason),
				})
			}
			for _, rs := range risksByDecision[d.ID] {
				rref := "risk_signal/" + rs.ID
				if !seenRef[rref] {
					seenRef[rref] = true
					res.EvidenceRefs = append(res.EvidenceRefs, EvidenceRef{
						Ref:     rref,
						Kind:    "risk_signal",
						ID:      rs.ID,
						Summary: fmt.Sprintf("%s severity=%s action=%s", rs.SignalType, rs.Severity, rs.RecommendedAction),
					})
				}
			}
		}
		if len(fired) > 0 {
			anyFired = true
		}
		res.Rules = append(res.Rules, view)
	}

	switch {
	case anyEnforced:
		res.Status = RuleStatusEnforced
		res.Reason = "a mapped rule fired and blocked the action in this run"
	case anyFired:
		res.Status = RuleStatusDetected
		res.Reason = "a mapped rule fired but is detect-only, so the action was observed, not blocked"
		res.Gap = "threat detected but not enforced (rule runs in detect mode)"
		res.NextStep = "set the mapped rule(s) to enforce mode to block, not just record, this activity"
	default:
		res.Status = RuleStatusNotTriggered
		res.Reason = "rule(s) map to this control but none matched any activity in this run"
	}
	return res
}
