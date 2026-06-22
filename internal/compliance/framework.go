package compliance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

const SchemaVersion = "agentprovenance.compliance_mapping/v1"

type Status string

const (
	StatusCovered       Status = "covered"
	StatusPartial       Status = "partial"
	StatusMissing       Status = "missing"
	StatusNotApplicable Status = "not_applicable"
)

type Framework struct {
	ID          string    `json:"id" yaml:"id"`
	Title       string    `json:"title" yaml:"title"`
	Description string    `json:"description" yaml:"description"`
	Disclaimer  string    `json:"disclaimer" yaml:"disclaimer"`
	Controls    []Control `json:"controls" yaml:"controls"`
}

type RuleSet struct {
	SchemaVersion string      `json:"schema_version" yaml:"schema_version"`
	ID            string      `json:"id" yaml:"id"`
	Title         string      `json:"title" yaml:"title"`
	Description   string      `json:"description" yaml:"description"`
	Disclaimer    string      `json:"disclaimer" yaml:"disclaimer"`
	Frameworks    []Framework `json:"frameworks" yaml:"frameworks"`
	Rules         []Rule      `json:"rules" yaml:"rules"`
	Mappings      []Mapping   `json:"mappings" yaml:"mappings"`
}

type Rule struct {
	ID          string   `json:"id" yaml:"id"`
	Title       string   `json:"title" yaml:"title"`
	Description string   `json:"description" yaml:"description"`
	Evidence    []string `json:"evidence" yaml:"evidence"`
	Partial     []string `json:"partial,omitempty" yaml:"partial"`
	NotApplies  []string `json:"not_applicable,omitempty" yaml:"not_applicable"`
	Gap         string   `json:"gap" yaml:"gap"`
	NextStep    string   `json:"recommended_next_step" yaml:"recommended_next_step"`
}

type Mapping struct {
	Framework       string   `json:"framework" yaml:"framework"`
	Rules           []string `json:"rules" yaml:"rules"`
	BuiltinControls []string `json:"builtin_controls" yaml:"builtin_controls"`
}

type Control struct {
	ID          string   `json:"id" yaml:"id"`
	Title       string   `json:"title" yaml:"title"`
	Description string   `json:"description" yaml:"description"`
	Evidence    []string `json:"evidence" yaml:"evidence"`
	Partial     []string `json:"partial,omitempty" yaml:"partial"`
	NotApplies  []string `json:"not_applicable,omitempty" yaml:"not_applicable"`
	Gap         string   `json:"gap" yaml:"gap"`
	NextStep    string   `json:"recommended_next_step" yaml:"recommended_next_step"`
}

type MappingOptions struct {
	Framework string
	RunID     string
	RuleSet   *RuleSet
	Only      []string
	Exclude   []string
}

type MappingReport struct {
	SchemaVersion string          `json:"schema_version"`
	Framework     string          `json:"framework"`
	FrameworkName string          `json:"framework_name"`
	RunID         string          `json:"run_id"`
	Disclaimer    string          `json:"disclaimer"`
	Summary       MappingSummary  `json:"summary"`
	Items         []MappingResult `json:"items"`
}

type MappingSummary struct {
	Covered       int `json:"covered"`
	Partial       int `json:"partial"`
	Missing       int `json:"missing"`
	NotApplicable int `json:"not_applicable"`
	Total         int `json:"total"`
}

type MappingResult struct {
	Framework           string        `json:"framework"`
	ControlID           string        `json:"control_id"`
	Title               string        `json:"title"`
	Status              Status        `json:"status"`
	EvidenceRefs        []EvidenceRef `json:"evidence_refs"`
	Gap                 string        `json:"gap"`
	RecommendedNextStep string        `json:"recommended_next_step"`
	Reason              string        `json:"reason"`
}

type EvidenceRef struct {
	Ref     string `json:"ref"`
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Summary string `json:"summary,omitempty"`
}

func Frameworks(ruleSets ...RuleSet) []Framework {
	items := []Framework{owaspASI(), nistRFI()}
	for _, ruleSet := range ruleSets {
		items = mergeRuleSet(items, ruleSet)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func GetFramework(id string, ruleSets ...RuleSet) (Framework, bool) {
	for _, framework := range Frameworks(ruleSets...) {
		if framework.ID == id {
			return framework, true
		}
	}
	return Framework{}, false
}

func MapRun(db *sql.DB, opts MappingOptions) (MappingReport, error) {
	if opts.Framework == "" {
		return MappingReport{}, fmt.Errorf("framework is required")
	}
	if opts.RunID == "" {
		return MappingReport{}, fmt.Errorf("run is required")
	}
	var ruleSets []RuleSet
	if opts.RuleSet != nil {
		ruleSets = append(ruleSets, *opts.RuleSet)
	}
	framework, ok := GetFramework(opts.Framework, ruleSets...)
	if !ok {
		return MappingReport{}, fmt.Errorf("unknown framework %q", opts.Framework)
	}
	index, err := ResolveEvidence(db, opts.RunID)
	if err != nil {
		return MappingReport{}, err
	}
	report := MappingReport{
		SchemaVersion: SchemaVersion,
		Framework:     framework.ID,
		FrameworkName: framework.Title,
		RunID:         opts.RunID,
		Disclaimer:    framework.Disclaimer,
	}
	for _, control := range framework.Controls {
		if !includeControl(control.ID, opts.Only, opts.Exclude) {
			continue
		}
		result := mapControl(framework.ID, control, index)
		report.Items = append(report.Items, result)
		switch result.Status {
		case StatusCovered:
			report.Summary.Covered++
		case StatusPartial:
			report.Summary.Partial++
		case StatusMissing:
			report.Summary.Missing++
		case StatusNotApplicable:
			report.Summary.NotApplicable++
		}
	}
	report.Summary.Total = len(report.Items)
	return report, nil
}

func includeControl(controlID string, only, exclude []string) bool {
	if len(only) > 0 {
		found := false
		for _, id := range only {
			if id == controlID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, id := range exclude {
		if id == controlID {
			return false
		}
	}
	return true
}

func LoadRuleSet(path string) (RuleSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return RuleSet{}, err
	}
	var ruleSet RuleSet
	if err := yaml.Unmarshal(raw, &ruleSet); err != nil {
		return RuleSet{}, err
	}
	if err := ruleSet.Validate(); err != nil {
		return RuleSet{}, err
	}
	return ruleSet, nil
}

func (r RuleSet) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("ruleset id is required")
	}
	ruleIDs := map[string]bool{}
	for _, rule := range r.Rules {
		if rule.ID == "" {
			return fmt.Errorf("ruleset %s has rule with empty id", r.ID)
		}
		if ruleIDs[rule.ID] {
			return fmt.Errorf("ruleset %s has duplicate rule %s", r.ID, rule.ID)
		}
		if len(rule.Evidence) == 0 && len(rule.Partial) == 0 && len(rule.NotApplies) == 0 {
			return fmt.Errorf("rule %s must define evidence, partial, or not_applicable", rule.ID)
		}
		ruleIDs[rule.ID] = true
	}
	for _, framework := range r.Frameworks {
		if framework.ID == "" {
			return fmt.Errorf("ruleset %s has framework with empty id", r.ID)
		}
	}
	for _, mapping := range r.Mappings {
		if mapping.Framework == "" {
			return fmt.Errorf("ruleset %s has mapping with empty framework", r.ID)
		}
		if len(mapping.Rules) == 0 && len(mapping.BuiltinControls) == 0 {
			return fmt.Errorf("mapping for framework %s must reference rules or builtin_controls", mapping.Framework)
		}
		for _, ruleID := range mapping.Rules {
			if !ruleIDs[ruleID] {
				return fmt.Errorf("mapping for framework %s references unknown rule %s", mapping.Framework, ruleID)
			}
		}
	}
	return nil
}

func mergeRuleSet(base []Framework, ruleSet RuleSet) []Framework {
	frameworks := append([]Framework{}, base...)
	byID := map[string]int{}
	for i, framework := range frameworks {
		byID[framework.ID] = i
	}
	for _, framework := range ruleSet.Frameworks {
		if framework.Disclaimer == "" {
			framework.Disclaimer = firstNonEmpty(ruleSet.Disclaimer, disclaimer)
		}
		if idx, ok := byID[framework.ID]; ok {
			frameworks[idx].Title = firstNonEmpty(framework.Title, frameworks[idx].Title)
			frameworks[idx].Description = firstNonEmpty(framework.Description, frameworks[idx].Description)
			frameworks[idx].Disclaimer = firstNonEmpty(framework.Disclaimer, frameworks[idx].Disclaimer)
			frameworks[idx].Controls = append(frameworks[idx].Controls, framework.Controls...)
			continue
		}
		frameworks = append(frameworks, framework)
		byID[framework.ID] = len(frameworks) - 1
	}
	rules := map[string]Rule{}
	for _, rule := range ruleSet.Rules {
		rules[rule.ID] = rule
	}
	builtinControls := builtinControlIndex(base)
	for _, mapping := range ruleSet.Mappings {
		idx, ok := byID[mapping.Framework]
		if !ok {
			frameworks = append(frameworks, Framework{
				ID:         mapping.Framework,
				Title:      mapping.Framework,
				Disclaimer: firstNonEmpty(ruleSet.Disclaimer, disclaimer),
			})
			idx = len(frameworks) - 1
			byID[mapping.Framework] = idx
		}
		for _, controlID := range mapping.BuiltinControls {
			control, ok := builtinControls[controlID]
			if !ok {
				continue
			}
			frameworks[idx].Controls = append(frameworks[idx].Controls, control)
		}
		for _, ruleID := range mapping.Rules {
			rule := rules[ruleID]
			frameworks[idx].Controls = append(frameworks[idx].Controls, Control{
				ID:          rule.ID,
				Title:       rule.Title,
				Description: rule.Description,
				Evidence:    rule.Evidence,
				Partial:     rule.Partial,
				NotApplies:  rule.NotApplies,
				Gap:         rule.Gap,
				NextStep:    rule.NextStep,
			})
		}
	}
	return frameworks
}

func builtinControlIndex(frameworks []Framework) map[string]Control {
	out := map[string]Control{}
	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			out[control.ID] = control
			out[framework.ID+":"+control.ID] = control
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func mapControl(frameworkID string, control Control, index EvidenceIndex) MappingResult {
	requiredRefs, requiredOK := index.RequiredRefs(control.Evidence...)
	partialRefs := index.Refs(append(control.Evidence, control.Partial...)...)
	naRefs := index.Refs(control.NotApplies...)
	refs := requiredRefs
	status := StatusCovered
	reason := "all required evidence classes were found"
	switch {
	case requiredOK:
	case len(partialRefs) > 0:
		status = StatusPartial
		refs = partialRefs
		reason = "only partial evidence classes were found"
	case len(naRefs) > 0:
		status = StatusNotApplicable
		refs = naRefs
		reason = "run contains evidence that makes this control not applicable"
	default:
		status = StatusMissing
		refs = nil
		reason = "no matching runtime evidence was found"
	}
	return MappingResult{
		Framework:           frameworkID,
		ControlID:           control.ID,
		Title:               control.Title,
		Status:              status,
		EvidenceRefs:        refs,
		Gap:                 gapForStatus(status, control),
		RecommendedNextStep: control.NextStep,
		Reason:              reason,
	}
}

func gapForStatus(status Status, control Control) string {
	if status == StatusCovered || status == StatusNotApplicable {
		return ""
	}
	if control.Gap != "" {
		return control.Gap
	}
	return "collect more runtime evidence for this control"
}

func (r MappingReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
