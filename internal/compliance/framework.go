package compliance

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// This file defines the framework/control CATALOG and the custom-ruleset loader.
// The actual run-to-control mapping lives in rule_mapping.go (MapRunRules), which
// maps concrete detection rules onto these controls. The older evidence-class
// mapping was removed in favour of that single model.

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

// EvidenceRef is one entity-backed piece of evidence for a control (e.g. a
// policy_decision or risk_signal). Its "kind/id" resolves to a graph-lens node,
// so the dashboard cross-links it back to the graph.
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
