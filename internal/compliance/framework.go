package compliance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
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
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Disclaimer  string    `json:"disclaimer"`
	Controls    []Control `json:"controls"`
}

type Control struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence"`
	Partial     []string `json:"partial,omitempty"`
	NotApplies  []string `json:"not_applicable,omitempty"`
	Gap         string   `json:"gap"`
	NextStep    string   `json:"recommended_next_step"`
}

type MappingOptions struct {
	Framework string
	RunID     string
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

func Frameworks() []Framework {
	items := []Framework{owaspASI(), nistRFI()}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func GetFramework(id string) (Framework, bool) {
	for _, framework := range Frameworks() {
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
	framework, ok := GetFramework(opts.Framework)
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
