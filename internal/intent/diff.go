package intent

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

func isBaselineForbidden(k EffectKind) bool {
	for _, b := range baselineForbidden {
		if b == k {
			return true
		}
	}
	return false
}

// Diff states. v1 deliberately ships the security-relevant states and the
// honesty state, and does NOT emit executed_without_intent (which needs
// complete intent capture to avoid false positives -- an effect with no
// contract is reported as intent_coverage_gap, not as a rogue action).
const (
	StatusMismatch       = "declared_vs_effect_mismatch"  // effect violates the contract boundary
	StatusRefusedBypass  = "refused_but_runtime_happened" // a refused action's effects happened anyway
	StatusExecuted       = "decided_and_executed"         // declared effects appeared, no violation
	StatusCoverageGap    = "intent_coverage_gap"          // effects seen for a scope with NO captured intent
	StatusAssociationGap = "intent_association_gap"       // intent exists, but operation-level attribution is unresolved
)

// FindingPeerMessageMismatch marks a boundary violation whose intent originated
// from a peer message -- the multi-agent lateral-influence finding.
const FindingPeerMessageMismatch = "peer_message_intent_mismatch"

const RuleVersion = "agentprov.intent_scope/v4"

type IntentCandidate struct {
	ContractID   string   `json:"contract_id"`
	Kind         string   `json:"kind"`
	Source       string   `json:"source"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	Basis        []string `json:"basis"`
}

type IntentAssociation struct {
	Status       string            `json:"status"`
	Basis        []string          `json:"basis,omitempty"`
	EvidenceRefs []string          `json:"evidence_refs,omitempty"`
	Candidates   []IntentCandidate `json:"candidates,omitempty"`
}

// IntentRuntimeDiff is one reconciliation of a contract against the effects
// attributed to its scope.
type IntentRuntimeDiff struct {
	ID             string            `json:"id"`
	RunID          string            `json:"run_id"`
	AgentID        string            `json:"agent_id"`
	ToolCallID     string            `json:"tool_call_id,omitempty"`
	ContractKind   string            `json:"contract_kind"`
	Operation      string            `json:"operation"`
	Target         string            `json:"target"`
	Status         string            `json:"status"`
	Finding        string            `json:"finding,omitempty"`
	Confidence     float64           `json:"confidence"`
	Declared       []EffectKind      `json:"declared_effects"`
	Forbidden      []EffectKind      `json:"forbidden_effects"`
	Observed       []EffectKind      `json:"observed_effects"`
	MismatchReason string            `json:"mismatch_reason,omitempty"`
	Source         string            `json:"source"`
	RuleVersion    string            `json:"rule_version"`
	EventIDs       []string          `json:"event_ids,omitempty"`
	Association    IntentAssociation `json:"association"`
}

// Diff reconciles contracts against runtime effects and returns typed diffs.
func Diff(contracts []IntentContract, effects []RuntimeEffect) []IntentRuntimeDiff {
	byAgent := map[string][]int{}
	byToolCall := map[string][]int{}
	covered := make([]bool, len(effects))
	unbound := make(map[int][]IntentCandidate)
	for i, e := range effects {
		byAgent[e.AgentID] = append(byAgent[e.AgentID], i)
		if e.ToolCallID != "" {
			byToolCall[e.ToolCallID] = append(byToolCall[e.ToolCallID], i)
		}
	}

	var out []IntentRuntimeDiff
	for _, c := range contracts {
		var candidates []int
		if c.ScopeAgent != "" {
			candidates = byAgent[c.ScopeAgent]
		}
		policy := c.Kind == ContractPeerMessage && c.ScopeKind == "agent_policy"
		if !policy {
			if c.Kind == ContractPeerMessage && c.ToolCallID == "" {
				for _, index := range candidates {
					e := effects[index]
					if (isBaselineForbidden(e.Kind) || c.Profile.forbiddenSet()[e.Kind]) && messageMayPrecede(c.ObservedAt, e.ObservedAt) {
						basis := []string{"same_agent"}
						if validTime(c.ObservedAt) && validTime(e.ObservedAt) {
							basis = append(basis, "message_not_after_effect")
						} else {
							basis = append(basis, "time_unknown")
						}
						unbound[index] = append(unbound[index], IntentCandidate{ContractID: c.ID, Kind: c.Kind, Source: c.Source, EvidenceRefs: c.EvidenceRefs, Basis: basis})
					}
				}
				continue
			}
			// Tool calls, refusals and explicit delegations share the same scope.
			candidates = nil
			if c.ToolCallID != "" {
				candidates = byToolCall[c.ToolCallID]
			}
		}
		var scope []RuntimeEffect
		for _, index := range candidates {
			e := effects[index]
			if c.Kind == ContractPeerMessage && !messageMayPrecede(c.ObservedAt, e.ObservedAt) {
				continue
			}
			if policy && !policyApplies(c, e) {
				continue
			}
			if c.ScopeAgent != "" && e.AgentID != "" && c.ScopeAgent != e.AgentID {
				continue
			}
			covered[index] = true
			scope = append(scope, e)
		}

		forbidden := c.Profile.forbiddenSet()
		if c.Negative {
			// A refusal forbids every baseline-sensitive effect outright.
			forbidden = map[EffectKind]bool{}
			for _, e := range baselineForbidden {
				forbidden[e] = true
			}
		}

		var violating []RuntimeEffect
		observedKinds := map[EffectKind]bool{}
		for _, e := range scope {
			observedKinds[e.Kind] = true
			if forbidden[e.Kind] {
				violating = append(violating, e)
			}
		}
		if len(violating) == 0 {
			// No boundary violation. Emit a green baseline only when the declared
			// effects actually appeared (proof the intent executed as claimed).
			if declaredObserved(c.Profile.Declared, observedKinds) && len(scope) > 0 {
				out = append(out, IntentRuntimeDiff{
					ID: "diff/" + trimContract(c.ID) + "/ok", RunID: "", AgentID: c.ScopeAgent, ToolCallID: c.ToolCallID,
					ContractKind: c.Kind, Operation: c.Operation, Target: c.Target,
					Status: StatusExecuted, Confidence: violationConfidence(c, scope),
					Declared: c.Profile.Declared, Observed: kindsOf(scope), Source: c.Source, EventIDs: eventIDsOf(scope),
					Association: contractAssociation(c, scope),
				})
			}
			continue
		}

		status := StatusMismatch
		finding := ""
		reason := c.Operation + " produced effects it does not permit: " + joinKinds(kindsOf(violating))
		switch {
		case c.Negative:
			status = StatusRefusedBypass
			reason = "agent refused this action but its runtime produced: " + joinKinds(kindsOf(violating))
		case c.Kind == ContractPeerMessage:
			finding = FindingPeerMessageMismatch
			reason = "effects attributed to this peer contract exceed its declared boundary: " + joinKinds(kindsOf(violating))
		}
		out = append(out, IntentRuntimeDiff{
			ID: "diff/" + trimContract(c.ID), AgentID: c.ScopeAgent, ToolCallID: c.ToolCallID,
			ContractKind: c.Kind, Operation: c.Operation, Target: c.Target,
			Status: status, Finding: finding, Confidence: violationConfidence(c, violating),
			Declared: c.Profile.Declared, Forbidden: sortedForbidden(forbidden), Observed: kindsOf(violating),
			MismatchReason: reason, Source: c.Source, EventIDs: eventIDsOf(violating),
			Association: contractAssociation(c, violating),
		})
	}

	// Honesty: a baseline-sensitive effect (foreign-secret read, metadata egress,
	// private-CIDR reach) that we could NOT tie to any captured contract is a
	// coverage gap, NOT a rogue action -- we will not claim "executed without
	// intent" when we may simply have failed to capture the intent (in-process
	// sub-agents share one kernel scope; command-match can miss). Benign effects
	// with no contract are not reported. Keep the most specific known scope.
	type gapScope struct {
		agent, tool, candidates string
	}
	gaps := map[gapScope][]RuntimeEffect{}
	candidateSets := map[gapScope][]IntentCandidate{}
	for index, e := range effects {
		if (!isBaselineForbidden(e.Kind) && len(unbound[index]) == 0) || (covered[index] && len(unbound[index]) == 0) {
			continue
		}
		cs := sortedCandidates(unbound[index])
		var ids []string
		for _, c := range cs {
			ids = append(ids, fmt.Sprintf("%d:%s", len(c.ContractID), c.ContractID))
		}
		key := gapScope{agent: e.AgentID, tool: e.ToolCallID, candidates: strings.Join(ids, "")}
		gaps[key] = append(gaps[key], e)
		candidateSets[key] = cs
	}
	for key, b := range gaps {
		scopeKey := fmt.Sprintf("%d:%s%d:%s%s", len(key.agent), key.agent, len(key.tool), key.tool, key.candidates)
		d := IntentRuntimeDiff{
			ID: fmt.Sprintf("diff/gap/%x", sha256.Sum256([]byte(scopeKey))), ContractKind: "none", Status: StatusCoverageGap, Confidence: 0,
			AgentID: key.agent, ToolCallID: key.tool,
			Observed:       kindsOf(b),
			MismatchReason: "sensitive runtime effects observed (" + joinKinds(kindsOf(b)) + ") but no intent contract was captured for this scope",
			Source:         "coverage", EventIDs: eventIDsOf(b),
			Association: IntentAssociation{Status: "missing", EvidenceRefs: effectRefs(b)},
		}
		if cs := candidateSets[key]; len(cs) > 0 {
			d.ContractKind, d.Status, d.Source = ContractPeerMessage, StatusAssociationGap, "association"
			d.MismatchReason = "sensitive effects recorded; peer messages share the agent scope but lack an operation binding"
			d.Association.Status, d.Association.Candidates = "candidate", cs
			d.Association.Basis = []string{"same_agent", "missing_operation_binding"}
			if len(cs) > 1 {
				d.Association.Status = "ambiguous"
			}
			for _, c := range cs {
				d.Association.EvidenceRefs = append(d.Association.EvidenceRefs, c.EvidenceRefs...)
			}
			d.Association.EvidenceRefs = uniqueStrings(d.Association.EvidenceRefs)
		}
		out = append(out, d)
	}

	for i := range out {
		out[i].RuleVersion = RuleVersion
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := statusRank(out[i].Status), statusRank(out[j].Status); a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func declaredObserved(declared []EffectKind, observed map[EffectKind]bool) bool {
	if len(declared) == 0 {
		return false
	}
	for _, d := range declared {
		if !observed[d] {
			return false
		}
	}
	return true
}

func violationConfidence(c IntentContract, violating []RuntimeEffect) float64 {
	// This grades the relation, not the quality of the original runtime event.
	min := max(0, min(1, c.Confidence))
	for _, e := range violating {
		if e.Confidence < min {
			min = e.Confidence
		}
	}
	return max(0, min)
}

func validTime(value string) bool { _, err := time.Parse(time.RFC3339Nano, value); return err == nil }

func messageMayPrecede(message, effect string) bool {
	m, me := time.Parse(time.RFC3339Nano, message)
	e, ee := time.Parse(time.RFC3339Nano, effect)
	return me != nil || ee != nil || !m.After(e)
}

func policyApplies(c IntentContract, e RuntimeEffect) bool {
	if c.ScopeAgent == "" || c.ScopeAgent != e.AgentID || c.ToolCallID != "" || len(c.EvidenceRefs) == 0 {
		return false
	}
	start, se := time.Parse(time.RFC3339Nano, c.ScopeStart)
	end, ee := time.Parse(time.RFC3339Nano, c.ScopeEnd)
	at, ae := time.Parse(time.RFC3339Nano, e.ObservedAt)
	return se == nil && ee == nil && ae == nil && end.After(start) && !at.Before(start) && at.Before(end)
}

func effectRefs(es []RuntimeEffect) []string {
	var refs []string
	for _, id := range eventIDsOf(es) {
		refs = append(refs, "runtime_event/"+id)
	}
	return refs
}

func contractAssociation(c IntentContract, es []RuntimeEffect) IntentAssociation {
	a := IntentAssociation{Status: "bound", Basis: []string{"tool_call_id"}, EvidenceRefs: append(effectRefs(es), c.EvidenceRefs...)}
	if c.ScopeKind == "agent_policy" {
		a.Status = "policy_scope"
		a.Basis = []string{"explicit_policy_scope", "validity_interval"}
	} else if c.ToolCallID != "" {
		a.EvidenceRefs = append(a.EvidenceRefs, c.ToolCallID)
	}
	a.EvidenceRefs = uniqueStrings(a.EvidenceRefs)
	return a
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" {
			seen[value] = true
		}
	}
	var out []string
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedCandidates(values []IntentCandidate) []IntentCandidate {
	byID := map[string]IntentCandidate{}
	for _, c := range values {
		byID[c.ContractID] = c
	}
	var out []IntentCandidate
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ContractID < out[j].ContractID })
	return out
}

func kindsOf(es []RuntimeEffect) []EffectKind {
	seen := map[EffectKind]bool{}
	var out []EffectKind
	for _, e := range es {
		if !seen[e.Kind] {
			seen[e.Kind] = true
			out = append(out, e.Kind)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func eventIDsOf(es []RuntimeEffect) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range es {
		if e.EventID != "" && !seen[e.EventID] {
			seen[e.EventID] = true
			out = append(out, e.EventID)
		}
	}
	sort.Strings(out)
	return out
}

func sortedForbidden(m map[EffectKind]bool) []EffectKind {
	var out []EffectKind
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func statusRank(s string) int {
	switch s {
	case StatusRefusedBypass:
		return 0
	case StatusMismatch:
		return 1
	case StatusCoverageGap, StatusAssociationGap:
		return 2
	case StatusExecuted:
		return 3
	}
	return 4
}
