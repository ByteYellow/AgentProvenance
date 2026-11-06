package intent

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestDiffCoverageIsPerTool(t *testing.T) {
	contracts := []IntentContract{
		{ID: "contract/t1", Kind: ContractToolCall, ScopeAgent: "agent", ToolCallID: "t1", Operation: "exec", Profile: profileFor(profiles(), "exec")},
		{ID: "contract/t3", Kind: ContractToolCall, ScopeAgent: "agent", ToolCallID: "t3", Operation: "exec", Profile: profileFor(profiles(), "exec")},
	}
	effects := []RuntimeEffect{
		{Kind: EffectProcessExec, AgentID: "agent", ToolCallID: "t1", EventID: "e1", Confidence: 1},
		{Kind: EffectSecretRead, AgentID: "agent", ToolCallID: "t2", EventID: "e2", Confidence: 1},
		{Kind: EffectProcessExec, AgentID: "agent", ToolCallID: "t3", EventID: "e3", Confidence: 1},
		{Kind: EffectMetadataEgress, AgentID: "agent", ToolCallID: "t4", EventID: "e4", Confidence: 1},
	}
	for _, reverse := range []bool{false, true} {
		if reverse {
			slices.Reverse(contracts)
			slices.Reverse(effects)
		}
		diffs := Diff(contracts, effects)
		for tool, event := range map[string]string{"t2": "e2", "t4": "e4"} {
			d, ok := findDiff(diffs, func(d IntentRuntimeDiff) bool {
				return d.Status == StatusCoverageGap && d.AgentID == "agent" && d.ToolCallID == tool
			})
			if !ok || !reflect.DeepEqual(d.EventIDs, []string{event}) {
				t.Errorf("reverse=%v: missing tool %s gap with original event: %+v", reverse, tool, diffs)
			}
		}
		for _, tool := range []string{"t1", "t3"} {
			if _, ok := findDiff(diffs, func(d IntentRuntimeDiff) bool {
				return d.ToolCallID == tool && d.Status == StatusExecuted
			}); !ok {
				t.Errorf("reverse=%v: lost covered execution %s: %+v", reverse, tool, diffs)
			}
		}
	}
}

func TestDiffToolContractCannotFallBackToAgent(t *testing.T) {
	for _, tool := range []string{"", "absent"} {
		contracts := []IntentContract{{ID: "contract/unknown", Kind: ContractToolCall, ScopeAgent: "agent", ToolCallID: tool, Profile: profileFor(profiles(), "exec")}}
		effects := []RuntimeEffect{{Kind: EffectSecretRead, AgentID: "agent", ToolCallID: "other", EventID: "original", Confidence: 1}}
		diffs := Diff(contracts, effects)
		if len(diffs) != 1 || diffs[0].Status != StatusCoverageGap || !reflect.DeepEqual(diffs[0].EventIDs, []string{"original"}) {
			t.Errorf("tool=%q: unmatched contract claimed event: %+v", tool, diffs)
		}
	}
}

func TestDiffConflictingAgentDoesNotBorrowToolContract(t *testing.T) {
	contracts := []IntentContract{{ID: "contract/t1", Kind: ContractToolCall, ScopeAgent: "alice", ToolCallID: "t1", Profile: profileFor(profiles(), "exec")}}
	effects := []RuntimeEffect{{Kind: EffectSecretRead, AgentID: "bob", ToolCallID: "t1", EventID: "bob-event", Confidence: 1}}
	diffs := Diff(contracts, effects)
	if len(diffs) != 1 || diffs[0].Status != StatusCoverageGap || diffs[0].AgentID != "bob" {
		t.Fatalf("conflicting agent was silently covered: %+v", diffs)
	}
}

func TestDiffLongScopeIDsRemainDistinct(t *testing.T) {
	prefix := strings.Repeat("shared-prefix-", 4)
	effects := []RuntimeEffect{
		{Kind: EffectSecretRead, AgentID: prefix + "a", ToolCallID: "t1", EventID: "e1"},
		{Kind: EffectSecretRead, AgentID: prefix + "b", ToolCallID: "t2", EventID: "e2"},
	}
	diffs := Diff(nil, effects)
	if len(diffs) != 2 || diffs[0].ID == diffs[1].ID {
		t.Fatalf("different gaps collide: %+v", diffs)
	}
}
