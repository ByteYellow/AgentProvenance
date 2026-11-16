package provenance

import (
	"fmt"
	"maps"
	"testing"
)

func TestOverviewArtifactCountExcludesMessages(t *testing.T) {
	nodes := map[string]GraphLensNode{}
	for _, kind := range []string{"artifact", "llm_prompt", "llm_completion", "message", "relay"} {
		nodes[kind] = GraphLensNode{ID: kind, Kind: kind}
	}
	counts := overviewCounts(nodes, nil, nil)
	if counts.Artifacts != 1 || counts.LLMIntents != 2 || counts.AgentMessages != 1 {
		t.Fatalf("file artifacts, model content and peer messages must be counted separately: %+v", counts)
	}
}

func TestStandaloneEvidenceRespectsGraphBudget(t *testing.T) {
	nodes := map[string]GraphLensNode{}
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("call-%02d", i)
		nodes[id] = GraphLensNode{ID: id, Kind: "tool_call"}
	}
	options := GraphLensOptions{RunID: "run", Lens: "intent", Limit: 3}
	first := buildGraphLensFromData(options, maps.Clone(nodes), nil, nil)
	second := buildGraphLensFromData(options, maps.Clone(nodes), nil, nil)
	if len(first.Nodes) != 3 || !first.Query.Truncated || first.Query.OmittedNodes != 9 {
		t.Fatalf("standalone records bypass the budget: %+v", first.Query)
	}
	for i := range first.Nodes {
		if first.Nodes[i].ID != second.Nodes[i].ID {
			t.Fatal("bounded standalone display is not deterministic")
		}
	}
	options.Focus = "call-11"
	focused := buildGraphLensFromData(options, maps.Clone(nodes), nil, nil)
	if len(focused.Nodes) != 1 || focused.Nodes[0].ID != options.Focus {
		t.Fatal("focused view includes unrelated standalone records")
	}
}

func TestCountedEvidenceHasDrilldownWithoutRelations(t *testing.T) {
	for _, tc := range []struct{ kind, lens, detail string }{
		{"tool_call", "intent", "summary"},
		{"tool_call", "intent", "raw"},
		{"artifact", "file-artifact", "raw"},
	} {
		t.Run(tc.kind+"/"+tc.detail, func(t *testing.T) {
			nodes := map[string]GraphLensNode{
				"recorded":  {ID: "recorded", Kind: tc.kind, Label: "Saved evidence"},
				"unrelated": {ID: "unrelated", Kind: "runtime_event"},
			}
			m := buildGraphLensFromData(GraphLensOptions{RunID: "run", Lens: tc.lens, Detail: tc.detail, Limit: 10}, nodes, nil, nil)
			if !lensHasNode(m, "recorded", tc.kind) || lensHasNode(m, "unrelated", "runtime_event") {
				t.Fatalf("standalone evidence missing or unrelated evidence included: %+v", m.Nodes)
			}
			if len(m.Edges)+len(m.DerivedEdges) != 0 {
				t.Fatal("showing saved evidence must not manufacture a relation")
			}
		})
	}
}

func TestFileSummaryIncludesNonFileArtifacts(t *testing.T) {
	nodes := map[string]GraphLensNode{"artifact": {ID: "artifact", Kind: "artifact", Subtype: "egress_payload"}}
	m := buildGraphLensFromData(GraphLensOptions{RunID: "run", Lens: "file-artifact", Detail: "summary", Limit: 10}, maps.Clone(nodes), nil, nil)
	found := false
	for _, n := range m.Nodes {
		if n.Kind != "file_group" || n.Data["category"] != "artifacts" {
			continue
		}
		found = true
		if n.Data["count"] != 1 {
			t.Fatalf("artifact count: %+v", n.Data)
		}
		next := buildGraphLensFromData(GraphLensOptions{RunID: "run", Lens: n.Data["drilldown_lens"].(string), Detail: n.Data["drilldown_detail"].(string), Limit: 10}, maps.Clone(nodes), nil, nil)
		if !lensHasNode(next, "artifact", "artifact") {
			t.Fatal("artifact summary links to an empty graph")
		}
	}
	if !found {
		t.Fatal("a saved non-file artifact disappears from the summary")
	}
}
