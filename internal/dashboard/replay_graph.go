package dashboard

import (
	"encoding/json"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

// Intern complete objects, rather than IDs: the same node can carry a different
// label or attributes in another lens. Index order preserves server-computed
// edge order and its separate focus priorities. This is a storage encoding only.
type replayGraphPool struct {
	SchemaVersion string            `json:"schema_version"`
	Nodes         []json.RawMessage `json:"nodes"`
	Edges         []json.RawMessage `json:"edges"`
	nodeIndex     map[string]int
	edgeIndex     map[string]int
}

type replaySharedLensView struct {
	SchemaVersion  string                              `json:"schema_version"`
	Manifest       provenance.GraphLensManifest        `json:"manifest"`
	NodeIndexes    []int                               `json:"node_indexes"`
	EdgeIndexes    []int                               `json:"edge_indexes"`
	DerivedIndexes []int                               `json:"derived_indexes,omitempty"`
	FocusIndexes   []int                               `json:"focus_indexes"`
	Priorities     []int                               `json:"priorities"`
	ExtraNodes     map[string]provenance.GraphLensNode `json:"extra_nodes,omitempty"`
	AddedNodes     []string                            `json:"added_nodes,omitempty"`
	TotalNodes     int                                 `json:"total_nodes"`
	TotalEdges     int                                 `json:"total_edges"`
}

func newReplayGraphPool() *replayGraphPool {
	return &replayGraphPool{SchemaVersion: "agentprovenance.replay_graph/v1",
		Nodes: []json.RawMessage{}, Edges: []json.RawMessage{},
		nodeIndex: map[string]int{}, edgeIndex: map[string]int{}}
}

func internReplayObjects[T any](values []T, pool *[]json.RawMessage, indexes map[string]int) ([]int, error) {
	if values == nil {
		return nil, nil
	}
	result := make([]int, 0, len(values))
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		key := string(raw)
		index, ok := indexes[key]
		if !ok {
			index = len(*pool)
			indexes[key] = index
			*pool = append(*pool, raw)
		}
		result = append(result, index)
	}
	return result, nil
}

func (p *replayGraphPool) view(value provenance.ReplayLensView) (replaySharedLensView, error) {
	result := replaySharedLensView{SchemaVersion: "agentprovenance.replay_lens_view/v2",
		Manifest: value.Manifest, Priorities: value.Priorities, ExtraNodes: value.ExtraNodes,
		AddedNodes: value.AddedNodes, TotalNodes: value.TotalNodes, TotalEdges: value.TotalEdges}
	var err error
	if result.NodeIndexes, err = internReplayObjects(value.Manifest.Nodes, &p.Nodes, p.nodeIndex); err != nil {
		return result, err
	}
	if result.EdgeIndexes, err = internReplayObjects(value.Manifest.Edges, &p.Edges, p.edgeIndex); err != nil {
		return result, err
	}
	if result.DerivedIndexes, err = internReplayObjects(value.Manifest.DerivedEdges, &p.Edges, p.edgeIndex); err != nil {
		return result, err
	}
	if result.FocusIndexes, err = internReplayObjects(value.FocusEdges, &p.Edges, p.edgeIndex); err != nil {
		return result, err
	}
	result.Manifest.Nodes, result.Manifest.Edges, result.Manifest.DerivedEdges = nil, nil, nil
	return result, nil
}
