package provenance

import (
	"database/sql"
	"maps"
	"sort"
)

// ReplayLensView contains server-computed relations, never browser inference.
// FocusEdges retain canonical order; priorities preserve the live edge budget.
type ReplayLensView struct {
	Manifest   GraphLensManifest        `json:"manifest"`
	FocusEdges []GraphLensEdge          `json:"focus_edges"`
	Priorities []int                    `json:"priorities"`
	ExtraNodes map[string]GraphLensNode `json:"extra_nodes,omitempty"`
	AddedNodes []string                 `json:"added_nodes,omitempty"`
	TotalNodes int                      `json:"total_nodes"`
	TotalEdges int                      `json:"total_edges"`
}
type ReplayLenses struct {
	Nodes      map[string]GraphLensNode  `json:"nodes"`
	Present    []string                  `json:"present"`
	FocusNodes map[string]GraphLensNode  `json:"focus_nodes"`
	Views      map[string]ReplayLensView `json:"views"`
}

// BuildReplayLenses prepares immutable, run-scoped views for a static demo.
// Browsers only select stored edges and apply the same display limits as the UI.
func BuildReplayLenses(db *sql.DB, run string) (ReplayLenses, error) {
	nodes, events, err := graphLensNodes(db, run)
	if err != nil {
		return ReplayLenses{}, err
	}
	edges, err := graphLensEdges(db, run)
	if err != nil {
		return ReplayLenses{}, err
	}
	result := ReplayLenses{Nodes: maps.Clone(nodes), FocusNodes: maps.Clone(nodes), Views: map[string]ReplayLensView{}}
	for id := range nodes {
		result.Present = append(result.Present, id)
	}
	sort.Strings(result.Present)
	for _, lens := range availableGraphLenses {
		for _, detail := range []string{"summary", "expanded", "raw"} {
			working := maps.Clone(nodes)
			all := append(append([]GraphLensEdge{}, edges...), deriveGraphLensEdges(lens, events, detail)...)
			focus := filterGraphLensEdges(lens, "", detail, working, events, all)
			priorities := make([]int, len(focus))
			extra := map[string]GraphLensNode{}
			var added []string
			for i, e := range focus {
				priorities[i] = lensEdgePriority(e, working)
				if e.EdgeType == "possible_sensitive_data_flow_summary" {
					extra[e.ToID] = egressGroupNode(e)
					if _, ok := nodes[e.ToID]; !ok {
						added = append(added, e.ToID)
					}
					result.Nodes[e.ToID] = extra[e.ToID]
				}
			}
			opts := GraphLensOptions{RunID: run, Lens: lens, Detail: detail, Limit: 500, Overlays: []string{"risk", "trust"}}
			manifest := buildGraphLensFromData(opts, working, events, edges)
			for _, n := range manifest.Nodes {
				result.Nodes[n.ID] = n
			}
			for _, e := range focus {
				for _, id := range []string{e.FromID, e.ToID} {
					if _, ok := result.Nodes[id]; !ok {
						result.Nodes[id] = inferLensNode(id)
					}
				}
			}
			result.Views[lens+"/"+detail] = ReplayLensView{Manifest: manifest, FocusEdges: focus, Priorities: priorities, ExtraNodes: extra, AddedNodes: added, TotalNodes: len(nodes), TotalEdges: len(all)}
		}
	}
	for id := range result.Nodes {
		if _, ok := result.FocusNodes[id]; !ok {
			result.FocusNodes[id] = inferLensNode(id)
		}
	}
	return result, nil
}
