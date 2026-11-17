package dashboard

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
)

func TestReplayGraphStoragePreservesViewsAndNodeVariants(t *testing.T) {
	a := provenance.GraphLensNode{ID: "a", Kind: "browser", Label: "Summary", Data: map[string]any{"generation": "one"}}
	variant := a
	variant.Label = "Expanded"
	b := provenance.GraphLensNode{ID: "b", Kind: "request", Label: "Request"}
	edge := provenance.GraphLensEdge{FromID: "a", ToID: "b", EdgeType: "request", EvidenceRefs: []string{"object/observed"}}
	derived := edge
	derived.Derived, derived.DerivationRule = true, "saved-rule/v1"
	first := provenance.ReplayLensView{Manifest: provenance.GraphLensManifest{
		RunID: "run", Nodes: []provenance.GraphLensNode{a, b}, Edges: []provenance.GraphLensEdge{edge},
		DerivedEdges: []provenance.GraphLensEdge{derived}}, FocusEdges: []provenance.GraphLensEdge{derived, edge},
		Priorities: []int{7, 2}, TotalNodes: 2, TotalEdges: 2}
	second := first
	second.Manifest.Nodes = []provenance.GraphLensNode{variant, b}
	empty := provenance.ReplayLensView{Manifest: provenance.GraphLensManifest{Nodes: []provenance.GraphLensNode{}, Edges: nil}}
	lenses := provenance.ReplayLenses{Nodes: map[string]provenance.GraphLensNode{"a": a, "b": b},
		FocusNodes: map[string]provenance.GraphLensNode{"a": a, "b": b}, Present: []string{"a", "b"},
		Views: map[string]provenance.ReplayLensView{"default/summary": first, "default/expanded": second, "default/raw": empty}}
	w := &staticdata.Writer{Root: t.TempDir()}
	ref, err := writeReplayLenses(w, lenses)
	if err != nil {
		t.Fatal(err)
	}
	read := func(ref staticdata.Ref, v any) {
		t.Helper()
		f, err := os.Open(filepath.Join(w.Root, ref.Path))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		z, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		defer z.Close()
		if err := json.NewDecoder(z).Decode(v); err != nil {
			t.Fatal(err)
		}
	}
	var index struct {
		Graph staticdata.Ref
		Views map[string]staticdata.Ref
	}
	read(ref, &index)
	var pool replayGraphPool
	read(index.Graph, &pool)
	if len(pool.Nodes) != 3 || len(pool.Edges) != 2 {
		t.Fatalf("complete-object deduplication lost variants or duplicated edges: nodes=%d edges=%d", len(pool.Nodes), len(pool.Edges))
	}
	for key, want := range lenses.Views {
		var view replaySharedLensView
		read(index.Views[key], &view)
		restore := func(ids []int, values []json.RawMessage, target any) {
			t.Helper()
			var raw []json.RawMessage
			if ids != nil {
				raw = make([]json.RawMessage, 0, len(ids))
			}
			for _, i := range ids {
				raw = append(raw, values[i])
			}
			encoded, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(encoded, target); err != nil {
				t.Fatal(err)
			}
		}
		got := provenance.ReplayLensView{Manifest: view.Manifest, Priorities: view.Priorities,
			ExtraNodes: view.ExtraNodes, AddedNodes: view.AddedNodes, TotalNodes: view.TotalNodes, TotalEdges: view.TotalEdges}
		restore(view.NodeIndexes, pool.Nodes, &got.Manifest.Nodes)
		restore(view.EdgeIndexes, pool.Edges, &got.Manifest.Edges)
		restore(view.DerivedIndexes, pool.Edges, &got.Manifest.DerivedEdges)
		restore(view.FocusIndexes, pool.Edges, &got.FocusEdges)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("view %s changed after round trip\n got: %#v\nwant: %#v", key, got, want)
		}
	}
	again, err := writeReplayLenses(w, lenses)
	if err != nil || again != ref {
		t.Fatalf("graph encoding is not deterministic: %v %v", again, err)
	}
}
