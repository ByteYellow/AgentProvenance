package provenance

import (
	"encoding/json"
	"testing"
)

func TestReplayLensesPreserveCanonicalViews(t *testing.T) {
	db := newLensTestDB(t)
	insertLensFixture(t, db, "2026-09-28T00:00:00Z")
	replay, err := BuildReplayLenses(db, "run-lens")
	if err != nil {
		t.Fatal(err)
	}
	for key, view := range replay.Views {
		live, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: view.Manifest.Lens, Detail: view.Manifest.Query.Detail, Limit: 500, Overlays: []string{"risk", "trust"}})
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(view.Manifest)
		b, _ := json.Marshal(live)
		if string(a) != string(b) {
			t.Errorf("%s changed canonical graph", key)
		}
		if len(view.FocusEdges) != len(view.Priorities) {
			t.Fatalf("%s missing priorities", key)
		}
	}
	// An overview group is synthesized only for the summary; focusing the same
	// identifier must keep the live reader's unknown-node semantics.
	if replay.Nodes["overview/files"].Kind != "overview_group" || replay.FocusNodes["overview/files"].Kind != "unknown" {
		t.Fatal("summary nodes leaked into focused evidence")
	}
}
