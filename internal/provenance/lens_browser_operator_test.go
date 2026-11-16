//go:build linux || darwin

package provenance_test

import (
	"context"
	"os"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/browsercustody"
	"github.com/byteyellow/agentprovenance/internal/browserlink"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// The x86 handoff uses the same production authorization and source resolver as
// graph lens/dashboard export. Import the original Bundle and B01 capture first.
func TestBrowserLayerOperatorIngress(t *testing.T) {
	config, root := os.Getenv("AGENTPROV_BROWSER_CUSTODY_CONFIG"), os.Getenv("AGENTPROV_BROWSER_DATA_DIR")
	if config == "" && root == "" {
		t.Skip("operator custody/store inputs absent; sensor-on acceptance is opt-in")
	}
	if config == "" || root == "" {
		t.Fatal("both operator custody config and data directory are required")
	}
	ctx := context.Background()
	paths := store.ResolvePaths(root)
	verified, err := browsercustody.Load(ctx, config, paths)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	custody, err := verified.Resolve(ctx, db, verified.RunID())
	if err != nil {
		t.Fatal(err)
	}
	graph, err := provenance.BuildGraphLensWithBrowserCustody(db, provenance.GraphLensOptions{RunID: verified.RunID(), Detail: "raw", Limit: 1000000}, custody)
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, edge := range graph.DerivedEdges {
		if edge.DerivationRule == browserlink.RuntimeRule && edge.EdgeType == "browser_scope_process" {
			matched++
		}
	}
	if matched == 0 {
		t.Fatal("no exact native host/process-birth match; inspect custody support and sensor coverage")
	}
	if _, err := provenance.BuildSessionReplayLensesWithBrowserCustody(db, verified.RunID(), nil, custody); err != nil {
		t.Fatal(err)
	}
	t.Logf("authorized_mappings=%d matched_native_process_observations=%d", len(custody), matched)
}
