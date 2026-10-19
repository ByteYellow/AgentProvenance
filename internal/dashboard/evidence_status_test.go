package dashboard

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func readVerifyStatus(t *testing.T, value any) provenance.VerifyResult {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result provenance.VerifyResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDashboardVerifyUnavailableRecovers(t *testing.T) {
	db := newDashboardTestDB(t)
	s := Server{DB: db}
	if _, err := db.Exec(`ALTER TABLE sessions RENAME TO sessions_saved`); err != nil {
		t.Fatal(err)
	}
	broken := readVerifyStatus(t, s.verifyOverview("missing"))
	if broken.Status != "unavailable" || broken.Error == "" || broken.IssueCount != 0 {
		t.Fatalf("broken=%+v", broken)
	}
	if _, err := db.Exec(`ALTER TABLE sessions_saved RENAME TO sessions`); err != nil {
		t.Fatal(err)
	}
	recovered := readVerifyStatus(t, s.verifyOverview("missing"))
	if recovered.Status != "failed" || recovered.Error != "" || len(recovered.Issues) != 1 || recovered.Issues[0].Kind != "unknown_run" {
		t.Fatalf("stale error=%+v", recovered)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	closed := readVerifyStatus(t, s.verifyOverview("missing"))
	if closed.Status != "unavailable" || closed.Error == "" {
		t.Fatalf("count failure reused cache: %+v", closed)
	}
}

func TestDashboardVerifyIsDatabaseScoped(t *testing.T) {
	a, b := newDashboardTestDB(t), newDashboardTestDB(t)
	if _, err := a.Exec(`INSERT INTO tool_calls(id,run_id,status,created_at) VALUES('tool','same','completed','now')`); err != nil {
		t.Fatal(err)
	}
	if result := readVerifyStatus(t, (Server{DB: a}).verifyOverview("same")); result.Status != "ok" {
		t.Fatalf("first=%+v", result)
	}
	if result := readVerifyStatus(t, (Server{DB: b}).verifyOverview("same")); result.Status != "failed" {
		t.Fatalf("reused other DB's result: %+v", result)
	}
}

func TestDashboardVerifyPreservesCompletedIssuesOnFailure(t *testing.T) {
	db := newDashboardTestDB(t)
	for _, query := range []string{
		`INSERT INTO rollouts (id,run_id,base_snapshot_id,status,fanout,created_at,updated_at) VALUES ('r','partial','missing','running',1,'now','now')`,
		`ALTER TABLE promotions RENAME TO promotions_saved`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	result := readVerifyStatus(t, (Server{DB: db}).verifyOverview("partial"))
	if result.Status != "unavailable" || result.Error == "" || result.IssueCount != 1 || result.ErrorCount != 1 || len(result.Issues) != 1 || result.Issues[0].Kind != "missing_snapshot" {
		t.Fatalf("completed checks lost: %+v", result)
	}
}

func TestDashboardVerifyAfterEvidenceAndSchemaChange(t *testing.T) {
	db := newDashboardTestDB(t)
	s := Server{DB: db}
	if _, err := db.Exec(`INSERT INTO tool_calls(id,run_id,status,created_at) VALUES('tool','cache-review','completed','now')`); err != nil {
		t.Fatal(err)
	}
	first := readVerifyStatus(t, s.verifyOverview("cache-review"))
	if first.Status != "ok" {
		t.Fatalf("setup=%+v", first)
	}
	if _, err := db.Exec(`UPDATE tool_calls SET session_id='missing' WHERE id='tool'`); err != nil {
		t.Fatal(err)
	}
	direct, err := provenance.Verify(db, "cache-review")
	if err != nil {
		t.Fatal(err)
	}
	cached := readVerifyStatus(t, s.verifyOverview("cache-review"))
	t.Logf("after data change: direct=%s cached=%s issues=%+v", direct.Status, cached.Status, direct.Issues)
	if cached.Status != direct.Status {
		t.Error("cache hides invalid evidence")
	}
	if _, err := db.Exec(`ALTER TABLE graph_edges RENAME TO graph_edges_saved`); err != nil {
		t.Fatal(err)
	}
	direct, err = provenance.Verify(db, "cache-review")
	cached = readVerifyStatus(t, s.verifyOverview("cache-review"))
	t.Logf("after schema fault: direct=%s cached=%s error=%v", direct.Status, cached.Status, err)
	if cached.Status != direct.Status {
		t.Error("cache hides verification failure")
	}
}

func TestDashboardVerifyDetectsObjectChangesAfterBundleExport(t *testing.T) {
	_, db, objects := artifactStore(t)
	obj := putArtifact(t, objects, "imported", "fixture", map[string]any{"content": "original"})
	if _, err := db.Exec(`INSERT INTO forensics_bundles(id,run_id,path,status,created_at) VALUES('export','imported','fixture.tar','ready','now')`); err != nil {
		t.Fatal(err)
	}
	server := Server{DB: db}
	if result := readVerifyStatus(t, server.verifyOverview("imported")); result.Status != "ok" {
		t.Fatalf("before=%+v", result)
	}
	if err := os.WriteFile(obj.Path, []byte(`{"content":"changed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	result := readVerifyStatus(t, server.verifyOverview("imported"))
	if result.Status != "failed" || result.ErrorCount == 0 {
		t.Fatalf("object corruption hidden by old bundle metadata: %+v", result)
	}
}
