package dashboard

import (
	"encoding/json"
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

func TestDashboardVerifyUnavailableNotCached(t *testing.T) {
	db := newDashboardTestDB(t)
	s := Server{DB: db}
	if _, err := db.Exec(`ALTER TABLE sessions RENAME TO sessions_saved`); err != nil {
		t.Fatal(err)
	}
	broken := readVerifyStatus(t, s.cachedVerify("missing"))
	if broken.Status != "unavailable" || broken.Error == "" || broken.IssueCount != 0 {
		t.Fatalf("broken=%+v", broken)
	}
	if _, err := db.Exec(`ALTER TABLE sessions_saved RENAME TO sessions`); err != nil {
		t.Fatal(err)
	}
	recovered := readVerifyStatus(t, s.cachedVerify("missing"))
	if recovered.Status != "failed" || recovered.Error != "" || len(recovered.Issues) != 1 || recovered.Issues[0].Kind != "unknown_run" {
		t.Fatalf("stale error=%+v", recovered)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	closed := readVerifyStatus(t, s.cachedVerify("missing"))
	if closed.Status != "unavailable" || closed.Error == "" {
		t.Fatalf("count failure reused cache: %+v", closed)
	}
}

func TestDashboardVerifyCacheIsDatabaseScoped(t *testing.T) {
	a, b := newDashboardTestDB(t), newDashboardTestDB(t)
	if _, err := a.Exec(`INSERT INTO forensics_bundles(id,run_id,path,sha256,size_bytes,status,created_at) VALUES('bundle','same','fixture','hash',1,'ready','now')`); err != nil {
		t.Fatal(err)
	}
	if result := readVerifyStatus(t, (Server{DB: a}).cachedVerify("same")); result.Status != "ok" {
		t.Fatalf("first=%+v", result)
	}
	if result := readVerifyStatus(t, (Server{DB: b}).cachedVerify("same")); result.Status != "failed" {
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
	result := readVerifyStatus(t, (Server{DB: db}).cachedVerify("partial"))
	if result.Status != "unavailable" || result.Error == "" || result.IssueCount != 1 || result.ErrorCount != 1 || len(result.Issues) != 1 || result.Issues[0].Kind != "missing_snapshot" {
		t.Fatalf("completed checks lost: %+v", result)
	}
}
