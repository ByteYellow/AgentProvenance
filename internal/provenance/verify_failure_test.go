package provenance

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func verificationDB(t *testing.T) *sql.DB {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestVerificationLookupsPropagateFailures(t *testing.T) {
	for name, lookup := range map[string]func(*sql.DB) (bool, error){
		"reference": func(db *sql.DB) (bool, error) { return exists(db, `SELECT 1 FROM events WHERE id='missing'`) },
		"run":       func(db *sql.DB) (bool, error) { return runExists(db, "missing") },
		"edge":      func(db *sql.DB) (bool, error) { return edgeExists(db, "missing", "a", "b", "x") },
		"taint":     func(db *sql.DB) (bool, error) { return attemptIsTainted(db, "missing") },
		"binding": func(db *sql.DB) (bool, error) {
			return externalContextBindingExists(db, "missing", "session", "", "", "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := verificationDB(t)
			if found, err := lookup(db); err != nil || found {
				t.Fatalf("no row=%v err=%v", found, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if found, err := lookup(db); err == nil || found || !strings.Contains(err.Error(), "closed") {
				t.Fatalf("query error swallowed: found=%v err=%v", found, err)
			}
		})
	}
}

func TestVerifyUnavailableAndJSON(t *testing.T) {
	db := verificationDB(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(db, "run")
	if err == nil || result.Status != "unavailable" || !strings.Contains(result.Error, "closed") || result.IssueCount != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	var out bytes.Buffer
	if err := VerifyRunJSON(db, "run", &out); err == nil {
		t.Fatal("CLI reported success")
	}
	var wire VerifyResult
	if err := json.Unmarshal(out.Bytes(), &wire); err != nil || wire.Status != "unavailable" || wire.Error == "" {
		t.Fatalf("JSON=%s err=%v", out.String(), err)
	}
	out.Reset()
	if err := VerifyRun(db, "run", &out); err == nil || !strings.Contains(out.String(), "status=unavailable") {
		t.Fatalf("text=%s err=%v", out.String(), err)
	}
}

func TestVerifyLookupFailureIsNotMissingSnapshot(t *testing.T) {
	db := verificationDB(t)
	for _, query := range []string{
		`INSERT INTO rollouts (id,run_id,base_snapshot_id,status,fanout,created_at,updated_at) VALUES ('r','run','missing','running',1,'now','now')`,
		`ALTER TABLE snapshots RENAME TO snapshots_saved`,
		`CREATE VIEW snapshots AS SELECT abs(-9223372036854775808) AS id`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	result, err := Verify(db, "run")
	if err == nil || result.Status != "unavailable" || !strings.Contains(result.Error, "overflow") || result.IssueCount != 0 {
		t.Fatalf("lookup failure became violation: %+v err=%v", result, err)
	}
}

func TestContentLookupErrorsRemainOperational(t *testing.T) {
	db := verificationDB(t)
	var payload any
	err := ReadObjectPayload(db, "r", "sha256:missing", &payload)
	if err == nil || contentQueryFailed(err) {
		t.Fatalf("missing object misclassified: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	err = ReadObjectPayload(db, "r", "sha256:missing", &payload)
	if err == nil || !contentQueryFailed(err) {
		t.Fatalf("DB failure misclassified: %v", err)
	}
}

func TestGraphConfidenceUnknownVersusZero(t *testing.T) {
	for _, tc := range []struct {
		name       string
		confidence *float64
		field      string
	}{
		{"unknown", nil, ""}, {"zero", graphConfidence(0), `"confidence":0`}, {"known", graphConfidence(0.8), `"confidence":0.8`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := GraphLensEdge{FromID: "a", ToID: "b", Derived: true, Confidence: tc.confidence}
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			if tc.field == "" && strings.Contains(string(raw), `"confidence"`) || tc.field != "" && !strings.Contains(string(raw), tc.field) {
				t.Fatalf("wire=%s", raw)
			}
			var copy GraphLensEdge
			if err := json.Unmarshal(raw, &copy); err != nil {
				t.Fatal(err)
			}
			if (copy.Confidence == nil) != (e.Confidence == nil) {
				t.Fatal("lost confidence presence")
			}
			var out bytes.Buffer
			if err := PrintGraphLensManifest(&out, GraphLensManifest{DerivedEdges: []GraphLensEdge{copy}}); err != nil {
				t.Fatal(err)
			}
			want := "confidence=unknown"
			if tc.name == "zero" {
				want = "confidence=0.00"
			} else if tc.name == "known" {
				want = "confidence=0.80"
			}
			if !strings.Contains(out.String(), want) {
				t.Fatalf("output=%s", out.String())
			}
		})
	}
}
