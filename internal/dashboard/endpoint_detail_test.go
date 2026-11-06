package dashboard

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func addEndpointAssociationFixture(t *testing.T, db *sql.DB, paths store.Paths, run, mode string) string {
	t.Helper()
	const marker = "PUBLIC-ENDPOINT-FIXTURE-CANARY"
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(marker)))
	for _, stmt := range []string{
		`INSERT INTO leases(id,run_id,task_path,task_yaml,status,created_at,updated_at) VALUES (?||'-lease',?,'fixture','{}','released','2026-11-06T00:00:00Z','2026-11-06T00:00:04Z')`,
		`INSERT INTO sessions(id,run_id,lease_id,workspace_host_path,runtime,status,created_at,updated_at) VALUES (?||'-session',?,?||'-lease','/fixture','local','stopped','2026-11-06T00:00:00Z','2026-11-06T00:00:04Z')`,
	} {
		args := []any{run, run}
		if strings.Contains(stmt, "INSERT INTO sessions") {
			args = append(args, run)
		}
		if _, err := db.Exec(stmt, args...); err != nil {
			t.Fatal(err)
		}
	}
	addProcess := func(id string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO processes(id,session_id,command,status,started_at,ended_at,exit_code)
			VALUES (?,?||'-session','synthetic endpoint fixture','exited','2026-11-06T00:00:00Z','2026-11-06T00:00:04Z',0)`, id, run); err != nil {
			t.Fatal(err)
		}
	}
	if mode != "missing" {
		for _, name := range []string{"a", "b"} {
			if mode == "bound" && name == "b" {
				continue
			}
			payload, _ := json.Marshal(map[string]any{"path": "/fixture/secret.txt", "content_sha256": hash, "fixture": true})
			addProcess(run + "-reader-" + name)
			if _, err := db.Exec(`INSERT INTO events(id,run_id,process_id,source,event_type,payload,created_at)
				VALUES (?,?,?,'fixture','secret_path',?,'2026-11-06T00:00:01Z')`, run+"-read-"+name, run, run+"-reader-"+name, string(payload)); err != nil {
				t.Fatal(err)
			}
		}
	}
	meta := map[string]any{"seq": 1, "kind": "EXFIL-REQ", "path": "/storage", "host": "fixture.invalid", "canary_hits": []string{marker}, "observed_at": "2026-11-06T00:00:03.000000Z"}
	if mode == "bound" {
		addProcess(run + "-sender")
		if _, err := db.Exec(`INSERT INTO events(id,run_id,process_id,source,event_type,payload,created_at)
			VALUES (?,?,?,'fixture','network_connect','{"dst_host":"fixture.invalid","fixture":true}','2026-11-06T00:00:02Z')`, run+"-send", run, run+"-sender"); err != nil {
			t.Fatal(err)
		}
		meta["runtime_event_id"] = run + "-send"
		meta["source_read_events"] = []string{run + "-read-a"}
	}
	dump := t.TempDir()
	metadata, _ := json.Marshal(meta)
	body, _ := json.Marshal(map[string]any{"fixture": true, "files": []any{map[string]any{"path": "/fixture/secret.txt", "content": marker}}})
	for name, data := range map[string][]byte{"01.meta.json": metadata, "01.body.bin": body} {
		if err := os.WriteFile(filepath.Join(dump, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := provenance.IngestEndpointDump(provenance.ObjectStore{DB: db, Paths: paths}, db, run, dump); err != nil {
		t.Fatal(err)
	}
	var event string
	if err := db.QueryRow(`SELECT id FROM events WHERE run_id=? AND source='endpoint_capture'`, run).Scan(&event); err != nil {
		t.Fatal(err)
	}
	verification, err := provenance.Verify(db, run)
	if err != nil || verification.ErrorCount != 0 {
		t.Fatalf("endpoint fixture integrity: %+v %v", verification, err)
	}
	return event
}

func TestEndpointReplaySelectionKeepsCandidateSetOrExcludesDependentCapture(t *testing.T) {
	paths, db, _ := artifactStore(t)
	const run = "ui-endpoint-candidates"
	event := addEndpointAssociationFixture(t, db, paths, run, "candidates")
	for _, exclude := range []bool{false, true} {
		t.Run(fmt.Sprint(exclude), func(t *testing.T) {
			selection := ReplaySelection{RunID: run, Scope: "whole_run"}
			if exclude {
				selection.ExcludeRecords = []string{"3/" + run + "-read-b"}
			}
			p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(context.Background(), selection)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			_, all := replayZIPData(t, p)
			if !exclude {
				for _, want := range []string{event, `"status":"ambiguous"`, run + "-read-a", run + "-read-b", "agentprov.endpoint_attribution/v2", `"status":"matched"`} {
					if !strings.Contains(all, want) {
						t.Fatalf("whole replay lost %s", want)
					}
				}
			} else {
				if strings.Contains(all, `"source":"endpoint_capture"`) || strings.Contains(all, run+"-reader-b") || strings.Contains(all, `"status":"candidate"`) || strings.Contains(all, "PUBLIC-ENDPOINT-FIXTURE-CANARY") {
					t.Fatal("partial replay leaked source metadata or narrowed candidates")
				}
				if !strings.Contains(all, "endpoint_support_not_included") || !strings.Contains(all, run+"-read-a") {
					t.Fatal("missing export-boundary reason or independently selected read")
				}
			}
		})
	}
}
