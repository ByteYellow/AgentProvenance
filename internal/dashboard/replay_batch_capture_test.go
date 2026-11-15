package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/capturemanifest"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestOfflineJSONLReceiptsUseCompleteSelectedMembership(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	const run = "jsonl-capture"
	save := func(path string) telemetry.JSONLIngestResult {
		t.Helper()
		b, err := telemetry.IngestJSONLReader(db, telemetry.JSONLIngestOptions{RunID: run, Format: "native", Path: path}, strings.NewReader(`{"event_type":"file_open","path":"/work/report.py"}`+"\n"+`{"event_type":"execve","argv":["python3","report.py"]}`))
		if err != nil || b.Ingested != 2 {
			t.Fatalf("ingest: %+v %v", b, err)
		}
		return b
	}
	a, b := save("private-input-a"), save("private-input-b")
	page, err := (capturemanifest.Service{DB: db}).List(ctx, capturemanifest.Options{RunID: run})
	if err != nil || len(page.Records) != 2 {
		t.Fatalf("receipts: %+v %v", page, err)
	}
	prepared := map[string]*PreparedReplay{}
	for name, selection := range map[string]ReplaySelection{
		"whole":   {RunID: run, Scope: "whole_run"},
		"partial": {RunID: run, Scope: "whole_run", ExcludeRecords: []string{"3/" + a.EventIDs[0]}},
		"empty":   {RunID: run, Scope: "whole_run", ExcludeCategories: []string{"runtime"}},
	} {
		p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(ctx, selection)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		prepared[name] = p
	}
	late := save("late-input")
	if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, p := range prepared {
		t.Run(name, func(t *testing.T) {
			files, _ := replayZIPData(t, p)
			got, scope := readReplayCapture(t, files, run)
			switch name {
			case "whole":
				if scope != "whole_run" || !reflect.DeepEqual(got, page.Records) {
					t.Fatalf("frozen receipts changed: %+v", got)
				}
			case "partial":
				if scope != "selected_evidence" || len(got) != 1 || got[0].Identity["batch_id"] != b.BatchID {
					t.Fatalf("partial membership disclosed original receipt: %+v", got)
				}
			case "empty":
				if scope != "selected_evidence" || len(got) != 0 {
					t.Fatalf("excluded runtime retained receipts: %+v", got)
				}
			}
			for _, r := range got {
				if r.Identity["batch_id"] == late.BatchID {
					t.Fatal("late receipt entered frozen export")
				}
			}
			if root := os.Getenv("AGENTPROV_JSONL_REPLAY_OUTPUT"); root != "" {
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(filepath.Join(root, name+".zip"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				writeErr, closeErr := p.WriteZIP(ctx, f), f.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("ZIP: %v %v", writeErr, closeErr)
				}
			}
		})
	}
}
