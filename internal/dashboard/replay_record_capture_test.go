package dashboard

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/capturemanifest"
	"github.com/byteyellow/agentprovenance/internal/record"
)

func TestOfflineRecordCaptureUsesSelectedLifecycleEvidence(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	r, err := (record.Service{DB: db, Paths: paths, Options: record.Options{AllowShell: true, AllowAnyWorkdir: true}}).Run(record.Request{
		RunID: "recorder-capture", Workdir: t.TempDir(), Command: []string{"/bin/sh", "-c", "printf 'recorder-evidence,42\\n' > totals.csv"},
		PostRootGraceMS: 1, Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := (capturemanifest.Service{DB: db}).List(ctx, capturemanifest.Options{RunID: r.RunID})
	if err != nil || len(page.Records) != 2 {
		t.Fatalf("original recorder manifest: %+v %v", page, err)
	}
	prepared := map[string]*PreparedReplay{}
	for name, selection := range map[string]ReplaySelection{
		"whole":    {RunID: r.RunID, Scope: "whole_run"},
		"excluded": {RunID: r.RunID, Scope: "whole_run", ExcludeRecords: []string{"3/" + r.EndEventID}},
		"empty":    {RunID: r.RunID, Scope: "whole_run", ExcludeCategories: []string{"runtime"}},
	} {
		p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(ctx, selection)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		prepared[name] = p
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, p := range prepared {
		t.Run(name, func(t *testing.T) {
			files, _ := replayZIPData(t, p)
			got, scope := readReplayCapture(t, files, r.RunID)
			switch name {
			case "whole":
				if scope != "whole_run" || !reflect.DeepEqual(got, page.Records) {
					t.Fatalf("recorder source changed: %+v", got)
				}
			case "excluded":
				if scope != "selected_evidence" || len(got) != 1 || got[0].Snapshots[0].Boundary != "start" {
					t.Fatalf("excluded completion retained: %+v", got)
				}
			case "empty":
				if scope != "selected_evidence" || len(got) != 0 {
					t.Fatalf("excluded runtime retained recorder metadata: %+v", got)
				}
			}
			if root := os.Getenv("AGENTPROV_RECORD_REPLAY_OUTPUT"); root != "" {
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
