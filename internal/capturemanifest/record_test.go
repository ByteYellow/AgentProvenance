package capturemanifest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/buildinfo"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
)

func TestOrdinaryRecordCapturesOwnCapabilities(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		t.Run(map[bool]string{true: "snapshot", false: "no_snapshot"}[snapshot], func(t *testing.T) {
			db, paths := testStore(t)
			r, err := (record.Service{DB: db, Paths: paths, Options: record.Options{AllowShell: true, AllowAnyWorkdir: true}}).Run(record.Request{
				RunID: "record-capabilities", Workdir: t.TempDir(), Command: []string{"/bin/sh", "-c", "printf 'total,42\\n' > totals.csv; exit 7"},
				DisableSnapshot: !snapshot, SampleIntervalMS: 7, PostRootGraceMS: 10, Stdout: io.Discard, Stderr: io.Discard,
			})
			if err != nil || r.ExitCode != 7 {
				t.Fatalf("record task: %+v %v", r, err)
			}
			got := all(t, db, r.RunID, 1)
			if len(got) != 2 {
				t.Fatalf("want start/end recorder capability witnesses, got %+v", got)
			}
			for _, c := range got {
				if c.Source != "record" || c.IdentityDomain != "record_scope" || c.Placement != "local_process" || c.ProducerVersion != buildinfo.Version || c.ProducerCommit != buildinfo.Commit || c.Identity["os"] != runtime.GOOS || c.Identity["architecture"] != runtime.GOARCH || c.Identity["attempt_id"] != r.AttemptID {
					t.Fatalf("capture identity changed: %+v", c)
				}
				if c.Identity["sample_interval_ms"] != "7" || c.Identity["post_root_grace_ms"] != "10" || c.IntervalBasis != "recorder_observation" {
					t.Fatalf("missing sampling configuration: %+v", c)
				}
				if len(c.Retention) != 1 || c.Retention[0].Enabled == nil || *c.Retention[0].Enabled != snapshot {
					t.Fatalf("snapshot retention changed: %+v", c)
				}
				if c.Snapshots[0].Boundary == "end" && c.Status != "stopped" {
					t.Fatalf("command failure became capture failure: %+v", c)
				}
				for _, counter := range c.Loss {
					if counter.Name == "missed_processes" && counter.Value != nil {
						t.Fatalf("polling inferred no missing processes: %+v", counter)
					}
				}
			}
		})
	}
}

func TestRecordCapabilitiesPreserveStartFailureAndLegacy(t *testing.T) {
	db, paths := testStore(t)
	r, err := (record.Service{DB: db, Paths: paths, Options: record.Options{AllowAnyWorkdir: true}}).Run(record.Request{
		RunID: "start-failure", Workdir: t.TempDir(), Command: []string{"/missing/recorder-fixture"}, DisableSnapshot: true,
	})
	if err != nil || r.ExitCode != 125 {
		t.Fatalf("record start failure: %+v %v", r, err)
	}
	got := all(t, db, r.RunID, 50)
	if len(got) != 1 || got[0].Snapshots[0].Boundary != "error" || got[0].StartedAt != "" || *got[0].Snapshots[0].Features[0].Observed {
		t.Fatalf("failed spawn became captured execution: %+v", got)
	}
	if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at) VALUES ('legacy','legacy','record','exec_start','{"command":"true"}','2026-11-15T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if got := all(t, db, "legacy", 50); len(got) != 0 {
		t.Fatalf("old record gained reader-host capabilities: %+v", got)
	}
}

func TestRecordCapabilitiesKeepAttemptsAndSignedSource(t *testing.T) {
	db, paths := testStore(t)
	attempts := map[string]bool{}
	for i := 0; i < 2; i++ {
		r, err := (record.Service{DB: db, Paths: paths, Options: record.Options{AllowAnyWorkdir: true}}).Run(record.Request{
			RunID: "signed-record", Workdir: t.TempDir(), Command: []string{"/bin/echo", "recorded-source"}, DisableSnapshot: true, PostRootGraceMS: 1,
			Stdout: io.Discard, Stderr: io.Discard,
		})
		if err != nil {
			t.Fatal(err)
		}
		attempts[r.AttemptID] = true
	}
	before := all(t, db, "signed-record", 1)
	if len(before) != 4 || len(attempts) != 2 {
		t.Fatalf("same-Run attempts merged: %+v", before)
	}
	for _, r := range before {
		if !attempts[r.Identity["attempt_id"]] {
			t.Fatalf("foreign attempt: %+v", r)
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: private}).ExportBundle("signed-record")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, public); err != nil {
		t.Fatal(err)
	}
	dst, dest := testStore(t)
	if _, err := (forensics.Service{DB: dst, Paths: dest}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	if got := all(t, dst, "signed-record", 3); !reflect.DeepEqual(got, before) {
		t.Fatalf("import changed recorder facts: %+v", got)
	}
	if checked, err := provenance.Verify(dst, "signed-record"); err != nil || checked.ErrorCount != 0 || checked.WarningCount != 0 {
		t.Fatalf("graph: %+v %v", checked, err)
	}
}

func TestRecordCapabilitiesRejectConflictingEvidence(t *testing.T) {
	db, paths := testStore(t)
	r, err := (record.Service{DB: db, Paths: paths, Options: record.Options{AllowAnyWorkdir: true}}).Run(record.Request{
		RunID: "invalid-record", Workdir: t.TempDir(), Command: []string{"/bin/echo", "recorded-source"}, DisableSnapshot: true, PostRootGraceMS: 1, Stdout: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range all(t, db, r.RunID, 50) {
		if c.Snapshots[0].Boundary != "end" {
			continue
		}
		found = true
		id := strings.TrimPrefix(c.EvidenceRef, "runtime_event/")
		var original string
		if err := db.QueryRow(`SELECT payload FROM events WHERE id=?`, id).Scan(&original); err != nil {
			t.Fatal(err)
		}
		for name, expression := range map[string]string{
			"null":     `json_set(payload,'$.record_capture',null)`,
			"run":      `json_set(payload,'$.record_capture.run_id','foreign')`,
			"attempt":  `json_set(payload,'$.record_capture.attempt_id','foreign')`,
			"session":  `json_set(payload,'$.record_capture.session_id','foreign')`,
			"boundary": `json_set(payload,'$.record_capture.boundary','start')`,
			"counts":   `json_set(payload,'$.record_capture.sampling.failures',-1)`,
			"time":     `json_set(payload,'$.record_capture.sampling.started_at','2100-01-01T00:00:00Z')`,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := db.Exec(`UPDATE events SET payload=`+expression+` WHERE id=?`, id); err != nil {
					t.Fatal(err)
				}
				if _, err := (Service{DB: db}).List(context.Background(), Options{RunID: r.RunID}); err == nil {
					t.Fatal("conflicting recorder metadata was accepted")
				}
				if _, err := db.Exec(`UPDATE events SET payload=? WHERE id=?`, original, id); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	if !found {
		t.Fatal("missing end observation")
	}
}

func TestRecordCapabilitiesPreserveAbortedLifecycle(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "started"}[started], func(t *testing.T) {
			db, paths := testStore(t)
			failure := errors.New("fixture lifecycle failure")
			hooks := &record.Lifecycle{}
			if started {
				hooks.Started = func(record.ExecutionScope) error { return failure }
			} else {
				hooks.Prepared = func(record.ExecutionScope) error { return failure }
			}
			r, err := (record.Service{DB: db, Paths: paths, Lifecycle: hooks, Options: record.Options{AllowAnyWorkdir: true}}).Run(record.Request{
				RunID: "aborted-record", Workdir: t.TempDir(), Command: []string{"/bin/echo", "fixture"}, DisableSnapshot: true, Stdout: io.Discard,
			})
			if !errors.Is(err, failure) {
				t.Fatalf("missing hook failure: %v", err)
			}
			found := false
			for _, c := range all(t, db, r.RunID, 1) {
				if c.Snapshots[0].Boundary != "error" {
					continue
				}
				found = true
				if c.Status != "partial" || (c.StartedAt != "") != started || *c.Snapshots[0].Features[0].Observed != started {
					t.Fatalf("aborted lifecycle changed: %+v", c)
				}
			}
			if !found {
				t.Fatal("missing error capture observation")
			}
		})
	}
}

func TestRecordCapabilitiesExposeSamplePersistenceFailures(t *testing.T) {
	db, paths := testStore(t)
	for _, sql := range []string{
		`CREATE TRIGGER fail_sample_binding BEFORE INSERT ON execution_context_bindings WHEN NEW.binding_source='zero_sdk_record_descendant' BEGIN SELECT RAISE(ABORT,'fixture binding write failure'); END`,
		`CREATE TRIGGER fail_sample_event BEFORE INSERT ON events WHEN NEW.source='record_process_sample' BEGIN SELECT RAISE(ABORT,'fixture event write failure'); END`,
	} {
		if _, err := db.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	r, err := (record.Service{DB: db, Paths: paths, Options: record.Options{AllowShell: true, AllowAnyWorkdir: true}}).Run(record.Request{
		RunID: "sample-storage-failure", Workdir: t.TempDir(), Command: []string{"/bin/sh", "-c", "/bin/sleep 0.2 & wait"},
		DisableSnapshot: true, SampleIntervalMS: 5, PostRootGraceMS: 10, Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil || r.ExitCode != 0 || len(r.Observed) == 0 {
		t.Fatalf("fixture did not execute and observe descendants: %+v %v", r, err)
	}
	found := false
	for _, c := range all(t, db, r.RunID, 1) {
		if c.Snapshots[0].Boundary != "end" {
			continue
		}
		found = true
		if c.Status != "partial" {
			t.Fatalf("failed sampled writes hidden: %+v", c)
		}
		counts := map[string]string{}
		for _, loss := range c.Loss {
			if loss.Value != nil {
				counts[loss.Name] = *loss.Value
			}
		}
		for _, name := range []string{"sample_binding_failures", "sample_event_failures"} {
			if counts[name] == "" || counts[name] == "0" {
				t.Fatalf("missing %s: %+v", name, c)
			}
		}
	}
	if !found {
		t.Fatal("missing end observation")
	}
}

func TestRecordSamplingFailureRemainsVisible(t *testing.T) {
	db, paths := testStore(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ps"), []byte("#!/bin/sh\nexit 42\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	r, err := (record.Service{DB: db, Paths: paths, Options: record.Options{AllowShell: true, AllowAnyWorkdir: true}}).Run(record.Request{
		RunID: "record-sample-failure", Workdir: t.TempDir(), Command: []string{"/bin/sh", "-c", "exit 0"}, DisableSnapshot: true, PostRootGraceMS: 1,
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("task should still succeed: %+v %v", r, err)
	}
	got := all(t, db, r.RunID, 50)
	if len(got) != 2 {
		t.Fatalf("missing recorder observations: %+v", got)
	}
	ended := false
	for _, c := range got {
		if c.Snapshots[0].Boundary != "end" {
			continue
		}
		ended = true
		if c.Status != "partial" {
			t.Fatalf("failed ps hidden: %+v", c)
		}
		found := false
		for _, loss := range c.Loss {
			if loss.Name == "process_table_failures" && loss.Value != nil && *loss.Value != "0" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing sampling failures: %+v", c)
		}
	}
	if !ended {
		t.Fatal("missing end observation")
	}
}
