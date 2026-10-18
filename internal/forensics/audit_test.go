package forensics_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestSignedBundleRetainsAuditDecisions(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			const runID = "run-audit"
			paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
			db := mustOpen(t, paths)
			defer db.Close()
			policy, err := agentcontext.NewCapturePolicy(preset, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := (agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}).EnsureCapturePolicy(context.Background(), runID); err != nil {
				t.Fatal(err)
			}
			input := `type=AVC msg=audit(1792342593.757:130): apparmor="DENIED" operation="open" profile="fixture-policy" pid=42 name="/tmp/fixture" requested_mask="r" denied_mask="r"
type=SECCOMP msg=audit(1792342593.758:131): pid=42 arch=c00000b7 syscall=203 sig=0 code=0x7ffc0000
type=SECCOMP msg=audit(1792342593.759:132): pid=43 arch=c000003e syscall=39 sig=31 code=0x80000000
`
			opts := telemetry.AuditIngestOptions{RunID: runID, RetainRaw: policy.SourceRecords, Source: telemetry.AuditSource{
				HostID: "fixture-host", BootID: "01234567-89ab-cdef-0123-456789abcdef"}}
			result, err := telemetry.IngestAuditReader(context.Background(), db, opts, strings.NewReader(input))
			if err != nil || result.Ingested != 3 {
				t.Fatalf("ingest=%+v err=%v", result, err)
			}
			before, err := telemetry.ListEvents(db, runID, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range before {
				if _, recorded, err := security.EvaluateRuntimeEvent(db, e.ID); err != nil || recorded {
					t.Fatalf("external audit decision caused enforcement: recorded=%v err=%v", recorded, err)
				}
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle(runID)
			if err != nil {
				t.Fatal(err)
			}
			if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
				t.Fatal(err)
			}
			replayPaths := mustInit(t, filepath.Join(t.TempDir(), "replay"))
			replayDB := mustOpen(t, replayPaths)
			defer replayDB.Close()
			if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
				t.Fatal(err)
			}
			after, err := telemetry.ListEvents(replayDB, runID, "")
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("audit evidence changed across signed roundtrip: %v", err)
			}
			verified, err := provenance.Verify(replayDB, runID)
			if err != nil || verified.ErrorCount != 0 {
				t.Fatalf("verify=%+v err=%v", verified, err)
			}
			result, err = telemetry.IngestAuditReader(context.Background(), replayDB, opts, strings.NewReader(input))
			if err != nil || result.Ingested != 0 || result.Duplicates != 3 {
				t.Fatalf("reimport changed stable identity: %+v %v", result, err)
			}
		})
	}
}

func TestSignedBundleRetainsAuditAssociationInputs(t *testing.T) {
	const run = "audit-association"
	const boot = "01234567-89ab-cdef-0123-456789abcdef"
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	ctx := context.Background()
	input := `type=SECCOMP msg=audit(1792342593.757:130): pid=42 comm="fixture" arch=c00000b7 syscall=203 code=0x7ffc0000`
	if r, err := telemetry.IngestAuditReader(ctx, db, telemetry.AuditIngestOptions{RunID: run,
		Source: telemetry.AuditSource{HostID: "fixture-host", BootID: boot}}, strings.NewReader(input)); err != nil || r.Ingested != 1 {
		t.Fatalf("audit import: %+v %v", r, err)
	}
	at := time.Unix(1792342593, 757000000).UTC()
	for _, event := range []struct {
		typeName, stage string
		delta           time.Duration
	}{{"execve", "", -5 * time.Millisecond}, {"network_connect", "attempt", 100 * time.Microsecond},
		{"syscall_result", "result", 200 * time.Microsecond}, {"process_exit", "", 6 * time.Millisecond}} {
		body := map[string]any{"host_id": "fixture-host", "boot_id": boot, "process_instance_id": boot + ":42:1000000000",
			"process_start_ns": "1000000000", "monotonic_ns": fmt.Sprint(int64(10*time.Second) + int64(event.delta)),
			"realtime_coarse_resolution_ns": int64(4 * time.Millisecond), "comm": "fixture", "command": "fixture",
			"dst_ip": "127.0.0.1", "exit_code": 0, "exit_scope": "thread_group"}
		if event.stage != "" {
			body["operation_id"], body["operation"] = "syscall-v1:"+boot+":43:1000000000:42:1000000000:10000100000", "network_connect"
			body["tid"], body["thread_instance_id"], body["thread_start_ns"] = 43, boot+":43:1000000000", "1000000000"
			body["syscall_start_ns"], body["syscall_number"], body["sensor_arch"], body["observation_stage"] = "10000100000", 203, "arm64", event.stage
			if event.stage == "result" {
				body["syscall_result"], body["syscall_outcome"] = 0, "success"
			}
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{RunID: run, PID: 42, TGID: 42,
			Source: "agentprov_ebpf", EventType: event.typeName, Timestamp: at.Add(event.delta).Format(time.RFC3339Nano), Payload: string(raw)}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := telemetry.BuildAuditAssociations(ctx, db, telemetry.AuditAssociationOptions{RunID: run})
	if err != nil || len(before.Items) != 1 || before.Items[0].Operation.Status != "inferred" {
		t.Fatalf("before=%+v %v", before, err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	replayPaths := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	replayDB := mustOpen(t, replayPaths)
	defer replayDB.Close()
	if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	after, err := telemetry.BuildAuditAssociations(ctx, replayDB, telemetry.AuditAssociationOptions{RunID: run})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("association inputs/refs changed in signed replay: before=%+v after=%+v err=%v", before, after, err)
	}
	verified, err := provenance.Verify(replayDB, run)
	if err != nil || verified.ErrorCount != 0 {
		t.Fatalf("graph verification=%+v %v", verified, err)
	}
}
