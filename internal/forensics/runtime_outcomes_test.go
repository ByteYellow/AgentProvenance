package forensics_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestSignedBundleRetainsRuntimeOutcomes(t *testing.T) {
	const runID = "run-outcomes"
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	if _, err := correlation.RecordBinding(db, correlation.Binding{ID: "scope", RunID: runID, CgroupID: "cg", StartedAt: "2026-10-19T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	identity := `"source":"agentprov_ebpf","pid":42,"tgid":42,"tid":43,"cgroup_id":"cg","process_instance_id":"01234567-89ab-cdef-0123-456789abcdef:42:90","thread_instance_id":"01234567-89ab-cdef-0123-456789abcdef:43:100"`
	operation := `"operation_id":"syscall-v1:01234567-89ab-cdef-0123-456789abcdef:43:100:42:90:200","operation":"network_connect","syscall_start_ns":"200","syscall_number":203,"sensor_arch":"arm64"`
	input := fmt.Sprintf(`{%s,%s,"event_type":"network_connect","dst_ip":"169.254.169.254","dst_port":80,"observation_stage":"attempt","timestamp":"2026-10-19T00:00:01Z"}
{%s,%s,"event_type":"syscall_result","dst_ip":"169.254.169.254","dst_port":80,"observation_stage":"result","syscall_result":-13,"errno":13,"syscall_outcome":"failure","timestamp":"2026-10-19T00:00:02Z"}
{%s,"event_type":"thread_exit","exit_code":0,"exit_scope":"thread","timestamp":"2026-10-19T00:00:03Z"}
{%s,"event_type":"process_exit","exit_signal":31,"raw_exit_status":159,"exit_scope":"thread_group","termination":"signal","timestamp":"2026-10-19T00:00:04Z"}
`, identity, operation, identity, operation, identity, identity)
	result, err := telemetry.IngestJSONLReader(db, telemetry.JSONLIngestOptions{Format: "native", RunID: runID}, strings.NewReader(input))
	if err != nil || result.Ingested != 4 {
		t.Fatalf("ingest=%+v err=%v", result, err)
	}
	before, err := telemetry.ListEvents(db, runID, "")
	if err != nil {
		t.Fatal(err)
	}
	decisions := 0
	for _, e := range before {
		if _, recorded, err := security.EvaluateRuntimeEvent(db, e.ID); err != nil {
			t.Fatal(err)
		} else if recorded {
			decisions++
		}
	}
	if decisions != 1 {
		t.Fatalf("outcomes duplicated risk: %d decisions", decisions)
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
		t.Fatalf("outcome evidence changed across signed roundtrip: err=%v", err)
	}
	verified, err := provenance.Verify(replayDB, runID)
	if err != nil || verified.ErrorCount != 0 {
		t.Fatalf("verify=%+v err=%v", verified, err)
	}
}
