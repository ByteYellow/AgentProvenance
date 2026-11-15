package capturemanifest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"google.golang.org/protobuf/proto"
)

func sentryOpen(t *testing.T, db *sql.DB, run, generation, connection string, sequence, sysno uint64, result bool, drops uint32) string {
	t.Helper()
	at := time.Date(2026, 11, 15, 0, 0, 0, int(sequence), time.UTC)
	ctx := &wire.ContextData{ContainerId: "container", TimeNs: at.UnixNano(), ThreadId: 7, ThreadStartTimeNs: at.Add(-time.Hour).UnixNano(),
		ThreadGroupId: 7, ThreadGroupStartTimeNs: at.Add(-time.Hour).UnixNano()}
	msg := &wire.Open{ContextData: ctx, Pathname: "/work/manifest-input", Sysno: sysno}
	if result {
		msg.Exit = &wire.Exit{Result: 3}
	}
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, seccheck.HeaderBytes)
	binary.LittleEndian.PutUint16(header, seccheck.HeaderBytes)
	binary.LittleEndian.PutUint16(header[2:], uint16(wire.MessageType_MESSAGE_SYSCALL_OPEN))
	binary.LittleEndian.PutUint32(header[4:], drops)
	packet, err := seccheck.DecodePacket(append(header, raw...))
	if err != nil {
		t.Fatal(err)
	}
	delta := uint64(drops)
	rec := seccheck.Record{Kind: "event", Registration: seccheck.Registration{Namespace: "lab", InstanceID: "same-instance", Generation: generation, SandboxID: "sandbox", ContainerID: "container"},
		ConnectionID: connection, Sequence: sequence, ReceivedAt: at.Add(time.Second), ProtocolVersion: seccheck.ProtocolVersion, Packet: &packet, DroppedDelta: &delta}
	e, err := telemetry.MapSecCheckRecord(run, rec)
	if err != nil {
		t.Fatal(err)
	}
	id, err := telemetry.IngestFiltered(db, e)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSentryObservedPointsRetainStagesAndQualifiedWitnesses(t *testing.T) {
	db, _ := testStore(t)
	for _, generation := range []string{"original", "clone"} {
		for _, connection := range []string{"first", "reconnected"} {
			sentryOpen(t, db, "observed", generation, connection, 1, 56, false, 0)
			sentryOpen(t, db, "observed", generation, connection, 2, 56, false, 0)
			sentryOpen(t, db, "observed", generation, connection, 3, 56, true, 0)
			// The protocol uses the same Open message for multiple syscalls.
			sentryOpen(t, db, "observed", generation, connection, 4, 257, false, 0)
		}
	}
	sentryOpen(t, db, "other", "original", "first", 1, 56, false, 0)
	got := all(t, db, "observed", 1)
	if len(got) != 12 {
		t.Fatalf("want twelve qualified point/stage witnesses, got %d", len(got))
	}
	for _, limit := range []int{2, 50, 200} {
		if next := all(t, db, "observed", limit); !reflect.DeepEqual(got, next) {
			t.Fatalf("page size %d changed witnesses", limit)
		}
	}
	seen := map[string]bool{}
	for _, r := range got {
		if r.IntervalBasis != "checkpoint_observation" || r.Status != "observed" || r.IdentityDomain != "sentry" || !strings.HasPrefix(r.EvidenceRef, "runtime_event/") || len(r.Snapshots) != 1 {
			t.Fatalf("invalid observed record: %+v", r)
		}
		p := r.Snapshots[0]
		if p.Ready != nil || len(p.Features) != 1 || p.Features[0].State != "observed" || p.Features[0].Enabled != nil || p.Features[0].Supported != nil || p.Features[0].Observed == nil || !*p.Features[0].Observed {
			t.Fatalf("observation became an enablement or readiness assertion: %+v", p)
		}
		key := r.Identity["generation"] + "/" + r.Identity["connection_id"] + "/" + p.Features[0].Target
		if seen[key] {
			t.Fatalf("duplicate point witness: %s", key)
		}
		seen[key] = true
		if r.ProducerVersion != "unknown" || r.StartedAt != "" || r.EndedAt != "" {
			t.Fatalf("reader filled unknown metadata or coverage interval: %+v", r)
		}
	}
}

func TestSentryPointWitnessesKeepLossObservations(t *testing.T) {
	db, _ := testStore(t)
	for i := 1; i <= 8; i++ {
		sentryOpen(t, db, "loss", "g", "c", uint64(i), 56, false, 0)
	}
	loss := sentryOpen(t, db, "loss", "g", "c", 9, 56, false, 4)
	reset := sentryOpen(t, db, "loss", "g", "c", 10, 56, false, 0)
	gap := sentryOpen(t, db, "loss", "g", "c", 11, 56, false, 0)
	if _, err := db.Exec(`UPDATE events SET payload=json_remove(json_set(payload,'$.sentry.drop_counter_decreased',json('true')),'$.sentry.dropped_delta') WHERE id=?`, reset); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE events SET payload=json_set(payload,'$.sentry.context.thread_start_ns',0,'$.sentry.identity_gaps',json('["thread_birth_missing"]')) WHERE id=?`, gap); err != nil {
		t.Fatal(err)
	}
	got := all(t, db, "loss", 1)
	found, foundReset, foundGap := false, false, false
	for _, r := range got {
		if r.EvidenceRef == "runtime_event/"+loss {
			found = len(r.Loss) == 1 && r.Loss[0].Value != nil && *r.Loss[0].Value == "4"
		}
		if r.EvidenceRef == "runtime_event/"+reset {
			foundReset = r.Loss[0].Value == nil && strings.Contains(strings.Join(r.Issues, ","), "drop_counter_decreased")
		}
		if r.EvidenceRef == "runtime_event/"+gap {
			foundGap = strings.Contains(strings.Join(r.Issues, ","), "thread_birth_missing")
		}
	}
	if !found || !foundReset || !foundGap || len(got) > 4 {
		t.Fatalf("loss hidden or every event copied to manifest: %+v", got)
	}
}

func TestSentryObservedPointsSurviveSignedImport(t *testing.T) {
	db, paths := testStore(t)
	for i := 1; i <= 3; i++ {
		sentryOpen(t, db, "signed-points", "g", "c", uint64(i), 56, i == 2, 0)
	}
	before := all(t, db, "signed-points", 1)
	if len(before) != 2 {
		t.Fatalf("missing saved witnesses: %d", len(before))
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("signed-points")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	dst, dest := testStore(t)
	if _, err := (forensics.Service{DB: dst, Paths: dest}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	if after := all(t, dst, "signed-points", 2); !reflect.DeepEqual(before, after) {
		t.Fatalf("signed witness projection changed: %+v", after)
	}
}

func TestSentryObservedPointsUnwrapAndRejectInvalidWitness(t *testing.T) {
	for _, mode := range []string{"nested", "identity", "stage", "syscall", "depth", "json"} {
		t.Run(mode, func(t *testing.T) {
			db, _ := testStore(t)
			id := sentryOpen(t, db, "r", "g", "c", 1, 56, false, 0)
			var payload string
			if err := db.QueryRow(`SELECT payload FROM events WHERE id=?`, id).Scan(&payload); err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal([]byte(payload), &body); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "nested", "depth":
				depth := 7
				if mode == "depth" {
					depth = 8
				}
				for i := 0; i < depth; i++ {
					payload = `{"payload":` + payload + `}`
				}
			case "identity":
				if _, err := db.Exec(`UPDATE events SET container_id='foreign' WHERE id=?`, id); err != nil {
					t.Fatal(err)
				}
			case "stage":
				body["observation_stage"] = json.RawMessage(`"sentry_checkpoint"`)
				raw, _ := json.Marshal(body)
				payload = string(raw)
			case "syscall":
				body["syscall_number"] = json.RawMessage(`-1`)
				raw, _ := json.Marshal(body)
				payload = string(raw)
			case "json":
				payload = `{"broken"`
			}
			if _, err := db.Exec(`UPDATE events SET payload=? WHERE id=?`, payload, id); err != nil {
				t.Fatal(err)
			}
			page, err := (Service{DB: db}).List(context.Background(), Options{RunID: "r"})
			if mode == "nested" {
				if err != nil || len(page.Records) != 1 {
					t.Fatalf("nested evidence: %+v %v", page, err)
				}
			} else if err == nil {
				t.Fatalf("%s evidence silently omitted or accepted: %+v", mode, page)
			}
		})
	}
}

func TestSentryObservedPointsEnumerateAllConnections(t *testing.T) {
	db, _ := testStore(t)
	for i := 0; i < 260; i++ {
		sentryOpen(t, db, "many", "g", fmt.Sprintf("c-%03d", i), 1, 56, false, 0)
	}
	if got := all(t, db, "many", 73); len(got) != 260 {
		t.Fatalf("connections truncated: %d", len(got))
	}
}

func TestSentryObservedPointsPreserveUnsignedSyscallIdentity(t *testing.T) {
	db, _ := testStore(t)
	for i, sysno := range []uint64{9007199254740992, 9007199254740993, 18446744073709551614, 18446744073709551615} {
		sentryOpen(t, db, "exact", "g", "c", uint64(i+1), sysno, false, 0)
	}
	got := all(t, db, "exact", 1)
	if len(got) != 4 {
		t.Fatalf("unsigned syscall identities rounded together: %+v", got)
	}
}
