package forensics_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"google.golang.org/protobuf/proto"
)

func TestSecCheckSignedRoundtripAndScopeValidation(t *testing.T) {
	paths := mustInit(t, t.TempDir())
	db := mustOpen(t, paths)
	defer db.Close()
	stream, err := telemetry.NewSecCheckStream(db, paths, telemetry.NativeStreamOptions{BatchEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	for _, sandbox := range []string{"one", "two"} {
		reg := seccheck.Registration{Namespace: "fixture", InstanceID: "node", Generation: "1", SandboxID: sandbox, ContainerID: sandbox}
		c := &wire.ContextData{ContainerId: sandbox, ThreadId: 1, ThreadGroupId: 1, ThreadStartTimeNs: 1800000000000000001, ThreadGroupStartTimeNs: 1800000000000000001, TimeNs: 1800000000000000111}
		data, err := proto.Marshal(&wire.Open{ContextData: c, Pathname: "/work/report.csv"})
		if err != nil {
			t.Fatal(err)
		}
		header := make([]byte, 8)
		binary.LittleEndian.PutUint16(header, 8)
		binary.LittleEndian.PutUint16(header[2:], uint16(wire.MessageType_MESSAGE_SYSCALL_OPEN))
		packet, err := seccheck.DecodePacket(append(header, data...))
		if err != nil {
			t.Fatal(err)
		}
		r := seccheck.Record{Kind: "event", Registration: reg, ConnectionID: "connection", Sequence: 1, ReceivedAt: time.Unix(1800000001, 0).UTC(), ProtocolVersion: 1, Packet: &packet}
		if err := stream.Sink("sentry-roundtrip", reg)(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	if err := stream.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := telemetry.ListEvents(db, "sentry-roundtrip", "")
	if err != nil || len(before) != 2 {
		t.Fatalf("events=%d %v", len(before), err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("sentry-roundtrip")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, public); err != nil {
		t.Fatal(err)
	}
	replayPaths := mustInit(t, t.TempDir())
	replayDB := mustOpen(t, replayPaths)
	defer replayDB.Close()
	if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	after, err := telemetry.ListEvents(replayDB, "sentry-roundtrip", "")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("signed projection changed: %v", err)
	}
	verified, err := provenance.Verify(replayDB, "sentry-roundtrip")
	if err != nil || verified.ErrorCount != 0 || verified.WarningCount != 0 {
		t.Fatalf("verify=%+v %v", verified, err)
	}
	first, second := telemetry.ProcessGraphIdentity(after[0]), telemetry.ProcessGraphIdentity(after[1])
	if first.Process.ID == second.Process.ID || first.Process.Basis != "sentry_process_instance" {
		t.Fatal("sandbox identities merged")
	}
	for _, statement := range []string{
		`UPDATE events SET container_id='host-container'`,
		`UPDATE events SET pid=999`,
		`UPDATE events SET payload=json_set(payload,'$.sentry.registration.generation','other')`,
		`UPDATE events SET raw_event_id='forged'`,
		`UPDATE events SET created_at='2026-01-01T00:00:00Z'`,
	} {
		tx, err := replayDB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(statement); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		broken, err := provenance.Verify(replayDB, "sentry-roundtrip")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, issue := range broken.Issues {
			if issue.Kind == "invalid_seccheck_scope" {
				found = true
			}
		}
		if !found {
			t.Fatalf("scope mutation accepted: %s %+v", statement, broken)
		}
		for _, e := range after {
			if _, err := replayDB.Exec(`UPDATE events SET container_id=?,pid=?,payload=?,raw_event_id=?,created_at=? WHERE id=?`, e.ContainerID, e.PID, e.Payload, e.RawEventID, e.CreatedAt, e.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
}
