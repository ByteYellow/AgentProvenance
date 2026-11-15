package dashboard

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/capturemanifest"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"google.golang.org/protobuf/proto"
)

func TestOfflineSentryWitnessesUseOnlyFrozenSelectedEvents(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	const run = "sentry-capture"
	save := func(sequence int, result bool) string {
		t.Helper()
		at := time.Date(2026, 11, 15, 0, 0, 0, sequence, time.UTC)
		m := &wire.Open{ContextData: &wire.ContextData{ContainerId: "sandbox", TimeNs: at.UnixNano(), ThreadId: 1, ThreadGroupId: 1, ThreadStartTimeNs: 1, ThreadGroupStartTimeNs: 1}, Pathname: "/work/manifest-input", Sysno: 56}
		if result {
			m.Exit = &wire.Exit{Result: 3}
		}
		raw, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		header := make([]byte, seccheck.HeaderBytes)
		binary.LittleEndian.PutUint16(header, seccheck.HeaderBytes)
		binary.LittleEndian.PutUint16(header[2:], uint16(wire.MessageType_MESSAGE_SYSCALL_OPEN))
		packet, err := seccheck.DecodePacket(append(header, raw...))
		if err != nil {
			t.Fatal(err)
		}
		e, err := telemetry.MapSecCheckRecord(run, seccheck.Record{Kind: "event", Registration: seccheck.Registration{Namespace: "fixture", InstanceID: "i", Generation: "g", SandboxID: "sandbox", ContainerID: "sandbox"},
			ConnectionID: "connection", Sequence: uint64(sequence), ReceivedAt: at, ProtocolVersion: seccheck.ProtocolVersion, Packet: &packet})
		if err != nil {
			t.Fatal(err)
		}
		id, err := telemetry.IngestFiltered(db, e)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	save(1, false)
	save(2, false)
	save(3, true)
	page, err := (capturemanifest.Service{DB: db}).List(ctx, capturemanifest.Options{RunID: run})
	if err != nil || len(page.Records) != 2 {
		t.Fatalf("original witnesses: %+v %v", page, err)
	}
	excluded := ""
	for _, r := range page.Records {
		if strings.HasPrefix(r.Snapshots[0].Features[0].Target, "attempt/") {
			excluded = strings.TrimPrefix(r.EvidenceRef, "runtime_event/")
		}
	}
	if excluded == "" {
		t.Fatal("missing attempt witness")
	}
	prepared := map[string]*PreparedReplay{}
	for name, selection := range map[string]ReplaySelection{
		"whole":    {RunID: run, Scope: "whole_run"},
		"excluded": {RunID: run, Scope: "whole_run", ExcludeRecords: []string{"3/" + excluded}},
		"empty":    {RunID: run, Scope: "whole_run", ExcludeCategories: []string{"runtime"}},
	} {
		p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(ctx, selection)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		prepared[name] = p
	}
	late := save(4, false)
	if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, p := range prepared {
		t.Run(name, func(t *testing.T) {
			files, _ := replayZIPData(t, p)
			records, scope := readReplayCapture(t, files, run)
			switch name {
			case "whole":
				if scope != "whole_run" || !reflect.DeepEqual(records, page.Records) {
					t.Fatalf("frozen witnesses changed: %+v", records)
				}
			case "excluded":
				if scope != "selected_evidence" || len(records) != 2 {
					t.Fatalf("retained second observation not used: %+v", records)
				}
			case "empty":
				if scope != "selected_evidence" || len(records) != 0 {
					t.Fatalf("excluded runtime still supports manifest: %+v", records)
				}
			}
			for _, r := range records {
				if r.EvidenceRef == "runtime_event/"+late || (name != "whole" && r.EvidenceRef == "runtime_event/"+excluded) {
					t.Fatalf("unselected witness leaked: %+v", r)
				}
			}
			if root := os.Getenv("AGENTPROV_SENTRY_REPLAY_OUTPUT"); root != "" {
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
