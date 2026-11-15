package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestReplaySelectionSecCheckUploadReferences(t *testing.T) {
	_, db, _ := artifactStore(t)
	ctx := context.Background()
	reg := seccheck.Registration{Namespace: "fixture", InstanceID: "original", Generation: "1", SandboxID: "same", ContainerID: "same"}
	event, err := telemetry.MapSecCheckRecord("spool-run", seccheck.Record{Kind: "stream", Reason: "receiver_ready", Registration: reg,
		ConnectionID: "original-connection", ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	if err := json.NewEncoder(&raw).Encode(event); err != nil {
		t.Fatal(err)
	}
	var receipts []telemetry.SecCheckReplayDelivery
	for _, instance := range []string{"clone-a", "clone-b"} {
		reg.InstanceID = instance
		result, err := telemetry.ReplaySecCheckSpool(ctx, db, bytes.NewReader(raw.Bytes()), fmt.Sprintf("%x", sha256.Sum256(raw.Bytes())),
			seccheck.Target{RunID: "uploader", SocketPath: "/tmp/registered.sock", Registration: reg})
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, result.Receipts...)
	}
	snapshot, err := (Server{DB: db}).freezeReplaySource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	server := Server{DB: snapshot.DB}
	whole, err := server.resolveReplaySelection(ctx, ReplaySelection{RunID: "spool-run", Scope: "whole_run"})
	if err != nil || whole.summary().Included != 3 {
		t.Fatalf("whole: %+v %v", whole, err)
	}
	excluded := "3/" + receipts[0].EventIDs[0]
	plan, err := server.resolveReplaySelection(ctx, ReplaySelection{RunID: "spool-run", Scope: "whole_run", ExcludeRecords: []string{excluded}})
	if err != nil {
		t.Fatal(err)
	}
	decisions := selectionDecisions(plan)
	for _, receipt := range receipts {
		decision := decisions["3/"+receipt.ReceiptID]
		if decision.Included || decision.Reason != "spool_replay_support_not_included" || decision.RelatedRecord != excluded {
			t.Fatalf("receipt escaped selection: %+v", decision)
		}
	}
	projection, err := snapshot.projectSelection(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer projection.Close()
	var count int
	if err := projection.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unselected references exported: %d %v", count, err)
	}
	// Excluding a delivery receipt alone does not remove its historical source.
	plan, err = server.resolveReplaySelection(ctx, ReplaySelection{RunID: "spool-run", Scope: "whole_run", ExcludeRecords: []string{"3/" + receipts[0].ReceiptID}})
	if err != nil || !selectionDecisions(plan)[excluded].Included || plan.summary().Included != 2 {
		t.Fatalf("receipt exclusion removed history: %+v %v", plan, err)
	}
}
