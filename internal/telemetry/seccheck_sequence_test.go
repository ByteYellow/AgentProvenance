package telemetry

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
)

func TestSecCheckSequenceWaitsForDurableContiguousEvidence(t *testing.T) {
	db, _ := nativeTestStore(t)
	makeRecord := func(seq uint64) seccheck.Record {
		return secCheckTestRecord(t, &wire.ExecveInfo{ContextData: secCheckTestContext(), Argv: []string{"true"}}, wire.MessageType_MESSAGE_SENTRY_EXEC, seq)
	}
	r := makeRecord(1)
	put := func(seq uint64) string {
		e, err := MapSecCheckRecord("receiver-run", makeRecord(seq))
		if err != nil {
			t.Fatal(err)
		}
		id, _, err := ingestSecCheckEvent(db, e)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := put(1)
	put(3)
	read := func() []EventRecord {
		events, err := ReadSecCheckSequence(context.Background(), db, "receiver-run", r.Registration, r.ConnectionID, 1, 3)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	if events := read(); len(events) != 1 || events[0].ID != first {
		t.Fatalf("out-of-order ingestion crossed missing sequence: %+v", events)
	}
	put(2)
	if events := read(); len(events) != 3 {
		t.Fatalf("late committed record not recovered: %d", len(events))
	}
	if _, err := ReadSecCheckSequence(context.Background(), db, "another-run", r.Registration, r.ConnectionID, 1, 3); err == nil {
		t.Fatal("receiver run mismatch accepted")
	}
	other := r.Registration
	other.Generation = "new"
	for _, item := range []struct {
		registration seccheck.Registration
		connection   string
	}{{other, r.ConnectionID}, {r.Registration, "reconnected"}} {
		rows, err := ReadSecCheckSequence(context.Background(), db, "receiver-run", item.registration, item.connection, 1, 3)
		if err != nil || len(rows) != 0 {
			t.Fatalf("cross-generation/connection lookup: %d %v", len(rows), err)
		}
	}
	if _, err := db.Exec(`UPDATE events SET payload=? WHERE id=?`, strings.Repeat("x", secCheckRecordBytes+1), first); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecCheckSequence(context.Background(), db, "receiver-run", r.Registration, r.ConnectionID, 1, 3); err == nil {
		t.Fatal("oversized evidence accepted")
	}
}

func TestSecCheckSequenceBoundsAndCancellation(t *testing.T) {
	db, _ := nativeTestStore(t)
	r := secCheckTestRecord(t, &wire.ExecveInfo{ContextData: secCheckTestContext()}, wire.MessageType_MESSAGE_SENTRY_EXEC, 1)
	for _, tc := range []struct {
		first uint64
		count int
	}{{1, 0}, {1, 257}, {math.MaxUint64, 2}} {
		if _, err := ReadSecCheckSequence(context.Background(), db, "run", r.Registration, r.ConnectionID, tc.first, tc.count); err == nil {
			t.Fatal("invalid page accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadSecCheckSequence(ctx, db, "run", r.Registration, r.ConnectionID, 1, 1); err == nil {
		t.Fatal("cancelled lookup succeeded")
	}
}
