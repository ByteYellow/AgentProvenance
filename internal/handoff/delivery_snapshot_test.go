package handoff

import (
	"context"
	"database/sql/driver"
	"testing"
)

func TestDeliverySnapshotDoesNotReuseUnfinishedStatement(t *testing.T) {
	f := testDelivery(t)
	db := f.sender.Ledger.DB
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Model a cancelled driver query that abandoned its already-created rows.
	// Ordinary queries still work on this connection; VACUUM cannot reuse it.
	var abandoned driver.Rows
	err = conn.Raw(func(raw any) error {
		var err error
		abandoned, err = raw.(driver.QueryerContext).QueryContext(context.Background(), "SELECT 1 UNION ALL SELECT 2", nil)
		return err
	})
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn, err := db.Conn(context.Background())
		if err == nil {
			defer conn.Close()
			_ = conn.Raw(func(any) error { return abandoned.Close() })
		}
	})
	d := f.prepare(t, "independent-snapshot")
	if d.Manifest.CheckpointRef != f.report.CheckpointRef {
		t.Fatal("snapshot changed the checkpoint")
	}
	f.receive(t, d)
}
