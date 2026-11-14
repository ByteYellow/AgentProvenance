package telemetry

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Hold the SQLite writer until both producers try to reserve capacity. With
// an unlocked read/check, both see the same empty queue before either inserts.
type capacityConnector struct {
	driver driver.Driver
	dsn    string
	writes chan struct{}
}

func (c *capacityConnector) Driver() driver.Driver { return c.driver }
func (c *capacityConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.driver.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &capacityConn{Conn: conn, writes: c.writes}, nil
}

type capacityConn struct {
	driver.Conn
	writes chan struct{}
	once   sync.Once
}

func (c *capacityConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c *capacityConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}
func (c *capacityConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(query, "UPDATE schema_versions") || strings.HasPrefix(query, "INSERT INTO telemetry_spool_batches") {
		c.once.Do(func() { c.writes <- struct{}{} })
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func TestRuntimeStreamsReserveSharedCapacityAtomically(t *testing.T) {
	db, paths := nativeTestStore(t)
	opts := NativeStreamOptions{BatchBytes: 1024, MaxQueuedBytes: 1024, MaxQueuedBatches: 1}
	native := nativeTestStream(t, db, paths, opts)
	sentry, err := NewSecCheckStream(db, paths, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sentry.Close() })
	writes := make(chan struct{}, 2)
	wrapped := sql.OpenDB(&capacityConnector{driver: db.Driver(), dsn: paths.DB, writes: writes})
	native.service.DB, sentry.stream.service.DB = wrapped, wrapped
	t.Cleanup(func() {
		native.service.DB, sentry.stream.service.DB = db, db
		wrapped.Close()
	})
	writer, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err := writer.Exec(`UPDATE schema_versions SET version=version WHERE 0`); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for _, stream := range []*NativeStream{native, sentry.stream} {
		go func(n *NativeStream) { results <- n.openBatch() }(stream)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-writes:
		case <-time.After(5 * time.Second):
			writer.Rollback()
			<-results
			<-results
			t.Fatal("producers did not reach reservation writes")
		}
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	accepted, refused := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		var pressure SpoolBackpressureError
		switch {
		case err == nil:
			accepted++
		case errors.As(err, &pressure):
			refused++
		default:
			t.Errorf("reservation: %v", err)
		}
	}
	var count, bytes int64
	if err := db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size_bytes),0) FROM telemetry_spool_batches`).Scan(&count, &bytes); err != nil {
		t.Fatal(err)
	}
	if accepted != 1 || refused != 1 || count != 1 || bytes != 1024 {
		t.Fatalf("shared budget exceeded: accepted=%d refused=%d batches=%d bytes=%d", accepted, refused, count, bytes)
	}
}
