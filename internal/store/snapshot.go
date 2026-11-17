package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
)

// FreezeDatabase copies the committed main database through a fresh, read-only
// source connection. A pooled connection may still carry a driver statement
// abandoned during cancellation; VACUUM requires an idle SQLite connection.
func FreezeDatabase(ctx context.Context, db *sql.DB, destination string) error {
	var source string
	if err := db.QueryRowContext(ctx, "SELECT file FROM pragma_database_list WHERE name='main'").Scan(&source); err != nil {
		return fmt.Errorf("locate snapshot source: %w", err)
	}
	if source == "" {
		return fmt.Errorf("database snapshots require a file-backed source")
	}
	uri := url.URL{Scheme: "file", OmitHost: true, Path: filepath.ToSlash(source), RawQuery: "mode=ro&cache=private&_pragma=busy_timeout(5000)"}
	reader, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return err
	}
	defer reader.Close()
	_, err = reader.ExecContext(ctx, "VACUUM INTO ?", destination)
	return err
}
