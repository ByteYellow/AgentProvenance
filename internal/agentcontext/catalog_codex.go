package agentcontext

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxCodexCatalogs = 32

// Catalog paths supplement source discovery, not source identity or timestamps.
// A catalog row alone never proves which execution produced a transcript.
func discoverCodexCatalogs(ctx context.Context, root string, inv *Inventory, budget *int64, add func(string, string, fs.FileInfo)) error {
	info, err := os.Stat(root)
	if os.IsNotExist(err) || (err == nil && !info.IsDir()) {
		return nil
	}
	if err != nil {
		inv.problem("catalog_root_unreadable")
		return nil
	}
	dir, err := os.Open(root)
	if err != nil {
		inv.problem("catalog_root_unreadable")
		return nil
	}
	defer dir.Close()
	visits, catalogs, rowsLeft := 0, 0, MaxDiscoveryFiles
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, readErr := dir.ReadDir(256)
		for _, entry := range entries {
			visits++
			if visits > MaxDiscoveryVisits {
				inv.problem("catalog_scan_limit")
				return nil
			}
			name := entry.Name()
			if !strings.HasPrefix(name, "state_") || !strings.HasSuffix(name, ".sqlite") {
				continue
			}
			file, err := entry.Info()
			if err != nil || !file.Mode().IsRegular() {
				inv.problem("catalog_not_regular")
				continue
			}
			catalogs++
			if catalogs > maxCodexCatalogs {
				inv.problem("catalog_count_limit")
				return nil
			}
			readCodexCatalog(ctx, filepath.Join(root, name), root, inv, budget, &rowsLeft, add)
			if rowsLeft <= 0 {
				inv.problem("catalog_row_limit")
				return ctx.Err()
			}
			if *budget <= 0 {
				return ctx.Err()
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			inv.problem("catalog_root_unreadable")
			return nil
		}
	}
}

func readCodexCatalog(parent context.Context, path, root string, inv *Inventory, budget *int64, rowsLeft *int, add func(string, string, fs.FileInfo)) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	uri := url.URL{Scheme: "file", Path: path}
	q := uri.Query()
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", "busy_timeout(100)")
	q.Add("_pragma", "trusted_schema(0)")
	uri.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		inv.problem("catalog_unreadable")
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var kind string
	err = db.QueryRowContext(ctx, `SELECT type FROM sqlite_schema WHERE name='threads'`).Scan(&kind)
	if err != nil || kind != "table" {
		code := "catalog_unreadable"
		if errors.Is(err, sql.ErrNoRows) || err == nil {
			code = "catalog_schema_unsupported"
		}
		inv.problem(code)
		return
	}
	// Bound values in SQL before allocating strings in Go. Never execute
	// catalog-owned views or interpolate catalog data as identifiers or SQL.
	rows, err := db.QueryContext(ctx, `SELECT substr(id,1,1025), substr(rollout_path,1,4097),
		typeof(id), typeof(rollout_path) FROM threads LIMIT ?`, *rowsLeft+1)
	if err != nil {
		inv.problem("catalog_query_failed")
		return
	}
	defer rows.Close()
	for rows.Next() {
		if *rowsLeft <= 0 {
			inv.problem("catalog_row_limit")
			return
		}
		*rowsLeft--
		var id, source sql.NullString
		var idType, sourceType string
		if err := rows.Scan(&id, &source, &idType, &sourceType); err != nil {
			inv.problem("catalog_row_unreadable")
			return
		}
		if idType != "text" || sourceType != "text" || id.String == "" || source.String == "" ||
			len(id.String) > 1024 || len(source.String) > 4096 || strings.ContainsRune(source.String, 0) {
			inv.problem("catalog_row_invalid")
			continue
		}
		if filepath.Ext(source.String) != ".jsonl" {
			inv.problem("catalog_source_format_unsupported")
			continue
		}
		sourcePath := source.String
		if !filepath.IsAbs(sourcePath) {
			sourcePath = filepath.Join(root, sourcePath)
		}
		sourcePath = filepath.Clean(sourcePath)
		info, err := os.Lstat(sourcePath)
		if err != nil || !info.Mode().IsRegular() {
			inv.problem("catalog_source_unavailable")
			continue
		}
		if *budget <= 0 {
			inv.problem("discovery_size_limit")
			return
		}
		add(sourcePath, id.String, info)
		if *budget <= 0 {
			inv.problem("discovery_size_limit")
			return
		}
	}
	if rows.Err() != nil {
		inv.problem("catalog_query_failed")
	}
}
