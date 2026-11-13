package forensics

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/store"
)

var ErrBundleConflict = errors.New("bundle_evidence_conflict")

const MaxStrictBundleBytes int64 = 256 << 20

// ImportBundleStrict is the append-only import path for authenticated handoffs.
// The caller verifies the sender and signature first. The decoded bundle is
// retained by digest; its projection never replaces existing evidence rows.
func (s Service) ImportBundleStrict(ctx context.Context, path, expectedRun string) (ImportInfo, error) {
	if !bundleComponent(expectedRun) {
		return ImportInfo{}, fmt.Errorf("invalid expected bundle run")
	}
	raw, err := readBoundedBundle(ctx, path, MaxStrictBundleBytes)
	if err != nil {
		return ImportInfo{}, err
	}
	if err := validateStrictBundle(ctx, raw, expectedRun); err != nil {
		return ImportInfo{}, err
	}
	sum := sha256.Sum256(raw)
	archiveRoot := filepath.Join(s.Paths.Artifacts, "received")
	if err := os.MkdirAll(archiveRoot, 0o700); err != nil {
		return ImportInfo{}, err
	}
	work, err := os.MkdirTemp(archiveRoot, ".import-")
	if err != nil {
		return ImportInfo{}, err
	}
	defer os.RemoveAll(work)
	stage := filepath.Join(work, "archive")
	if err := os.Mkdir(stage, 0o700); err != nil {
		return ImportInfo{}, err
	}
	archive := filepath.Join(archiveRoot, hex.EncodeToString(sum[:]))
	bundlePath := filepath.Join(stage, "bundle.json")
	if err := os.WriteFile(bundlePath, raw, 0o600); err != nil {
		return ImportInfo{}, err
	}
	stagePaths, err := store.Init(filepath.Join(stage, "store"))
	if err != nil {
		return ImportInfo{}, err
	}
	db, err := store.Open(stagePaths)
	if err != nil {
		return ImportInfo{}, err
	}
	defer db.Close()
	info, err := (Service{DB: db, Paths: stagePaths}).importBundle(ctx, bundlePath, raw)
	if err != nil {
		return ImportInfo{}, err
	}
	if err := prepareArchivePaths(ctx, db, stagePaths, expectedRun, stage, archive); err != nil {
		return ImportInfo{}, err
	}
	if err := db.Close(); err != nil {
		return ImportInfo{}, err
	}
	projection := filepath.Join(work, "projection.sqlite")
	if err := os.Rename(stagePaths.DB, projection); err != nil {
		return ImportInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return ImportInfo{}, err
	}
	// Publish complete content before referencing it from the receiving store.
	// A later database failure may leave an unreferenced archive, never missing
	// bodies behind a committed evidence row.
	if err := publishBundleArchive(ctx, stage, archive, raw); err != nil {
		return ImportInfo{}, err
	}
	source, err := sql.Open("sqlite", "file:"+projection+"?mode=ro")
	if err != nil {
		return ImportInfo{}, err
	}
	defer source.Close()
	source.SetMaxOpenConns(1)
	err = store.WithWriteTx(ctx, s.DB, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "PRAGMA defer_foreign_keys=ON"); err != nil {
			return err
		}
		for _, table := range append(append([]string{}, importTableOrder...), "telemetry_batches") {
			if err := copyStrictRows(ctx, tx, source, table, archive); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return ImportInfo{}, err
	}
	info.BundlePath = filepath.Join(archive, "bundle.json")
	return info, nil
}

func prepareArchivePaths(ctx context.Context, db *sql.DB, paths store.Paths, run, stage, archive string) error {
	rows, err := db.QueryContext(ctx, "SELECT id FROM snapshots")
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		root := filepath.Join(paths.Snapshots, "imported", run, id)
		if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, "UPDATE snapshots SET path=? WHERE id=?", root, id); err != nil {
			return err
		}
	}
	for _, table := range []string{"snapshots", "provenance_objects"} {
		prefix := stage + string(filepath.Separator)
		prefixLen := utf8.RuneCountInString(prefix)
		if _, err := db.ExecContext(ctx, "UPDATE "+table+" SET path=? || substr(path,?) WHERE substr(path,1,?)=?",
			archive+string(filepath.Separator), prefixLen+1, prefixLen, prefix); err != nil {
			return err
		}
	}
	return nil
}

func readBoundedBundle(ctx context.Context, path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var input io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		input = gz
	}
	var b bytes.Buffer
	buf := make([]byte, 32<<10)
	remaining := limit + 1
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := input.Read(buf[:min(int64(len(buf)), remaining)])
		b.Write(buf[:n])
		remaining -= int64(n)
		if int64(b.Len()) > limit {
			return nil, fmt.Errorf("bundle exceeds decoded byte limit %d", limit)
		}
		if err == io.EOF {
			return b.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("bundle exceeds decoded byte limit %d", limit)
}

func bundleComponent(value string) bool {
	return value != "" && len(value) <= 512 && value != "." && value != ".." &&
		!strings.ContainsAny(value, "/\\\x00") && filepath.Base(value) == value
}

func validateStrictBundle(ctx context.Context, raw []byte, run string) error {
	var bundle map[string]json.RawMessage
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return err
	}
	var actualRun, schema string
	if json.Unmarshal(bundle["run_id"], &actualRun) != nil || actualRun != run ||
		json.Unmarshal(bundle["schema_version"], &schema) != nil || schema != "agentprovenance.forensics_bundle/v1" {
		return fmt.Errorf("bundle identity or schema mismatch")
	}
	snapshots := map[string]bool{}
	objects := map[string]int64{}
	blobs := map[string]bool{}
	for _, key := range append(append([]string{}, importTableOrder...), "telemetry_batch_records", "object_blobs", "snapshot_files", "omitted_content") {
		value, ok := bundle[key]
		if !ok || bytes.Equal(value, []byte("null")) {
			continue
		}
		var rows []map[string]json.RawMessage
		if err := json.Unmarshal(value, &rows); err != nil {
			return fmt.Errorf("invalid bundle table %s: %w", key, err)
		}
		seen := map[string][]byte{}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(row) == 0 {
				return fmt.Errorf("empty row in bundle table %s", key)
			}
			if value, ok := row["run_id"]; ok && key != "snapshots" {
				var rowRun string
				if json.Unmarshal(value, &rowRun) != nil || rowRun != run {
					return fmt.Errorf("bundle table %s has foreign run", key)
				}
			}
			if key == "snapshots" || key == "snapshot_files" {
				idKey := "id"
				if key == "snapshot_files" {
					idKey = "snapshot_id"
				}
				var id string
				if json.Unmarshal(row[idKey], &id) != nil || !bundleComponent(id) {
					return fmt.Errorf("invalid snapshot identity")
				}
			}
			idKey := "id"
			if key == "provenance_objects" || key == "object_blobs" {
				idKey = "hash"
			}
			if key == "snapshot_files" {
				var snapshot string
				_ = json.Unmarshal(row["snapshot_id"], &snapshot)
				if !snapshots[snapshot] {
					return fmt.Errorf("snapshot content has no snapshot record")
				}
				var name string
				if json.Unmarshal(row["name"], &name) != nil {
					return fmt.Errorf("invalid snapshot filename")
				}
				clean, err := cleanBundleRelPath(name)
				if err != nil {
					return err
				}
				rowID, _ := json.Marshal(snapshot + "/" + clean)
				row["_strict_key"] = rowID
				idKey = "_strict_key"
			}
			if key == "omitted_content" {
				continue
			}
			var id string
			if json.Unmarshal(row[idKey], &id) != nil || strings.TrimSpace(id) == "" {
				return fmt.Errorf("invalid row identity in bundle table %s", key)
			}
			canonical, _ := json.Marshal(row)
			if previous, ok := seen[id]; ok && !bytes.Equal(previous, canonical) {
				return fmt.Errorf("%w: duplicate row in %s", ErrBundleConflict, key)
			}
			seen[id] = canonical
			switch key {
			case "snapshots":
				snapshots[id] = true
			case "provenance_objects":
				var size int64
				if json.Unmarshal(row["size_bytes"], &size) != nil || size < 0 {
					return fmt.Errorf("invalid object size")
				}
				objects[id] = size
			case "object_blobs", "snapshot_files":
				var encoded string
				if json.Unmarshal(row["content_b64"], &encoded) != nil || bytes.Equal(row["content_b64"], []byte("null")) {
					return fmt.Errorf("missing embedded content in %s", key)
				}
				content, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					return fmt.Errorf("invalid embedded content: %w", err)
				}
				if key == "object_blobs" {
					size, exists := objects[id]
					if !exists || int64(len(content)) != size {
						return fmt.Errorf("object content metadata mismatch")
					}
					blobs[id] = true
				}
			}
		}
	}
	for id := range objects {
		if !blobs[id] {
			return fmt.Errorf("required object content is missing")
		}
	}
	return nil
}

func publishBundleArchive(ctx context.Context, stage, archive string, raw []byte) error {
	// The private staging directory contains only generated database/content
	// files. Sync files and directories before the atomic directory rename.
	var directories []string
	err := filepath.WalkDir(stage, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		return syncArchivePath(path)
	})
	if err != nil {
		return err
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if err := syncArchivePath(directories[i]); err != nil {
			return err
		}
	}
	if err := os.Rename(stage, archive); err != nil {
		// Another reception of identical bytes may already have published it.
		existing, readErr := os.ReadFile(filepath.Join(archive, "bundle.json"))
		if readErr != nil || !bytes.Equal(existing, raw) {
			return err
		}
		if err := compareImportedContent(ctx, archive, stage, true); err != nil {
			return err
		}
		if err := compareImportedContent(ctx, stage, archive, true); err != nil {
			return err
		}
	}
	return syncArchivePath(filepath.Dir(archive))
}

func syncArchivePath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func copyStrictRows(ctx context.Context, tx *sql.Tx, source *sql.DB, table, archive string) error {
	ident, err := quoteIdent(table)
	if err != nil {
		return err
	}
	rows, err := source.QueryContext(ctx, "SELECT * FROM "+ident)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	quoted := make([]string, len(columns))
	for i, column := range columns {
		quoted[i], err = quoteIdent(column)
		if err != nil {
			return err
		}
	}
	for rows.Next() {
		values, targets := make([]any, len(columns)), make([]any, len(columns))
		for i := range targets {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			return err
		}
		var conditions []string
		var compared []any
		pathIndex := -1
		for i, column := range columns {
			if column == "path" && (table == "snapshots" || table == "provenance_objects") {
				original, ok := values[i].(string)
				if !ok {
					return fmt.Errorf("invalid content path")
				}
				rel, err := filepath.Rel(archive, original)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return fmt.Errorf("bundle content was not embedded: %s", table)
				}
				pathIndex = i
				continue
			}
			conditions = append(conditions, quoted[i]+" IS ?")
			compared = append(compared, values[i])
		}
		var existing any
		selection := "1"
		if pathIndex >= 0 {
			selection = "path"
		}
		err := tx.QueryRowContext(ctx, "SELECT "+selection+" FROM "+ident+" WHERE "+strings.Join(conditions, " AND ")+" LIMIT 1", compared...).Scan(&existing)
		if err == nil {
			if pathIndex >= 0 {
				if err := compareImportedContent(ctx, existing.(string), values[pathIndex].(string), table == "snapshots"); err != nil {
					return err
				}
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		query := "INSERT INTO " + ident + " (" + strings.Join(quoted, ",") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(values)), ",") + ")"
		if _, err := tx.ExecContext(ctx, query, values...); err != nil {
			var coded interface{ Code() int }
			if errors.As(err, &coded) && (coded.Code() == 1555 || coded.Code() == 2067) {
				return fmt.Errorf("%w: %s", ErrBundleConflict, table)
			}
			return err
		}
	}
	return rows.Err()
}

func compareImportedContent(ctx context.Context, existing, incoming string, directory bool) error {
	compare := func(old, next string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, err := fileDigest(ctx, old)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return fmt.Errorf("%w: existing content unavailable", ErrBundleConflict)
		}
		b, err := fileDigest(ctx, next)
		if err != nil {
			return err
		}
		if a != b {
			return fmt.Errorf("%w: content bytes differ", ErrBundleConflict)
		}
		return nil
	}
	if !directory {
		return compare(existing, incoming)
	}
	return filepath.WalkDir(incoming, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(incoming, path)
		if err != nil {
			return err
		}
		return compare(filepath.Join(existing, rel), path)
	})
}

func fileDigest(ctx context.Context, path string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	stat, err := os.Lstat(path)
	if err != nil {
		return sum, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > MaxStrictBundleBytes {
		return sum, fmt.Errorf("invalid archive content file")
	}
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	buffer := make([]byte, 32<<10)
	input := io.LimitReader(f, MaxStrictBundleBytes+1)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		n, err := input.Read(buffer)
		total += int64(n)
		if total > MaxStrictBundleBytes {
			return sum, fmt.Errorf("archive file exceeds byte limit")
		}
		h.Write(buffer[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return sum, err
		}
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
