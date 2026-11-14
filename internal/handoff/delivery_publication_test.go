//go:build linux || darwin

package handoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func publicationRoot(f deliveryFixture) string {
	return filepath.Join(f.sender.Paths.Artifacts, "execution-deliveries")
}

func copyPublication(t *testing.T, root string, d Delivery) string {
	t.Helper()
	dir, err := os.MkdirTemp(root, "package-")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bundle.json", "manifest.dsse.json"} {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(d.BundlePath), name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPublicationCleanupReferenceAndStorageBoundaries(t *testing.T) {
	f := testDelivery(t)
	d := f.prepare(t, "pending")
	receipt := f.receive(t, d)
	f.sender.ReceiverID = "another-receiver"
	other := f.prepare(t, "other-receiver")
	f.sender.ReceiverID = f.receiver.ID
	root := publicationRoot(f)
	orphan := copyPublication(t, root, d)
	work, err := os.MkdirTemp(root, ".prepare-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(work, "projection", "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "projection", "objects", "body"), []byte("staging"), 0o600); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(root, "operator-note")
	if err := os.WriteFile(unknown, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		result, err := f.sender.ReconcilePublications(context.Background(), 1)
		if err != nil || result.Removed != 1 || result.Busy || result.Failed != 0 || result.ReclaimedBytes <= 0 {
			t.Fatalf("bounded cleanup: %+v %v", result, err)
		}
	}
	for _, path := range []string{orphan, work} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("orphan remains: %s %v", path, err)
		}
	}
	for _, path := range []string{d.BundlePath, other.BundlePath, unknown} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("retained file removed: %s %v", path, err)
		}
	}
	if got, reused, err := f.sender.Prepare(context.Background(), f.principal, f.report.Attempt.ID, "pending"); err != nil || !reused || !bytes.Equal(got.Envelope, d.Envelope) {
		t.Fatalf("pending delivery changed: %v %t", err, reused)
	}
	if got, err := f.receiver.Receive(context.Background(), IdentityOf(f.report.Attempt), d.Envelope, strings.NewReader("")); err != nil || !bytes.Equal(got, receipt) {
		t.Fatalf("receiver archive changed: %v", err)
	}
	if result, err := f.sender.ReconcilePublications(context.Background(), 1); err != nil || result.Removed != 0 {
		t.Fatalf("repeat cleanup: %+v %v", result, err)
	}
}

func TestPublicationCleanupBusyCancellationAndInvalidEntries(t *testing.T) {
	f := testDelivery(t)
	d := f.prepare(t, "kept")
	root := publicationRoot(f)
	copyPublication(t, root, d)
	lease, err := acquirePublication(context.Background(), root, false)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := f.sender.ReconcilePublications(context.Background(), 1); err != nil || !result.Busy || result.Removed != 0 {
		t.Fatalf("active publication: %+v %v", result, err)
	}
	lease.Close()
	lease, err = acquirePublication(context.Background(), root, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	_, _, err = f.sender.Prepare(ctx, f.principal, f.report.Attempt.ID, "cancelled")
	cancel()
	lease.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting publication did not cancel: %v", err)
	}
	outside := t.TempDir()
	marker := filepath.Join(outside, "keep")
	if err := os.WriteFile(marker, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".prepare-link", "package-link"} {
		if err := os.Symlink(outside, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	bad := copyPublication(t, root, d)
	if err := os.WriteFile(filepath.Join(bad, "operator-note"), []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := f.sender.ReconcilePublications(context.Background(), 10)
	if err == nil || result.Failed != 3 || result.Removed != 1 {
		t.Fatalf("invalid entries hidden or starved valid cleanup: %+v %v", result, err)
	}
	for _, file := range []string{marker, filepath.Join(bad, "bundle.json"), d.BundlePath} {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("unexpected removal: %s %v", file, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.sender.ReconcilePublications(cancelled, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled cleanup: %v", err)
	}
}

func TestPublicationCleanupDatabaseFailurePreservesFiles(t *testing.T) {
	f := testDelivery(t)
	d := f.prepare(t, "kept")
	orphan := copyPublication(t, publicationRoot(f), d)
	if err := f.sender.Ledger.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := f.sender.ReconcilePublications(context.Background(), 10); err == nil || result.Removed != 0 {
		t.Fatalf("failed database treated as absence: %+v %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(orphan, "bundle.json")); err != nil {
		t.Fatal(err)
	}
}

type publicationHelperConfig struct {
	Root        string
	Target      Target
	Principal   Principal
	Attempt     string
	SignKey     ed25519.PrivateKey
	ReceiverID  string
	ReceiverKey ed25519.PublicKey
}

func TestPublicationProcessHelper(t *testing.T) {
	path := os.Getenv("AGENTPROV_PUBLICATION_HELPER")
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config publicationHelperConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	paths := store.ResolvePaths(config.Root)
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sender := DeliveryService{Ledger: Ledger{DB: db, Target: config.Target}, Paths: paths, SignKey: config.SignKey, ReceiverID: config.ReceiverID, ReceiverKey: config.ReceiverKey}
	if _, _, err := sender.Prepare(context.Background(), config.Principal, config.Attempt, "child"); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationConcurrentProcessCommitAndCrash(t *testing.T) {
	for _, mode := range []string{"commit", "crash"} {
		t.Run(mode, func(t *testing.T) {
			f := testDelivery(t)
			d := f.prepare(t, "kept")
			root := publicationRoot(f)
			cfg := publicationHelperConfig{f.sender.Paths.Root, f.sender.Ledger.Target, f.principal, f.report.Attempt.ID, f.sender.SignKey, f.sender.ReceiverID, f.sender.ReceiverKey}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "helper.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			// Hold the database writer after the original attempt is complete.
			// The child can freeze/read it, but cannot register its published files.
			tx, err := f.sender.Ledger.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.Exec(`UPDATE schema_versions SET version=version WHERE 0`); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPublicationProcessHelper$", "-test.timeout=20s")
			cmd.Env = append(os.Environ(), "AGENTPROV_PUBLICATION_HELPER="+path)
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				packages, err := filepath.Glob(filepath.Join(root, "package-*"))
				if err != nil {
					t.Fatal(err)
				}
				if len(packages) == 2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("child did not reach publication window")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if result, err := f.sender.ReconcilePublications(context.Background(), 10); err != nil || !result.Busy || result.Removed != 0 {
				t.Fatalf("GC overlapped active child: %+v %v", result, err)
			}
			if mode == "crash" {
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			waited = true
			if (err != nil) != (mode == "crash") {
				t.Fatalf("child %s: %v %s", mode, err, output.String())
			}
			result, err := f.sender.ReconcilePublications(context.Background(), 10)
			wantRemoved, wantRows := 0, 2
			if mode == "crash" {
				wantRemoved, wantRows = 2, 1
			}
			if err != nil || result.Removed != wantRemoved || result.Busy || rowCount(t, f.sender.Ledger.DB, "execution_deliveries") != wantRows {
				t.Fatalf("post-child cleanup: %+v %v", result, err)
			}
			if _, err := os.Stat(d.BundlePath); err != nil {
				t.Fatal(err)
			}
			t.Logf("child=%s removed=%d registered=%d", mode, result.Removed, wantRows)
		})
	}
}
