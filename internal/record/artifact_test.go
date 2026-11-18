//go:build linux || darwin

package record

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/redact"
	"github.com/byteyellow/agentprovenance/internal/store"
	"golang.org/x/sys/unix"
)

func artifactTestService(t *testing.T) Service {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return Service{DB: db, Paths: paths, Options: Options{AllowShell: true, AllowAnyWorkdir: true}}
}

func readCapturedText(t *testing.T, s Service, run, ref string) string {
	t.Helper()
	var body strings.Builder
	for offset := int64(0); ; {
		page, err := provenance.ReadTextContentPage(s.DB, run, ref, offset, 65536)
		if err != nil {
			t.Fatal(err)
		}
		body.WriteString(page.Content)
		if !page.HasMore {
			break
		}
		if page.NextOffset <= offset {
			t.Fatal("content page did not advance")
		}
		offset = page.NextOffset
	}
	return body.String()
}

func TestRecordStartFailureDoesNotClaimEmptyFileCapture(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled=%t", disabled), func(t *testing.T) {
			s := artifactTestService(t)
			workdir := t.TempDir()
			result, err := s.Run(Request{RunID: "not-started", Workdir: workdir, DisableSnapshot: disabled,
				Command: []string{filepath.Join(workdir, "missing-executable")}})
			if err != nil || result.ExitCode != 125 || result.Status != "failed" {
				t.Fatalf("start failure: %+v %v", result, err)
			}
			report := result.ArtifactCapture
			wantStatus := "failed"
			if disabled {
				wantStatus = "disabled"
			}
			if report.Status != wantStatus || report.Candidates != nil || report.Ref == "" || report.Stored != 0 {
				t.Fatalf("start failure hidden as empty/successful capture: %+v", report)
			}
			var saved ArtifactCaptureReport
			if err := provenance.ReadObjectPayload(s.DB, result.RunID, report.Ref, &saved); err != nil || saved.Status != wantStatus || saved.Candidates != nil {
				t.Fatalf("failure report not preserved: %+v %v", saved, err)
			}
		})
	}
}

func TestRecordedFileHistorySurvivesWorkspaceReuse(t *testing.T) {
	s := artifactTestService(t)
	work := t.TempDir()
	for _, label := range []string{"A", "B"} {
		if _, err := s.Run(Request{RunID: label, Workdir: work, PostRootGraceMS: 1,
			Command: []string{"sh", "-c", "echo report: " + label + " > result.txt"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, moved := range []bool{false, true} {
		if moved {
			if err := os.Rename(work, filepath.Join(t.TempDir(), "moved")); err != nil {
				t.Fatal(err)
			}
		}
		diff, err := provenance.BuildDiffFile(s.DB, "A", "result.txt")
		if err != nil || len(diff.Attempts) != 1 || strings.Join(diff.Attempts[0].UnifiedDiff, "\n") != "+report: A" {
			t.Fatalf("historical diff (moved=%t): %+v, %v", moved, diff, err)
		}
		blame, err := provenance.BuildBlameFile(s.DB, "A", "result.txt")
		if err != nil || len(blame.Entries) != 1 || blame.Entries[0].SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("report: A\n"))) {
			t.Fatalf("historical blame: %+v, %v", blame, err)
		}
		tr, err := provenance.BuildTrajectoriesRun(s.DB, "A")
		if err != nil || len(tr.Trajectories) != 1 || len(tr.Trajectories[0].FileChanges) != 1 || strings.Join(tr.Trajectories[0].FileChanges[0].UnifiedDiff, "\n") != "+report: A" {
			t.Fatalf("historical trajectory: %+v, %v", tr, err)
		}
	}
}

func TestSnapshotDeletionIsNotAMissingWrite(t *testing.T) {
	s := artifactTestService(t)
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "result.txt"), []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := s.Run(Request{RunID: "deleted", Workdir: work, Command: []string{"rm", "result.txt"}, PostRootGraceMS: 1})
	if err != nil {
		t.Fatal(err)
	}
	r := result.ArtifactCapture
	if r.Status != "ok" || r.Omitted != 0 || len(r.Files) != 1 || r.Files[0].ContentState != "deleted" {
		t.Fatalf("snapshot removal misreported: %+v", r)
	}
	var kind string
	if err := s.DB.QueryRow("SELECT event_type FROM events WHERE run_id=? AND source='record_file_diff'", result.RunID).Scan(&kind); err != nil || kind != "file_snapshot_removed" {
		t.Fatalf("snapshot event: %q, %v", kind, err)
	}
}

func TestRecordCapturesFullTextAndOmissionsOffline(t *testing.T) {
	s := artifactTestService(t)
	workspace := t.TempDir()
	body := strings.Repeat("recorded line\n", 700000) + "\ntoken=abcdef\nCAPTURED-END"
	want, _ := redact.Redact(body)
	source := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(source, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "deleted.txt"), []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := s.Run(Request{RunID: "capture", Workdir: workspace, PostRootGraceMS: 10,
		Command: []string{"sh", "-c", `cp "$1" large.txt; : > empty.txt; printf '\000\001binary' > binary.bin; rm deleted.txt`, "capture", source}})
	if err != nil {
		t.Fatal(err)
	}
	report := result.ArtifactCapture
	if report.Status != "partial" || report.Candidates == nil || *report.Candidates != 4 || report.Stored != 2 || report.Omitted != 1 || report.Deleted != 1 || report.Failed != 0 || report.Ref == "" {
		t.Fatalf("capture report: %+v", report)
	}
	items := map[string]CapturedArtifact{}
	for _, item := range report.Files {
		items[item.Path] = item
	}
	if items["binary.bin"].ContentState != "binary_omitted" || items["deleted.txt"].ContentState != "deleted" || items["empty.txt"].ContentBytes == nil || *items["empty.txt"].ContentBytes != 0 {
		t.Fatalf("missing/binary/empty conflated: %+v", items)
	}
	large := items["large.txt"]
	if !large.Redacted || large.ContentBytes == nil || *large.ContentBytes != int64(len(want)) || *large.ContentBytes <= 8<<20 || large.SourceBytes == nil || *large.SourceBytes != int64(len(body)) {
		t.Fatalf("large file metadata: %+v", large)
	}
	sum := sha256.Sum256([]byte(want))
	if large.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("wrong saved body hash")
	}
	if got := readCapturedText(t, s, "capture", large.ContentRef); got != want {
		t.Fatal("capture lost body/tail or failed to redact")
	}
	if err := os.WriteFile(filepath.Join(workspace, "large.txt"), []byte("MUTATED-AFTER-CAPTURE"), 0600); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: s.DB, Paths: s.Paths, SignKey: key}).ExportBundle("capture")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	fresh := artifactTestService(t)
	info, err := (forensics.Service{DB: fresh.DB, Paths: fresh.Paths}).ImportBundle(bundle.Path)
	if err != nil || info.Omitted != 0 {
		t.Fatalf("offline import: %+v %v", info, err)
	}
	if err := os.Rename(s.Paths.Provenance, s.Paths.Provenance+"-offline"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(workspace, workspace+"-offline"); err != nil {
		t.Fatal(err)
	}
	if got := readCapturedText(t, fresh, "capture", large.ContentRef); got != want {
		t.Fatal("offline content fell back to current source or lost its tail")
	}
	for _, tc := range []struct{ path, change, state, patch string }{
		{"large.txt", "created", "stored", "size_limit"},
		{"empty.txt", "created", "stored", ""},
		{"binary.bin", "created", "binary_omitted", ""},
		{"deleted.txt", "deleted", "deleted", "base_unavailable"},
		{".git/config", "unknown", "excluded", ""},
	} {
		d, err := provenance.BuildDiffFile(fresh.DB, "capture", tc.path)
		if err != nil || len(d.Attempts) != 1 || d.Attempts[0].ChangeType != tc.change ||
			d.Attempts[0].ContentState != tc.state || d.Attempts[0].PatchState != tc.patch {
			t.Errorf("imported file history for %s: %+v, %v", tc.path, d, err)
		}
	}
	var savedReport ArtifactCaptureReport
	if err := provenance.ReadObjectPayload(fresh.DB, "capture", report.Ref, &savedReport); err != nil {
		t.Fatal(err)
	}
	if savedReport.Status != report.Status || savedReport.StoredBytes != int64(len(want)) || len(savedReport.Files) != 4 {
		t.Fatalf("offline coverage changed: %+v", savedReport)
	}
	verified, err := provenance.Verify(fresh.DB, "capture")
	if err != nil || verified.ErrorCount != 0 {
		t.Fatalf("offline verify: %+v %v", verified, err)
	}
}

func TestArtifactCaptureLimitsAndSafeOpen(t *testing.T) {
	s := artifactTestService(t)
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "small.txt"), []byte("token=abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("OUTSIDE-NOT-CAPTURED"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(workspace, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(workspace, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(workspace, "oversized")
	f, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(provenance.MaxTextContentBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, tc := range []struct {
		path   string
		budget int64
		code   string
	}{
		{"small.txt", 0, "run_content_limit"},
		{"small.txt", 4, "file_content_limit"},
		{"small.txt", 12, "redacted_content_limit"},
		{"oversized", maxCapturedTextBytes, "file_content_limit"},
		{"missing", 100, "source_missing"},
		{"link", 100, "source_unreadable"},
		{"dirlink/outside.txt", 100, "source_unreadable"},
		{outside, 100, "source_unreadable"},
		{"../outside.txt", 100, "source_unreadable"},
		{"pipe", 100, "unsupported_file_type"},
	} {
		t.Run(tc.path+fmt.Sprint(tc.budget), func(t *testing.T) {
			item, err := s.captureArtifact("limits", "", workspace, tc.path, "", tc.budget)
			if err != nil || item.ReasonCode != tc.code || item.ContentRef != "" || item.ContentBytes != nil || item.Ref == "" {
				t.Fatalf("item=%+v err=%v", item, err)
			}
		})
	}
	var chunks int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE object_type IN ('text_chunk','text_content')`).Scan(&chunks); err != nil || chunks != 0 {
		t.Fatalf("omissions saved body chunks: %d %v", chunks, err)
	}
}

func TestArtifactWriteRollbackAndCaptureCountLimit(t *testing.T) {
	s := artifactTestService(t)
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "body.txt"), []byte(strings.Repeat("safe\n", 40000)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_artifact BEFORE INSERT ON provenance_objects WHEN NEW.object_type='artifact' BEGIN SELECT RAISE(ABORT,'test storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	report := s.captureArtifacts("failed", "", workspace, []string{"body.txt"}, nil)
	if report.Status != "failed" || report.Failed != 1 || report.Files[0].ContentRef != "" {
		t.Fatalf("failed storage claimed content: %+v", report)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial descriptors committed: %d %v", count, err)
	}
	if _, err := s.DB.Exec(`DROP TRIGGER fail_artifact`); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, maxCapturedFiles+1)
	for i := range paths {
		paths[i] = fmt.Sprintf("missing-%d", i)
	}
	report = s.captureArtifacts("count-limit", "", workspace, paths, nil)
	if report.Status != "partial" || report.Candidates == nil || *report.Candidates != len(paths) || len(report.Files) != maxCapturedFiles || report.Omitted != len(paths) || report.ReadBytes != 0 {
		t.Fatalf("capture count is not bounded: %+v", report)
	}
}

func TestArtifactCaptureDisabledAndEmptyAreDifferent(t *testing.T) {
	s := artifactTestService(t)
	for _, disabled := range []bool{true, false} {
		result, err := s.Run(Request{RunID: fmt.Sprintf("mode-%v", disabled), Workdir: t.TempDir(), Command: []string{"true"}, DisableSnapshot: disabled, PostRootGraceMS: 10})
		if err != nil {
			t.Fatal(err)
		}
		got := result.ArtifactCapture
		if disabled && (got.Status != "disabled" || got.Candidates != nil) {
			t.Fatalf("disabled capture: %+v", got)
		}
		if !disabled && (got.Status != "empty" || got.Candidates == nil || *got.Candidates != 0) {
			t.Fatalf("empty capture: %+v", got)
		}
		if got.Ref == "" {
			t.Fatal("capture status was not saved")
		}
		d, err := provenance.BuildDiffFile(s.DB, result.RunID, "unseen.txt")
		if err != nil || len(d.Attempts) != 1 {
			t.Fatalf("history: %+v %v", d, err)
		}
		a := d.Attempts[0]
		if disabled && (a.Changed != nil || a.FileExists != nil || a.ContentState != "disabled") ||
			!disabled && (a.Changed == nil || *a.Changed || a.FileExists == nil || *a.FileExists) {
			t.Fatalf("disabled and observed absence conflated: %+v", a)
		}
	}
}
