package agentcontext

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func deepseekHeader(version int, cwd string, at time.Time) string {
	header, _ := json.Marshal(map[string]any{"type": "session", "version": version, "id": "session", "cwd": cwd, "createdAt": at.UnixMilli()})
	return string(header) + "\n"
}

func TestDeepSeekDiscoverySelectsNewestGenerationWithoutFallback(t *testing.T) {
	for _, tc := range []struct {
		name, file, content string
		compressed          bool
		wantStatus          Status
	}{
		{"plain-v4", "session.v4.jsonl", "", false, OK},
		{"compressed-v4", "session.v4.jsonl.zstd", "", true, OK},
		{"unsupported", "session.v10.jsonl", `{"type":"session","version":10,"id":"session"}` + "\n", false, Failed},
		{"oversized-generation", "session.v99999999999999999999999.jsonl", `{"type":"session","version":99,"id":"session"}` + "\n", false, Failed},
		{"broken-latest", "session.v4.jsonl", "broken\n", false, Ambiguous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, now := t.TempDir(), time.Now().UTC()
			opts := DiscoverOptions{Harness: "deepseek", Root: root, Workdir: root}
			before := discoverTest(t, opts)
			old := filepath.Join(root, "session.v3.jsonl")
			writeSource(t, old, deepseekHeader(3, root, now))
			content := tc.content
			if content == "" {
				content = deepseekHeader(4, root, now)
			}
			data := []byte(content)
			if tc.compressed {
				writer, err := zstd.NewWriter(nil)
				if err != nil {
					t.Fatal(err)
				}
				data = writer.EncodeAll(data, nil)
				writer.Close()
			}
			latest := filepath.Join(root, tc.file)
			if err := os.WriteFile(latest, data, 0600); err != nil {
				t.Fatal(err)
			}
			after := discoverTest(t, opts)
			if len(after.Candidates) != 1 || after.Candidates[0].Path != latest {
				t.Fatalf("older generation selected: %+v", after)
			}
			selection := SelectSources(context.Background(), before, after, SelectOptions{SessionID: "session", StartedAt: now.Add(-time.Second), EndedAt: now.Add(time.Second)})
			if tc.wantStatus == Ambiguous {
				if selection.Status != Ambiguous || len(selection.Sources) != 0 {
					t.Fatalf("bad latest log fell back: %+v", selection)
				}
			} else {
				if selection.Status != OK || len(selection.Sources) != 1 {
					t.Fatalf("selection: %+v", selection)
				}
				result, err := testService(t).ImportFile(context.Background(), "run", selection.Sources[0].ParseOptions("deepseek"))
				if err != nil || result.Coverage.Status != tc.wantStatus {
					t.Fatalf("unsupported generation hidden: %+v %v", result, err)
				}
			}
			// An operator can still acquire the old file as historical evidence.
			explicit := discoverTest(t, DiscoverOptions{Harness: "deepseek", Root: old})
			if !explicit.Complete || len(explicit.Candidates) != 1 || explicit.Candidates[0].Path != old {
				t.Fatal("explicit old source blocked")
			}
		})
	}
}

func TestDeepSeekMigrationCannotReassignHistoryToCurrentRun(t *testing.T) {
	root, now := t.TempDir(), time.Now().UTC()
	opts := DiscoverOptions{Harness: "deepseek", Root: root, Workdir: root, Snapshot: true}
	writeSource(t, filepath.Join(root, "session.v3.jsonl"), deepseekHeader(3, root, now.Add(-time.Hour)))
	before := discoverTest(t, opts)
	writeSource(t, filepath.Join(root, "session.v4.jsonl"), deepseekHeader(4, root, now))
	selection := SelectSources(context.Background(), before, discoverTest(t, opts), SelectOptions{SessionID: "session", StartedAt: now, EndedAt: now.Add(time.Second)})
	if selection.Status != Ambiguous || len(selection.Sources) != 0 || len(selection.Issues) != 1 || selection.Issues[0].Code != "source_moved_before_resume" {
		t.Fatalf("migration invented execution boundary: %+v", selection)
	}
}

func TestDeepSeekSymlinkCannotSilentlySelectOlderGeneration(t *testing.T) {
	root, now := t.TempDir(), time.Now().UTC()
	opts := DiscoverOptions{Harness: "deepseek", Root: root, Workdir: root}
	before := discoverTest(t, opts)
	old := filepath.Join(root, "session.v3.jsonl")
	writeSource(t, old, deepseekHeader(3, root, now))
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing.jsonl"), filepath.Join(root, "session.v4.jsonl")); err != nil {
		t.Fatal(err)
	}
	after := discoverTest(t, opts)
	if after.Complete || !hasDiscoveryIssue(after, "source_not_regular") {
		t.Fatalf("unreadable generation hidden: %+v", after)
	}
	window := SelectOptions{SessionID: "session", StartedAt: now.Add(-time.Second), EndedAt: now.Add(time.Second)}
	if selection := SelectSources(context.Background(), before, after, window); selection.Status != Ambiguous || len(selection.Sources) != 0 {
		t.Fatalf("symlink caused silent downgrade: %+v", selection)
	}
	window.Path = old
	if selection := SelectSources(context.Background(), before, after, window); selection.Status != Partial || len(selection.Sources) != 1 || selection.Sources[0].Path != old {
		t.Fatalf("explicit historical acquisition blocked: %+v", selection)
	}
}

func TestDeepSeekGenerationDoesNotResolveSameGenerationConflicts(t *testing.T) {
	root, now := t.TempDir(), time.Now().UTC()
	opts := DiscoverOptions{Harness: "deepseek", Root: root}
	before := discoverTest(t, opts)
	for _, directory := range []string{"first", "second"} {
		for _, version := range []int{3, 4} {
			name := "session.v3.jsonl"
			if version == 4 {
				name = "session.v4.jsonl"
			}
			writeSource(t, filepath.Join(root, directory, name), deepseekHeader(version, root, now))
		}
	}
	after := discoverTest(t, opts)
	if len(after.Candidates) != 2 {
		t.Fatalf("separate directories collapsed: %+v", after)
	}
	selection := SelectSources(context.Background(), before, after, SelectOptions{SessionID: "session", StartedAt: now, EndedAt: now.Add(time.Second)})
	if selection.Status != Ambiguous || len(selection.Sources) != 0 {
		t.Fatalf("duplicate identity guessed: %+v", selection)
	}
	for _, name := range []string{"session.vX.jsonl", "session.v.jsonl", "session.v-1.jsonl", "session.v4.jsonl.backup"} {
		if _, valid := deepseekGeneration(name); valid {
			t.Fatalf("invalid generation accepted: %s", name)
		}
	}
	if !newerGeneration("10", "9") || newerGeneration("3", "10") || newerGeneration("4", "4") {
		t.Fatal("generation ordering is not numeric")
	}
	if generation, valid := deepseekGeneration("session.v0004.jsonl.zstd"); !valid || generation != "4" {
		t.Fatal("generation normalization failed")
	}
}
