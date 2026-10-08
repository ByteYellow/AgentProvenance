package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestContextSnapshotComparisonCLIIsLanguageIndependent(t *testing.T) {
	dir := t.TempDir()
	paths, err := store.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := agentcontext.Service{DB: db, Paths: paths}
	a, b := `{"model":"source-one"}`, `{"model":"source-two"}`
	_, err = svc.Save(context.Background(), "run", agentcontext.Source{Harness: "codex", SessionID: "s", ParserVersion: "test/v1", Binding: "explicit"}, []agentcontext.Record{
		{Key: "a", Sequence: 1, Kind: "configuration", Body: &a},
		{Key: "b", Sequence: 2, Kind: "configuration", Body: &b},
	}, agentcontext.Coverage{Status: agentcontext.OK})
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.Entries(context.Background(), agentcontext.PageOptions{RunID: "run"})
	if err != nil || len(p.Entries) != 2 {
		t.Fatalf("entries: %+v %v", p, err)
	}
	var previous agentcontext.SnapshotComparison
	for _, lang := range []string{"en", "zh-CN"} {
		root := NewRootCommand()
		var out, stderr bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&stderr)
		root.SetArgs([]string{"--data-dir", dir, "--lang", lang, "context", "compare", "--run", "run", "--left", p.Entries[0].ID, "--right", p.Entries[1].ID})
		if err := root.Execute(); err != nil {
			t.Fatalf("compare: %v %s", err, stderr.String())
		}
		var got agentcontext.SnapshotComparison
		if json.Unmarshal(out.Bytes(), &got) != nil || got.Status != "different" || len(got.Changes) != 1 {
			t.Fatalf("machine output: %s", out.String())
		}
		if lang == "zh-CN" && !reflect.DeepEqual(previous, got) {
			t.Fatal("localization changed evidence or result codes")
		}
		previous = got
	}
}

func runContextCLI(t *testing.T, dir string, args ...string) ([]byte, error) {
	t.Helper()
	root := NewRootCommand()
	var out, stderr bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"--data-dir", dir, "context"}, args...))
	err := root.Execute()
	return out.Bytes(), err
}

func TestContextImportExitStatusRetainsCoverageJSON(t *testing.T) {
	const session = `{"type":"session_meta","payload":{"id":"s"}}` + "\n"
	for _, tc := range []struct {
		name, transcript string
		status           agentcontext.Status
		fail             bool
	}{
		{"ok", session, agentcontext.OK, false},
		{"empty", "", agentcontext.Empty, false},
		{"missing", "", agentcontext.NoInput, true},
		{"broken", "{broken}\n", agentcontext.Failed, true},
		{"partial", session + "{broken}\n", agentcontext.Partial, true},
		{"ambiguous", `{"type":"session_meta","payload":{"id":"different"}}` + "\n", agentcontext.Ambiguous, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(t.TempDir(), "transcript.jsonl")
			if tc.name != "missing" {
				if err := os.WriteFile(path, []byte(tc.transcript), 0600); err != nil {
					t.Fatal(err)
				}
			}
			out, err := runContextCLI(t, dir, "import", "--run", "run", "--harness", "codex", "--file", path, "--session", "s")
			if (err != nil) != tc.fail {
				t.Fatalf("exit status: error=%v want failure=%v", err, tc.fail)
			}
			var result agentcontext.SaveResult
			if err := json.Unmarshal(out, &result); err != nil || result.Coverage.Status != tc.status {
				t.Fatalf("one machine-readable result required: %s, %v", out, err)
			}
			coverage, err := runContextCLI(t, dir, "coverage", "--run", "run")
			var saved agentcontext.Overview
			if err != nil || json.Unmarshal(coverage, &saved) != nil || len(saved.Coverage) != 1 || saved.Coverage[0].ID != result.Coverage.ID {
				t.Fatalf("diagnostic was not retained: %s, %v", coverage, err)
			}
			if tc.name == "ok" {
				repeat, err := runContextCLI(t, dir, "import", "--run", "run", "--harness", "codex", "--file", path, "--session", "s")
				if err != nil || json.Unmarshal(repeat, &result) != nil || result.Stored != 0 || result.Duplicates != 1 {
					t.Fatalf("idempotent import is not a failure: %s, %v", repeat, err)
				}
			}
		})
	}
}

func TestContextCLIFiltersAndRecordedLinks(t *testing.T) {
	dir := t.TempDir()
	paths, err := store.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := agentcontext.Service{DB: db, Paths: paths}
	body := "source text"
	_, err = svc.Save(context.Background(), "run", agentcontext.Source{Harness: "codex", SessionID: "s", ParserVersion: "test/v1", Binding: "explicit"}, []agentcontext.Record{
		{Key: "a", Sequence: 1, Kind: "message", Body: &body},
		{Key: "b", Sequence: 2, Kind: "configuration", Body: &body},
	}, agentcontext.Coverage{Status: agentcontext.OK})
	if err != nil {
		t.Fatal(err)
	}
	all, err := svc.Entries(context.Background(), agentcontext.PageOptions{RunID: "run"})
	if err != nil || len(all.Entries) != 2 {
		t.Fatalf("saved entries: %+v, %v", all, err)
	}
	for _, tc := range []struct {
		args []string
		id   string
	}{
		{[]string{"--entry", all.Entries[0].ID}, all.Entries[0].ID},
		{[]string{"--node", all.Entries[1].ObjectHash}, all.Entries[1].ID},
		{[]string{"--group", "configuration"}, all.Entries[1].ID},
		{[]string{"--group", "conversation"}, all.Entries[0].ID},
	} {
		out, err := runContextCLI(t, dir, append([]string{"list", "--run", "run"}, tc.args...)...)
		var page agentcontext.Page
		if err != nil || json.Unmarshal(out, &page) != nil || len(page.Entries) != 1 || page.Entries[0].ID != tc.id {
			t.Fatalf("%v: %s, %v", tc.args, out, err)
		}
	}
	for _, args := range [][]string{
		{"list", "--limit", "0"}, {"list", "--limit", "-1"}, {"list", "--limit", "201"},
		{"list", "--group", "unknown"}, {"links"}, {"links", "--entry", "missing"},
		{"content", "--ref", all.Entries[0].Content.Ref, "--limit", "0"},
		{"content", "--ref", all.Entries[0].Content.Ref, "--offset", "-1"},
	} {
		if _, err := runContextCLI(t, dir, append(args, "--run", "run")...); err == nil {
			t.Fatalf("invalid query succeeded: %v", args)
		}
	}
	out, err := runContextCLI(t, dir, "links", "--run", "run", "--entry", all.Entries[0].ID)
	var links agentcontext.EntryLinks
	if err != nil || json.Unmarshal(out, &links) != nil || links.Reason != "no_recorded_graph_link" || len(links.Links) != 0 {
		t.Fatalf("missing link was guessed: %s, %v", out, err)
	}
	helper, err := runContextCLI(t, dir, "import", "--help")
	if err != nil || !strings.Contains(string(helper), "prior context") || strings.Contains(string(helper), "exclude physical") {
		t.Fatalf("resume help is stale: %s, %v", helper, err)
	}
}
