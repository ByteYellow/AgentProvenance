package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
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
