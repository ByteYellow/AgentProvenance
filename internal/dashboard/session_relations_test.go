package dashboard

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func addSessionRelationsFixture(t *testing.T, svc agentcontext.Service) {
	t.Helper()
	message := `{"id":"worker","message":"Synthetic relationship fixture; no message was actually sent."}`
	fork := `{"id":"branch","forked_from_id":"worker"}`
	task := "Synthetic cross-run session records for navigation testing."
	for _, item := range []struct {
		id, parent string
		records    []agentcontext.Record
	}{
		{"root", "", []agentcontext.Record{{Key: "task", Kind: "message", Role: "user", Body: &task}, {Key: "send", Kind: "tool_call", ToolName: "functions.send_input", ToolCallID: "send-worker", Body: &message}}},
		{"remote-child", "worker", nil},
		{"branch", "", []agentcontext.Record{{Key: "metadata", Kind: "configuration", Status: "session_metadata", Body: &fork}}},
		{"orphan", "not-collected", nil},
	} {
		_, err := svc.Save(context.Background(), "ui-session-related", agentcontext.Source{Harness: "codex", SessionID: item.id, ParentSessionID: item.parent,
			Channel: "transcript", Binding: "explicit", ParserVersion: "synthetic-session-relations/v1"}, item.records, agentcontext.Coverage{Status: agentcontext.OK})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hooksbridge.IngestContext(context.Background(), svc.DB, svc.Paths, "ui-session-related"); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRelationsReplayVisibility(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := agentcontext.Service{DB: db, Paths: paths}
	addSessionGraphFixture(t, svc)
	addSessionRelationsFixture(t, svc)
	root := t.TempDir()
	server, writer := Server{DB: db}, &staticdata.Writer{Root: root}
	read := func(ref staticdata.Ref) agentcontext.SessionRelationsPage {
		t.Helper()
		file, err := os.Open(filepath.Join(root, ref.Path))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		gz, err := gzip.NewReader(file)
		if err != nil {
			t.Fatal(err)
		}
		defer gz.Close()
		var p agentcontext.SessionRelationsPage
		if err := json.NewDecoder(gz).Decode(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, visible := range [][]string{{"ui-session-graph"}, {"ui-session-graph", "ui-session-related"}} {
		replay, err := server.ExportReplaySet(context.Background(), "ui-session-graph", writer, visible)
		if err != nil {
			t.Fatal(err)
		}
		page := read(replay.Sessions[`["codex","worker"]`].Relations[""])
		foreign := 0
		for _, r := range page.Relations {
			if r.From.RunID == "ui-session-related" || r.To.RunID == "ui-session-related" {
				foreign++
			}
		}
		if len(visible) == 1 && foreign != 0 || len(visible) == 2 && foreign != 3 {
			t.Fatalf("exported catalog %v: foreign=%d %+v", visible, foreign, page)
		}
	}
}
