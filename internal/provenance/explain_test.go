package provenance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestExplainFileJSONManifest(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	workdir := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "app.py"), []byte("value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:   "run-explain-json",
		Name:    "explain-json",
		Workdir: workdir,
		Command: []string{"sh", "-lc", "printf 'value = 2\\n' > app.py"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Explain(db, ExplainOptions{RunID: "run-explain-json", File: "app.py", WithJSON: true}, &out); err != nil {
		t.Fatal(err)
	}
	var manifest ExplainManifest
	if err := json.Unmarshal(out.Bytes(), &manifest); err != nil {
		t.Fatalf("invalid explain json: %v\n%s", err, out.String())
	}
	if manifest.SchemaVersion != "agentprovenance.explain/v1" {
		t.Fatalf("schema_version = %q", manifest.SchemaVersion)
	}
	if manifest.Target.Type != "file" || manifest.Target.Run != "run-explain-json" || manifest.Target.File != "app.py" {
		t.Fatalf("unexpected target: %+v", manifest.Target)
	}
	if manifest.FileDiff == nil || manifest.FileDiff.SchemaVersion != "agentprovenance.diff/v1" {
		t.Fatalf("missing diff manifest: %+v", manifest.FileDiff)
	}
	if manifest.FileBlame == nil || manifest.FileBlame.SchemaVersion != "agentprovenance.blame/v1" {
		t.Fatalf("missing blame manifest: %+v", manifest.FileBlame)
	}
	if len(manifest.RuntimeEvents) == 0 || manifest.RuntimeEvents[0].ToolCallID != result.ToolCallID || manifest.RuntimeEvents[0].ProcessID != result.ProcessID {
		t.Fatalf("runtime events not correlated to record context: %+v", manifest.RuntimeEvents)
	}
	edgeTypes := map[string]bool{}
	for _, edge := range manifest.RuntimeEdges {
		edgeTypes[edge.EdgeType] = true
	}
	for _, want := range []string{"runtime_event_file", "runtime_process_file", "runtime_tool_call_file", "runtime_attempt_file"} {
		if !edgeTypes[want] {
			t.Fatalf("missing runtime edge %s in %+v", want, manifest.RuntimeEdges)
		}
	}
}

func TestPhase1JSONSchemaVersions(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	workdir := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "app.py"), []byte("value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:   "run-schema",
		Name:    "schema",
		Workdir: workdir,
		Command: []string{"sh", "-lc", "printf 'value = 2\\n' > app.py"},
	}); err != nil {
		t.Fatal(err)
	}

	replay, err := BuildReplayRun(db, "run-schema")
	if err != nil {
		t.Fatal(err)
	}
	verify, err := Verify(db, "run-schema")
	if err != nil {
		t.Fatal(err)
	}
	trajectories, err := BuildTrajectoriesRun(db, "run-schema")
	if err != nil {
		t.Fatal(err)
	}
	diff, err := BuildDiffFile(db, "run-schema", "app.py")
	if err != nil {
		t.Fatal(err)
	}
	blame, err := BuildBlameFile(db, "run-schema", "app.py")
	if err != nil {
		t.Fatal(err)
	}
	explain, err := BuildExplain(db, ExplainOptions{RunID: "run-schema", File: "app.py"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{
		"replay":       replay.SchemaVersion,
		"verify":       verify.SchemaVersion,
		"trajectories": trajectories.SchemaVersion,
		"diff":         diff.SchemaVersion,
		"blame":        blame.SchemaVersion,
		"explain":      explain.SchemaVersion,
	}
	want := map[string]string{
		"replay":       "agentprovenance.replay/v1",
		"verify":       "agentprovenance.verify/v1",
		"trajectories": "agentprovenance.trajectories/v1",
		"diff":         "agentprovenance.diff/v1",
		"blame":        "agentprovenance.blame/v1",
		"explain":      "agentprovenance.explain/v1",
	}
	for key, wantVersion := range want {
		if got[key] != wantVersion {
			t.Fatalf("%s schema = %q, want %q", key, got[key], wantVersion)
		}
	}
}
