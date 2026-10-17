package provenance

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

func transcriptIntentSource(timestamp, toolID, agentID, sessionID string) string {
	line, _ := json.Marshal(map[string]any{
		"type": "assistant", "timestamp": timestamp, "agentId": agentID, "sessionId": sessionID,
		"message": map[string]any{"role": "assistant", "model": "test-model", "content": []any{
			map[string]any{"type": "tool_use", "id": toolID, "name": "Bash", "input": map[string]any{"command": "cat /work/config"}},
		}},
	})
	return string(line)
}

func insertTranscriptIntentAnchor(t *testing.T, db *sql.DB, edgeID, anchor, start, command string) {
	t.Helper()
	intentTestEvent(t, db, "action", "execve", "2026-01-01T00:00:02Z", "cg-a", "cat /work/config")
	if _, err := db.Exec(`INSERT INTO tool_calls (id,run_id,agent_id,session_id,command,status,created_at,started_at,ended_at)
		VALUES ('tool-a','intent-test','alice','session-a',?,'completed',?,?, '2026-01-01T00:00:03Z')`, command, start, start); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,source_event_id,created_at)
		VALUES (?,'intent-test','tool-a','runtime_event/action','agent_syscall',?,'2026-01-01T00:00:02Z')`, edgeID, anchor); err != nil {
		t.Fatal(err)
	}
}

func TestTranscriptIntentRequiresSpecificToolAnchor(t *testing.T) {
	for _, tt := range []struct {
		name, at, toolID, agentID, sessionID, edgeID, anchor, toolStart, command string
		want                                                                     int
	}{
		{"matched", "2026-01-01T00:00:00Z", "tool-a", "alice", "session-a", correlation.AppProcessEdgePrefix + "anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config", 1},
		{"missing timestamp", "", "tool-a", "alice", "session-a", correlation.AppProcessEdgePrefix + "anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config", 0},
		{"earlier execution", "2026-01-01T00:00:03Z", "tool-a", "alice", "session-a", correlation.AppProcessEdgePrefix + "anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config", 0},
		{"missing tool id", "2026-01-01T00:00:00Z", "", "alice", "session-a", correlation.AppProcessEdgePrefix + "anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config", 0},
		{"other tool", "2026-01-01T00:00:00Z", "tool-b", "alice", "session-a", correlation.AppProcessEdgePrefix + "anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config", 0},
		{"other agent", "2026-01-01T00:00:00Z", "tool-a", "bob", "session-a", correlation.AppProcessEdgePrefix + "anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config", 0},
		{"other session", "2026-01-01T00:00:00Z", "tool-a", "alice", "session-b", correlation.AppProcessEdgePrefix + "anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config", 0},
		{"legacy inference", "2026-01-01T00:00:00Z", "tool-a", "alice", "session-a", "old-edge", "action", "2026-01-01T00:00:01Z", "cat /work/config", 0},
		{"inherited child", "2026-01-01T00:00:00Z", "tool-a", "alice", "session-a", correlation.AppProcessEdgePrefix + "anchor", "parent-exec", "2026-01-01T00:00:01Z", "cat /work/config", 0},
		{"tool already running", "2026-01-01T00:00:00Z", "tool-a", "alice", "session-a", correlation.AppProcessEdgePrefix + "anchor", "action", "2025-12-31T23:59:59Z", "cat /work/config", 0},
		{"tool command differs", "2026-01-01T00:00:00Z", "tool-a", "alice", "session-a", correlation.AppProcessEdgePrefix + "anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config --extra", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, db := intentTestStore(t)
			db.SetMaxOpenConns(1)
			insertTranscriptIntentAnchor(t, db, tt.edgeID, tt.anchor, tt.toolStart, tt.command)
			source := transcriptIntentSource(tt.at, tt.toolID, tt.agentID, tt.sessionID)
			n, err := HarvestTranscriptStreams(st, db, "intent-test", []TranscriptStream{{Reader: strings.NewReader(source)}})
			if err != nil || n != 1 {
				t.Fatalf("harvest=%d, %v", n, err)
			}
			if got := intentCausedCount(t, db); got != tt.want {
				t.Fatalf("edges=%d, want %d", got, tt.want)
			}
			var objects int
			if err := db.QueryRow(`SELECT count(*) FROM provenance_objects WHERE run_id='intent-test' AND object_type='llm_message'`).Scan(&objects); err != nil {
				t.Fatal(err)
			}
			if objects != 2 {
				t.Fatalf("unmatched turn lost its evidence: %d", objects)
			}
		})
	}
}

func TestTranscriptDuplicateDecisionsAcrossStreamsStayAmbiguous(t *testing.T) {
	st, db := intentTestStore(t)
	insertTranscriptIntentAnchor(t, db, correlation.AppProcessEdgePrefix+"anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config")
	source := transcriptIntentSource("2026-01-01T00:00:00Z", "tool-a", "alice", "session-a")
	n, err := HarvestTranscriptStreams(st, db, "intent-test", []TranscriptStream{
		{AgentID: "main", Reader: strings.NewReader(source)},
		{AgentID: "duplicate", Reader: strings.NewReader(source)},
	})
	if err != nil || n != 2 {
		t.Fatalf("harvest=%d, %v", n, err)
	}
	if got := intentCausedCount(t, db); got != 0 {
		t.Fatalf("ambiguous shared execution=%d", got)
	}
}

func TestTranscriptScopedToolMapDoesNotFallBackToNativeID(t *testing.T) {
	st, db := intentTestStore(t)
	insertTranscriptIntentAnchor(t, db, correlation.AppProcessEdgePrefix+"anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config")
	source := transcriptIntentSource("2026-01-01T00:00:00Z", "tool-a", "alice", "session-a")
	if _, err := HarvestTranscriptStreams(st, db, "intent-test", []TranscriptStream{{Reader: strings.NewReader(source), ToolNodes: map[string]string{}}}); err != nil {
		t.Fatal(err)
	}
	if n := intentCausedCount(t, db); n != 0 {
		t.Fatalf("missing scoped identity fell back to native ID: %d", n)
	}
}

func TestTranscriptReanalysisFailureKeepsLastGraph(t *testing.T) {
	st, db := intentTestStore(t)
	insertTranscriptIntentAnchor(t, db, correlation.AppProcessEdgePrefix+"anchor", "action", "2026-01-01T00:00:01Z", "cat /work/config")
	file := filepath.Join(t.TempDir(), "transcript.jsonl")
	mustWrite(t, file, transcriptIntentSource("2026-01-01T00:00:00Z", "tool-a", "alice", "session-a"))
	if _, err := HarvestTranscriptSet(st, db, "intent-test", file, nil); err != nil {
		t.Fatal(err)
	}
	before := intentDerivedSnapshot(t, db)
	if _, err := HarvestTranscriptSet(st, db, "intent-test", file+".missing", nil); err == nil {
		t.Fatal("expected source error")
	}
	if after := intentDerivedSnapshot(t, db); !reflect.DeepEqual(before, after) {
		t.Fatal("source error removed old graph")
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_llm BEFORE INSERT ON graph_edges WHEN NEW.edge_type='llm_caused' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := HarvestTranscriptSet(st, db, "intent-test", file, nil); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("failure=%v", err)
	}
	if after := intentDerivedSnapshot(t, db); !reflect.DeepEqual(before, after) {
		t.Fatal("write error removed old graph")
	}
	if _, err := db.Exec(`DROP TRIGGER fail_llm`); err != nil {
		t.Fatal(err)
	}
	if _, err := HarvestTranscriptSet(st, db, "intent-test", file, nil); err != nil {
		t.Fatal(err)
	}
	if got := intentCausedCount(t, db); got != 1 {
		t.Fatalf("retry=%d edges", got)
	}
}
