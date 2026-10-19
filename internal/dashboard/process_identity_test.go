package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestProcessFocusRetainsLifetimeInLiveAndReplay(t *testing.T) {
	db := newDashboardTestDB(t)
	db.SetMaxOpenConns(1)
	s := Server{DB: db}
	const boot = "01234567-89ab-cdef-0123-456789abcdef"
	want := map[string][]string{}
	for i, tc := range []struct {
		birth int
		host  string
	}{{100, ""}, {200, ""}, {100, ""}, {100, "host-a"}, {100, "host-b"}, {100, "host-a"}} {
		instance := fmt.Sprintf("%s:42:%d", boot, tc.birth)
		payload, _ := json.Marshal(map[string]any{"host_id": tc.host, "process_instance_id": instance, "argv": []string{"true"}})
		id, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{RunID: "run-lifecycle", Source: "agentprov_ebpf", EventType: "execve", PID: 42, Payload: string(payload), Timestamp: fmt.Sprintf("2026-10-17T00:00:0%dZ", i)})
		if err != nil {
			t.Fatal(err)
		}
		node := "runtime_process/instance/" + instance
		if tc.host != "" {
			node = fmt.Sprintf("runtime_process/host/%x/instance/%s", sha256.Sum256([]byte(tc.host)), instance)
		}
		want[node] = append(want[node], id)
	}
	// An imported legacy PID node in the same run must not select the new
	// lifetimes that happen to carry its numeric PID.
	if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,pid,payload,created_at)
		VALUES ('legacy','run-lifecycle','test','execve',42,'{"argv":["old"]}','2026-10-17T00:00:03Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,source_event_id,created_at)
		VALUES ('legacy-edge','run-lifecycle','runtime_process/pid/42','runtime_event/legacy','runtime_process_event','legacy','2026-10-17T00:00:03Z')`); err != nil {
		t.Fatal(err)
	}
	want["runtime_process/pid/42"] = []string{"legacy"}
	for node, ids := range want {
		request := httptest.NewRequest("GET", "/api/events?focus="+url.QueryEscape(node), nil)
		q, err := s.eventQueryFromRequest("run-lifecycle", request)
		if err != nil {
			t.Fatal(err)
		}
		for offset := range ids {
			page, count, err := s.queryEventsPage("run-lifecycle", q, 1, offset)
			if err != nil || count != len(ids) || len(page) != 1 || page[0].ID != ids[offset] {
				t.Fatalf("focus page %+v count=%d err=%v", page, count, err)
			}
		}
		other, count, err := s.queryEventsPage("another-run", q, 10, 0)
		if err != nil || count != 0 || len(other) != 0 {
			t.Fatalf("cross-run focus leak: %+v %v", other, err)
		}
	}
	replay, err := s.ExportReplay(context.Background(), "run-lifecycle", &staticdata.Writer{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for node, ids := range want {
		got := replay.EventRefs[node]
		if len(got) != len(ids) {
			t.Fatalf("replay refs %s: %v want %v", node, got, ids)
		}
		set := map[string]bool{}
		for _, id := range got {
			set[id] = true
		}
		for _, id := range ids {
			if !set[id] {
				t.Fatalf("missing replay event %s", id)
			}
		}
	}
	refs, err := s.resolveEventRefs("run-lifecycle", []string{"runtime_process/instance/" + boot + ":42:200"})
	if err != nil || !reflect.DeepEqual(refs, want["runtime_process/instance/"+boot+":42:200"]) {
		t.Fatalf("refs %v %v", refs, err)
	}
}
