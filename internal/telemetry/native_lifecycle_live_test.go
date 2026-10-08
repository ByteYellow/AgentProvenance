package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

// Consume the fixture-only events emitted by accept_sensor_live.py. This gate
// checks the real captured lifetimes through the durable ingestion path.
func TestNativeLiveLifecycleAttribution(t *testing.T) {
	path := os.Getenv("AGENTPROV_LIVE_LIFECYCLE_EVENTS")
	if path == "" {
		t.Skip("set AGENTPROV_LIVE_LIFECYCLE_EVENTS to a live acceptance events file")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var lines [][]byte
	var root map[string]any
	var target map[string]any
	markers := map[string]bool{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
		command, _ := event["command"].(string)
		if event["event_type"] == "execve" && strings.Contains(command, "--worker") && strings.Contains(command, "python-openssl-ex") {
			root = event
		}
		if name, _ := event["path"].(string); name == "migration-after.env" || name == "clone-child.env" {
			markers[name] = true
			target = event
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if root == nil || target == nil || !markers["migration-after.env"] || !markers["clone-child.env"] {
		t.Fatal("live evidence must include worker exec, migration and clone3 fixtures")
	}
	group, _ := root["cgroup_id"].(string)
	targetGroup, _ := target["cgroup_id"].(string)
	if group == "" || targetGroup == "" || group == targetGroup {
		t.Fatal("fixture did not cross cgroups")
	}
	started, err := time.Parse(time.RFC3339Nano, root["timestamp"].(string))
	if err != nil {
		t.Fatal(err)
	}
	db, paths := nativeTestStore(t)
	_, err = correlation.RecordBinding(db, correlation.Binding{
		RunID: "run-live-lifecycle", SessionID: "session-live", ToolCallID: "tool-live", ProcessID: "process-live",
		CgroupID: group, StartedAt: started.Add(-time.Second).UTC().Format(time.RFC3339Nano),
		BindingSource: correlation.BindingSourceK8sCgroup,
	})
	if err != nil {
		t.Fatal(err)
	}
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, BatchEvents: 1})
	for _, line := range lines {
		if _, err := n.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	for name := range markers {
		var run, method, capturedGroup string
		err := db.QueryRow(`SELECT run_id,correlation_method,cgroup_id FROM events WHERE event_type='file_write' AND json_extract(payload,'$.raw.path')=?`, name).Scan(&run, &method, &capturedGroup)
		if err != nil || run != "run-live-lifecycle" || capturedGroup != targetGroup || !strings.HasPrefix(method, "kernel_process_instance:") {
			status, statusErr := ReadNativeStreamStatus(db)
			rejections, rejectionErr := ReadNativeRejections(paths.Logs)
			t.Logf("capture=%+v err=%v rejections=%+v err=%v", status, statusErr, rejections, rejectionErr)
			t.Fatalf("%s: run=%s method=%s group=%s err=%v", name, run, method, capturedGroup, err)
		}
	}
	var scopeClaims int
	if err := db.QueryRow(`SELECT COUNT(*) FROM execution_context_bindings WHERE cgroup_id=?`, targetGroup).Scan(&scopeClaims); err != nil || scopeClaims != 0 {
		t.Fatalf("child claimed migrated cgroup as a run scope: %d %v", scopeClaims, err)
	}
}
