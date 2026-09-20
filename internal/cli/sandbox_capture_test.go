package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/producer/k8sinformer"
	"github.com/byteyellow/agentprovenance/internal/store"
	corev1 "k8s.io/api/core/v1"
)

func TestInformerSinkCommitsAtomicallyAndReplaysWithoutDuplicates(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sink := localK8sScopeSink{db: db}
	started := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	scope := k8sinformer.ContainerScope{
		RunID: "late-run", SessionID: "pod-uid", PodUID: "pod-uid", ContainerName: "worker", ContainerID: "short-attempt",
		StartedAt: started.Format(time.RFC3339Nano), ObservedAt: started.Add(2 * time.Second).Format(time.RFC3339Nano),
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_pod_metadata BEFORE INSERT ON events WHEN NEW.event_type = 'pod_metadata'
		BEGIN SELECT RAISE(ABORT, 'temporary metadata failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Bind(context.Background(), scope); err == nil {
		t.Fatal("expected metadata insert failure")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM execution_context_bindings`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed metadata left a half-written binding: count=%d error=%v", count, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_pod_metadata`); err != nil {
		t.Fatal(err)
	}
	id, err := sink.Bind(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	finished := started.Add(500 * time.Millisecond).Format(time.RFC3339Nano)
	if err := sink.Close(context.Background(), id, finished); err != nil {
		t.Fatal(err)
	}
	// Replaying a stale running snapshot must not reopen the closed scope.
	for i := 0; i < 3; i++ {
		if replayID, err := sink.Bind(context.Background(), scope); err != nil || replayID != id {
			t.Fatalf("replay ID=%s expected=%s error=%v", replayID, id, err)
		}
	}
	for _, table := range []string{"execution_context_bindings", "events"} {
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s after retries: count=%d error=%v", table, count, err)
		}
	}
	binding, found, err := correlation.GetBinding(db, id)
	if err != nil || !found || binding.EndedAt != finished {
		t.Fatalf("replayed binding reopened: %+v found=%t error=%v", binding, found, err)
	}
	match, found, err := correlation.Resolve(db, correlation.RawIdentity{
		ContainerID: scope.ContainerID, Timestamp: started.Add(50 * time.Millisecond).Format(time.RFC3339Nano),
	})
	if err != nil || !found || match.RunID != scope.RunID {
		t.Fatalf("late event could not join recovered container identity: %+v found=%t error=%v", match, found, err)
	}
}

func TestInformerSinkAdoptsLegacyBindingOnUpgrade(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	started := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	legacyID, err := correlation.RecordBinding(db, correlation.Binding{
		ID: "bind_legacy_random", RunID: "existing-run", SessionID: "existing-pod", ContainerID: "existing-container",
		CgroupID: "12345", StartedAt: started, BindingSource: correlation.BindingSourceK8sCgroup,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := localK8sScopeSink{db: db}
	adopted, err := sink.Bind(context.Background(), k8sinformer.ContainerScope{
		RunID: "existing-run", SessionID: "existing-pod", PodUID: "existing-pod", ContainerName: "worker",
		ContainerID: "existing-container", CgroupID: "12345", StartedAt: started, ObservedAt: started,
	})
	if err != nil || adopted != legacyID {
		t.Fatalf("legacy binding was not adopted: got=%s want=%s error=%v", adopted, legacyID, err)
	}
	finished := time.Date(2026, 9, 19, 0, 1, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if err := sink.Close(context.Background(), adopted, finished); err != nil {
		t.Fatal(err)
	}
	bindings, err := correlation.ListBindings(db, correlation.BindingFilter{RunID: "existing-run"})
	if err != nil || len(bindings) != 1 || bindings[0].ID != legacyID || bindings[0].EndedAt != finished || bindings[0].StartedAt != started {
		t.Fatalf("upgrade left an orphan or changed historical identity: %+v error=%v", bindings, err)
	}
}

func TestInformerSinkWaitsForConcurrentCaptureWriter(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	watchDB, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer watchDB.Close()
	captureDB, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer captureDB.Close()
	// Hold a write reservation on an independent connection, as the node's
	// sensor does while inserting its batch. A deferred read-then-write Bind
	// fails immediately with SQLITE_BUSY instead of observing busy_timeout.
	writer, err := captureDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err := writer.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES ('capture-event', 'run', '', '', '', 'agentprov_ebpf', 'execve', '{}', '2026-09-19T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := (localK8sScopeSink{db: watchDB}).Bind(context.Background(), k8sinformer.ContainerScope{
			RunID: "run", SessionID: "pod", PodUID: "pod", ContainerName: "worker", ContainerID: "container",
			StartedAt: "2026-09-19T00:00:00Z", ObservedAt: "2026-09-19T00:00:01Z",
		})
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("binding did not wait for the capture writer: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("binding failed after capture transaction committed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("binding did not resume after capture writer committed")
	}
}

func TestHostCgroupPathCannotEscapeRoot(t *testing.T) {
	tests := map[string]string{
		"/kubepods.slice/pod-a":        "/sys/fs/cgroup/kubepods.slice/pod-a",
		"../../kubepods.slice/pod-b":   "/sys/fs/cgroup/kubepods.slice/pod-b",
		"../../../sys/fs/cgroup/pod-c": "/sys/fs/cgroup/sys/fs/cgroup/pod-c",
	}
	for input, want := range tests {
		if got := hostCgroupPath(input); got != want {
			t.Errorf("hostCgroupPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestProcScopeResolverRetainsTerminatedContainerIdentity(t *testing.T) {
	r := &procScopeResolver{root: t.TempDir(), byContainer: map[string]string{}}
	status := corev1.ContainerStatus{ContainerID: "containerd://departed", State: corev1.ContainerState{
		Terminated: &corev1.ContainerStateTerminated{},
	}}
	cgroup, pid, err := r.Resolve(context.Background(), &corev1.Pod{}, status)
	if err != nil || cgroup != "" || pid != 0 {
		t.Fatalf("departed identity: cgroup=%q pid=%d err=%v", cgroup, pid, err)
	}
	status.State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	if _, _, err := r.Resolve(context.Background(), &corev1.Pod{}, status); err == nil {
		t.Fatal("a running container without its cgroup must remain retryable")
	}
}

func TestProcScopeResolverIndexesContainerCgroups(t *testing.T) {
	const containerID = "1975174628cc0b9585d08bae7dfc65d661e8d307fa01f9d905685139cc0135ab"
	root := t.TempDir()
	dir := filepath.Join(root, "kubepods.slice", "cri-containerd-"+containerID+".scope")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t")
	}
	r := &procScopeResolver{root: root, byContainer: map[string]string{}, refreshEvery: time.Second}
	got, err := r.resolveContainer("containerd://" + containerID)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%d", stat.Ino); got != want {
		t.Fatalf("cgroup id = %q, want %q", got, want)
	}
}
