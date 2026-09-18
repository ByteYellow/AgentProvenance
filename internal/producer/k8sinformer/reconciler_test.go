package k8sinformer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type fakeResolver struct {
	mu      sync.Mutex
	results map[string]struct {
		cgroup string
		pid    int64
	}
}

func TestLastTerminationRecoveredWhileWaitingOrRunning(t *testing.T) {
	for _, running := range []bool{false, true} {
		t.Run(fmt.Sprintf("replacement_running_%t", running), func(t *testing.T) {
			pod := testPod("containerd://replacement")
			last := &corev1.ContainerStateTerminated{
				ContainerID: "containerd://missed-short-job", StartedAt: pod.CreationTimestamp,
				FinishedAt: metav1.NewTime(pod.CreationTimestamp.Add(100 * time.Millisecond)),
			}
			pod.Status.ContainerStatuses[0].LastTerminationState.Terminated = last
			if !running {
				pod.Status.ContainerStatuses[0].ContainerID = ""
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
			}
			sink := &fakeSink{}
			r := &ScopeReconciler{Sink: sink, Resolver: &fakeResolver{results: map[string]struct {
				cgroup string
				pid    int64
			}{"missed-short-job": {}, "replacement": {cgroup: "123"}}}}
			for i := 0; i < 10; i++ {
				if err := r.Upsert(context.Background(), pod); err != nil {
					t.Fatal(err)
				}
			}
			wantBound, wantActive := 1, 0
			if running {
				wantBound, wantActive = 2, 1
			}
			if len(sink.bound) != wantBound || len(sink.closed) != 0 || r.Report().ActiveBindings != wantActive {
				t.Fatalf("historical replay changed live replacement: bindings=%+v closed=%v report=%+v", sink.bound, sink.closed, r.Report())
			}
			if old := sink.bound[0]; old.ContainerID != "missed-short-job" || old.EndedAt != last.FinishedAt.Format(time.RFC3339Nano) {
				t.Fatalf("missed last execution: %+v", old)
			}
			if err := r.Delete(context.Background(), "default/demo", string(pod.UID)); err != nil {
				t.Fatal(err)
			}
			if len(r.recovered) != 0 || len(r.podLocks.entries) != 0 {
				t.Fatal("deleted Pod retained history or locks")
			}
		})
	}
}

func TestLastTerminationClosesObservedAttemptExactlyOnce(t *testing.T) {
	pod := testPod("containerd://old")
	sink := &fakeSink{}
	r := &ScopeReconciler{Sink: sink, Resolver: &fakeResolver{results: map[string]struct {
		cgroup string
		pid    int64
	}{"old": {cgroup: "1"}, "new": {cgroup: "2"}}}}
	if err := r.Upsert(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.ContainerStatuses[0].ContainerID = "containerd://new"
	pod.Status.ContainerStatuses[0].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{
		ContainerID: "containerd://old", StartedAt: pod.CreationTimestamp,
		FinishedAt: metav1.NewTime(pod.CreationTimestamp.Add(time.Second)),
	}
	for i := 0; i < 3; i++ {
		if err := r.Upsert(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.bound) != 2 || len(sink.closed) != 1 || r.Report().ActiveBindings != 1 {
		t.Fatalf("repeated last termination created duplicate scope: bound=%v closed=%v report=%+v", sink.bound, sink.closed, r.Report())
	}
}

func TestPodLocksSerializeWaitersAndReclaim(t *testing.T) {
	var locks podLocks
	var wg sync.WaitGroup
	var active, overlaps atomic.Int64
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				unlock := locks.lock("pod")
				if active.Add(1) != 1 {
					overlaps.Add(1)
				}
				active.Add(-1)
				unlock()
			}
		}()
	}
	wg.Wait()
	if overlaps.Load() != 0 || len(locks.entries) != 0 {
		t.Fatalf("overlapping holders=%d retained locks=%d", overlaps.Load(), len(locks.entries))
	}
}

func (r *fakeResolver) Resolve(_ context.Context, _ *corev1.Pod, status corev1.ContainerStatus) (string, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result, ok := r.results[normalizeContainerID(status.ContainerID)]
	if !ok {
		return "", 0, fmt.Errorf("container not visible in host cgroup")
	}
	return result.cgroup, result.pid, nil
}

type fakeSink struct {
	mu       sync.Mutex
	bound    []ContainerScope
	closed   []string
	closedAt []string
}

func (s *fakeSink) Bind(_ context.Context, scope ContainerScope) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bound = append(s.bound, scope)
	return fmt.Sprintf("binding-%d", len(s.bound)), nil
}

func (s *fakeSink) Close(_ context.Context, bindingID, endedAt string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = append(s.closed, bindingID)
	s.closedAt = append(s.closedAt, endedAt)
	return nil
}

func TestTerminatedContainerCanFirstAppearAfterExit(t *testing.T) {
	now := time.Date(2026, 9, 19, 0, 0, 20, 0, time.UTC)
	started := now.Add(-10 * time.Second)
	pod := testPod("containerd://short-job")
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
		ContainerID: "containerd://short-job", StartedAt: metav1.NewTime(started), FinishedAt: metav1.NewTime(started),
	}}
	resolver := &fakeResolver{results: map[string]struct {
		cgroup string
		pid    int64
	}{"short-job": {}}}
	sink := &fakeSink{}
	r := &ScopeReconciler{Resolver: resolver, Sink: sink, Now: func() time.Time { return now }}
	for i := 0; i < 2; i++ {
		if err := r.Upsert(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.bound) != 1 {
		t.Fatalf("late upserts produced %d bindings", len(sink.bound))
	}
	scope := sink.bound[0]
	if scope.StartedAt != started.Format(time.RFC3339Nano) || scope.EndedAt != started.Add(time.Second-time.Nanosecond).Format(time.RFC3339Nano) {
		t.Fatalf("lost the subsecond execution window: %+v", scope)
	}
	if scope.PID != 0 || scope.CgroupID != "" {
		t.Fatalf("invented vanished process identity: %+v", scope)
	}
	if report := r.Report(); report.ActiveBindings != 0 || report.BindingsClosed != 1 {
		t.Fatalf("report: %+v", report)
	}
	if err := r.Delete(context.Background(), "default/demo", string(pod.UID)); err != nil {
		t.Fatal(err)
	}
	if len(sink.closed) != 0 {
		t.Fatal("deletion overwrote the already closed execution window")
	}
}

func TestTerminationClosesExistingBindingAndIncludesInitContainers(t *testing.T) {
	finished := time.Date(2026, 9, 19, 0, 0, 5, 123, time.UTC)
	resolver := &fakeResolver{results: map[string]struct {
		cgroup string
		pid    int64
	}{
		"worker": {cgroup: "101", pid: 12}, "init": {cgroup: "102", pid: 0},
	}}
	sink := &fakeSink{}
	r := &ScopeReconciler{Resolver: resolver, Sink: sink}
	pod := testPod("containerd://worker")
	if err := r.Upsert(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
		StartedAt: metav1.NewTime(finished.Add(-time.Second)), FinishedAt: metav1.NewTime(finished),
	}}
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ContainerID: "containerd://init", State: pod.Status.ContainerStatuses[0].State}}
	if err := r.Upsert(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if len(sink.bound) != 2 || len(sink.closedAt) != 1 || sink.closedAt[0] != finished.Format(time.RFC3339Nano) {
		t.Fatalf("bindings=%+v closes=%+v", sink.bound, sink.closedAt)
	}
	if report := r.Report(); report.ActiveBindings != 0 || report.BindingsClosed != 2 {
		t.Fatalf("report: %+v", report)
	}
}

func TestScopeReconcilerContainerLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 5, 2, 0, 0, 0, time.UTC)
	resolver := &fakeResolver{results: map[string]struct {
		cgroup string
		pid    int64
	}{
		"container-a": {cgroup: "101", pid: 1001},
		"container-b": {cgroup: "202", pid: 2002},
	}}
	sink := &fakeSink{}
	r := &ScopeReconciler{Resolver: resolver, Sink: sink, Now: func() time.Time { return now }}
	pod := testPod("containerd://container-a")

	if err := r.Upsert(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if err := r.Upsert(context.Background(), pod.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if got := len(sink.bound); got != 1 {
		t.Fatalf("idempotent upsert created %d bindings, want 1", got)
	}
	if got := sink.bound[0]; got.RunID != "run-explicit" || got.ContainerID != "container-a" || got.CgroupID != "101" || got.PID != 1001 {
		t.Fatalf("first binding = %+v", got)
	}

	restarted := pod.DeepCopy()
	restarted.ResourceVersion = "2"
	restarted.Status.ContainerStatuses[0].ContainerID = "containerd://container-b"
	if err := r.Upsert(context.Background(), restarted); err != nil {
		t.Fatal(err)
	}
	if got := len(sink.bound); got != 2 {
		t.Fatalf("restart bindings = %d, want 2", got)
	}
	if len(sink.closed) != 1 || sink.closed[0] != "binding-1" {
		t.Fatalf("restart closed = %v, want [binding-1]", sink.closed)
	}

	if err := r.Delete(context.Background(), "default/demo", string(pod.UID)); err != nil {
		t.Fatal(err)
	}
	if len(sink.closed) != 2 || sink.closed[1] != "binding-2" {
		t.Fatalf("delete closed = %v, want binding-2 last", sink.closed)
	}
	report := r.Report()
	if report.BindingsCreated != 2 || report.BindingsClosed != 2 || report.ContainerRestarts != 1 || report.ActiveBindings != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestScopeReconcilerReportsResolutionFailure(t *testing.T) {
	r := &ScopeReconciler{
		Resolver: &fakeResolver{results: map[string]struct {
			cgroup string
			pid    int64
		}{}},
		Sink: &fakeSink{},
	}
	if err := r.Upsert(context.Background(), testPod("containerd://missing")); err == nil {
		t.Fatal("expected resolution failure")
	}
	if got := r.Report().ResolutionFailures; got != 1 {
		t.Fatalf("resolution_failures = %d, want 1", got)
	}
}

func testPod(containerID string) *corev1.Pod {
	created := time.Date(2026, 8, 5, 1, 59, 59, 0, time.UTC)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo", Namespace: "default", UID: types.UID("pod-uid"), ResourceVersion: "1",
			CreationTimestamp: metav1.NewTime(created),
			Annotations:       map[string]string{"agentprov.io/run": "run-explicit"},
			Labels:            map[string]string{"app": "demo"},
		},
		Spec: corev1.PodSpec{NodeName: "node-a", ServiceAccountName: "default"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "10.42.0.10",
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "worker", Image: "busybox", ContainerID: containerID,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(created)}},
			}},
		},
	}
}
