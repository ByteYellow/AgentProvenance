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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

type recordingReconciler struct {
	mu      sync.Mutex
	upserts int
	deletes int
	fail    int
}

func (r *recordingReconciler) Upsert(_ context.Context, _ *corev1.Pod) error {
	r.mu.Lock()
	r.upserts++
	if r.fail > 0 {
		r.fail--
		r.mu.Unlock()
		return fmt.Errorf("transient binding database failure")
	}
	r.mu.Unlock()
	return nil
}

func TestDeletedRecoveryErrorRemainsRetryable(t *testing.T) {
	r := &recordingReconciler{fail: 1}
	c, err := New(fake.NewSimpleClientset(), Options{NodeName: "node-a", Reconciler: r})
	if err != nil {
		t.Fatal(err)
	}
	defer c.queue.ShutDown()
	pod := testPod("containerd://short")
	item := queueItem{Key: "default/demo", UID: string(pod.UID), Deleted: true, DeletedPod: pod}
	if err := c.reconcile(context.Background(), item); err == nil {
		t.Fatal("final snapshot recovery failure was forgotten")
	}
	if _, deletes := r.counts(); deletes != 1 || c.Report().Deleted != 0 {
		t.Fatal("known scopes must close without reporting the failed snapshot successful")
	}
	if err := c.reconcile(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if upserts, deletes := r.counts(); upserts != 2 || deletes != 2 || c.Report().Deleted != 1 {
		t.Fatalf("upserts=%d deletes=%d report=%+v", upserts, deletes, c.Report())
	}
}

func TestRetryWaitsForHostCgroupRefresh(t *testing.T) {
	r := &recordingReconciler{fail: 1}
	c, err := New(fake.NewSimpleClientset(), Options{NodeName: "node-a", Reconciler: r})
	if err != nil {
		t.Fatal(err)
	}
	defer c.queue.ShutDown()
	pod := testPod("containerd://new")
	if err := c.informer.GetIndexer().Add(pod); err != nil {
		t.Fatal(err)
	}
	c.enqueue(pod, false)
	started := time.Now()
	c.processNext(context.Background())
	c.processNext(context.Background())
	if elapsed := time.Since(started); elapsed < time.Second {
		t.Fatalf("retry ran before 1s cgroup snapshot refresh: %s", elapsed)
	}
	if got := c.Report(); got.Retried != 1 || got.Reconciled != 1 || got.Failed != 0 {
		t.Fatalf("retry report: %+v", got)
	}
}

func TestStalePodQueueItemCannotReconcileReusedName(t *testing.T) {
	r := &recordingReconciler{}
	c, err := New(fake.NewSimpleClientset(), Options{NodeName: "node-a", Reconciler: r})
	if err != nil {
		t.Fatal(err)
	}
	defer c.queue.ShutDown()
	pod := testPod("containerd://new")
	pod.UID = "new-uid"
	if err := c.informer.GetIndexer().Add(pod); err != nil {
		t.Fatal(err)
	}
	if err := c.reconcile(context.Background(), queueItem{Key: "default/demo", UID: "old-uid"}); err != nil {
		t.Fatal(err)
	}
	if upserts, _ := r.counts(); upserts != 0 {
		t.Fatal("stale work item reconciled a different Pod")
	}
}

type blockingReconciler struct {
	entered chan struct{}
	release chan struct{}
	next    chan struct{}
	calls   atomic.Int64
}

func (r *blockingReconciler) Upsert(context.Context, *corev1.Pod) error {
	if r.calls.Add(1) == 1 {
		close(r.entered)
		<-r.release
	} else {
		close(r.next)
	}
	return nil
}

func (*blockingReconciler) Delete(context.Context, string, string) error { return nil }

func TestDeleteCannotOvertakeInFlightUpsertOrReopenAfterDelete(t *testing.T) {
	r := &blockingReconciler{entered: make(chan struct{}), release: make(chan struct{}), next: make(chan struct{})}
	c, err := New(fake.NewSimpleClientset(), Options{NodeName: "node-a", Reconciler: r, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer c.queue.ShutDown()
	pod := testPod("containerd://short")
	if err := c.informer.GetIndexer().Add(pod); err != nil {
		t.Fatal(err)
	}
	upsert := queueItem{Key: "default/demo", UID: string(pod.UID)}
	done := make(chan error, 2)
	go func() { done <- c.reconcile(context.Background(), upsert) }()
	<-r.entered
	if err := c.informer.GetIndexer().Delete(pod); err != nil {
		close(r.release)
		t.Fatal(err)
	}
	deleteStarted := make(chan struct{})
	go func() {
		close(deleteStarted)
		done <- c.reconcile(context.Background(), queueItem{Key: upsert.Key, UID: upsert.UID, Deleted: true, DeletedPod: pod})
	}()
	<-deleteStarted
	select {
	case <-r.next:
		close(r.release)
		t.Fatal("deletion overtook the running reconciliation")
	case <-time.After(20 * time.Millisecond):
	}
	close(r.release)
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if err := c.reconcile(context.Background(), upsert); err != nil {
		t.Fatal(err)
	}
	if r.calls.Load() != 2 || len(c.podLocks.entries) != 0 {
		t.Fatalf("stale snapshot reopened deleted scope or retained lock: upserts=%d locks=%d", r.calls.Load(), len(c.podLocks.entries))
	}
}

func (r *recordingReconciler) Delete(_ context.Context, _, _ string) error {
	r.mu.Lock()
	r.deletes++
	r.mu.Unlock()
	return nil
}

func (r *recordingReconciler) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.upserts, r.deletes
}

func TestControllerListWatchAndDelete(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "demo", Namespace: "default", UID: types.UID("uid-1"), ResourceVersion: "1",
		Labels: map[string]string{"agentprov.io/managed": "true"},
	}, Spec: corev1.PodSpec{NodeName: "node-a"}}
	client := fake.NewSimpleClientset()
	fakeWatch := watch.NewRaceFreeFake()
	client.PrependReactor("list", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{Items: []corev1.Pod{*pod}}, nil
	})
	client.PrependWatchReactor("pods", func(action clienttesting.Action) (bool, watch.Interface, error) {
		return true, fakeWatch, nil
	})
	reconciler := &recordingReconciler{}
	controller, err := New(client, Options{
		NodeName: "node-a", LabelSelector: "agentprov.io/managed=true", Reconciler: reconciler, Resync: time.Hour,
		OnError: func(key string, err error) { t.Logf("controller error key=%s: %v", key, err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	waitFor(t, func() bool {
		upserts, _ := reconciler.counts()
		return upserts == 1
	})

	fakeWatch.Delete(pod.DeepCopy())
	waitFor(t, func() bool {
		_, deletes := reconciler.counts()
		return deletes == 1
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	listSelector, labelSelector := "", ""
	for _, action := range client.Actions() {
		if action.GetVerb() == "list" && action.GetResource().Resource == "pods" {
			listSelector = action.(clienttesting.ListAction).GetListRestrictions().Fields.String()
			labelSelector = action.(clienttesting.ListAction).GetListRestrictions().Labels.String()
		}
	}
	if listSelector != "spec.nodeName=node-a" {
		t.Fatalf("pod list field selector = %q, want spec.nodeName=node-a", listSelector)
	}
	if labelSelector != "agentprov.io/managed=true" {
		t.Fatalf("pod list label selector = %q", labelSelector)
	}
	report := controller.Report()
	if !report.CacheSynced || report.Reconciled != 1 || report.Deleted != 1 || report.Failed != 0 {
		t.Fatalf("controller report = %+v", report)
	}
}

func TestDeletedSnapshotRecoversAContainerMissingFromCache(t *testing.T) {
	pod := testPod("containerd://short-job")
	finished := pod.CreationTimestamp.Time.Add(time.Second)
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
		StartedAt: pod.CreationTimestamp, FinishedAt: metav1.NewTime(finished),
	}}
	sink := &fakeSink{}
	reconciler := &ScopeReconciler{Sink: sink, Resolver: &fakeResolver{results: map[string]struct {
		cgroup string
		pid    int64
	}{"short-job": {}}}}
	controller, err := New(fake.NewSimpleClientset(), Options{NodeName: "node-a", Reconciler: reconciler})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.queue.ShutDown()
	controller.enqueue(pod, true)
	if !controller.processNext(context.Background()) {
		t.Fatal("queue shut down unexpectedly")
	}
	if len(sink.bound) != 1 || sink.bound[0].EndedAt == "" {
		t.Fatalf("deleted short-lived container not recovered: %+v", sink.bound)
	}
	if report := reconciler.Report(); report.ActiveBindings != 0 || report.BindingsCreated != 1 || report.BindingsClosed != 1 {
		t.Fatalf("report: %+v", report)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for informer reconciliation")
}
