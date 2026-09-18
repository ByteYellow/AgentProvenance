package k8sinformer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type ContainerScope struct {
	RunID          string
	SessionID      string
	PodName        string
	Namespace      string
	PodUID         string
	NodeName       string
	ContainerName  string
	ContainerID    string
	Image          string
	ServiceAccount string
	Labels         map[string]string
	PodIP          string
	CgroupID       string
	PID            int64
	StartedAt      string
	EndedAt        string
	ObservedAt     string
}

type ScopeResolver interface {
	Resolve(context.Context, *corev1.Pod, corev1.ContainerStatus) (string, int64, error)
}

type ScopeSink interface {
	Bind(context.Context, ContainerScope) (string, error)
	Close(context.Context, string, string) error
}

type ReconcilerReport struct {
	SchemaVersion           string  `json:"schema_version"`
	PodReconciles           int64   `json:"pod_reconciles"`
	ContainersObserved      int64   `json:"containers_observed"`
	BindingsCreated         int64   `json:"bindings_created"`
	BindingsClosed          int64   `json:"bindings_closed"`
	ContainerRestarts       int64   `json:"container_restarts"`
	ResolutionFailures      int64   `json:"resolution_failures"`
	ActiveBindings          int     `json:"active_bindings"`
	AttributionLatencyP50MS float64 `json:"attribution_latency_p50_ms"`
	AttributionLatencyP95MS float64 `json:"attribution_latency_p95_ms"`
}

type bindingState struct {
	bindingID   string
	containerID string
	cgroupID    string
	closed      bool
}

type ScopeReconciler struct {
	Resolver      ScopeResolver
	Sink          ScopeSink
	RunAnnotation string
	RunPrefix     string
	Now           func() time.Time

	mu                 sync.Mutex
	bindings           map[string]bindingState
	podLocks           podLocks
	recovered          map[string]string // at most one historical ID per Pod/container name
	latency            []float64
	podReconciles      atomic.Int64
	containersObserved atomic.Int64
	bindingsCreated    atomic.Int64
	bindingsClosed     atomic.Int64
	containerRestarts  atomic.Int64
	resolutionFailures atomic.Int64
}

func (r *ScopeReconciler) Upsert(ctx context.Context, pod *corev1.Pod) error {
	if r.Resolver == nil || r.Sink == nil {
		return fmt.Errorf("k8s scope reconciler requires resolver and sink")
	}
	if pod == nil || pod.UID == "" || pod.Spec.NodeName == "" {
		return nil
	}
	if strings.EqualFold(pod.Annotations["agentprov.io/ignore"], "true") ||
		strings.EqualFold(pod.Labels["agentprov.io/ignore"], "true") {
		return nil
	}
	r.ensureDefaults()
	unlock := r.lockPod(string(pod.UID))
	defer unlock()
	r.podReconciles.Add(1)
	var errs []string
	statuses := append([]corev1.ContainerStatus(nil), pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
	type observation struct {
		status     corev1.ContainerStatus
		historical bool
	}
	observations := make([]observation, 0, 2*len(statuses))
	for _, status := range statuses {
		// A CrashLoopBackOff snapshot can be the first time we see an attempt.
		// Recover LastTerminationState even if the current state is Waiting or
		// already Running a different container. Keep it separate from current
		// state so repeating the snapshot never closes the live replacement.
		if last := status.LastTerminationState.Terminated; last != nil && normalizeContainerID(last.ContainerID) != "" &&
			!(status.State.Terminated != nil && normalizeContainerID(last.ContainerID) == normalizeContainerID(status.ContainerID)) {
			previous := status
			previous.ContainerID = last.ContainerID
			previous.State = corev1.ContainerState{Terminated: last}
			observations = append(observations, observation{status: previous, historical: true})
		}
		observations = append(observations, observation{status: status})
	}
	for _, observed := range observations {
		status := observed.status
		containerID := normalizeContainerID(status.ContainerID)
		if containerID == "" && status.State.Terminated != nil {
			containerID = normalizeContainerID(status.State.Terminated.ContainerID)
			status.ContainerID = containerID
		}
		if containerID == "" {
			continue
		}
		// A waiting container has no current execution interval to attribute.
		if status.State.Running == nil && status.State.Terminated == nil {
			continue
		}
		now := r.Now().UTC()
		startedAt, endedAt, err := containerWindow(status, now)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", status.Name, err))
			continue
		}
		r.containersObserved.Add(1)
		key := scopeKey(pod.UID, status.Name)
		r.mu.Lock()
		previous, exists := r.bindings[key]
		recovered := r.recovered[key]
		r.mu.Unlock()
		if exists && previous.containerID == containerID {
			if endedAt != "" && !previous.closed {
				if err := r.Sink.Close(ctx, previous.bindingID, endedAt); err != nil {
					errs = append(errs, fmt.Sprintf("close %s: %v", status.Name, err))
					continue
				}
				previous.closed = true
				r.mu.Lock()
				r.bindings[key] = previous
				r.mu.Unlock()
				r.bindingsClosed.Add(1)
			}
			if observed.historical {
				r.mu.Lock()
				r.recovered[key] = containerID
				r.mu.Unlock()
			}
			continue
		}
		if observed.historical && recovered == containerID {
			continue
		}

		cgroupID, pid, err := r.Resolver.Resolve(ctx, pod, status)
		if err != nil {
			r.resolutionFailures.Add(1)
			errs = append(errs, fmt.Sprintf("%s: %v", status.Name, err))
			continue
		}
		if !observed.historical && exists && !previous.closed {
			closedAt := now.Format(time.RFC3339Nano)
			if last := status.LastTerminationState.Terminated; last != nil &&
				normalizeContainerID(last.ContainerID) == previous.containerID && !last.FinishedAt.IsZero() {
				closedAt = containerFinishedAt(last.FinishedAt.Time)
			}
			if err := r.Sink.Close(ctx, previous.bindingID, closedAt); err != nil {
				errs = append(errs, fmt.Sprintf("close %s: %v", status.Name, err))
				continue
			}
			previous.closed = true
			r.mu.Lock()
			r.bindings[key] = previous
			r.mu.Unlock()
			r.bindingsClosed.Add(1)
		}
		bindingID, err := r.Sink.Bind(ctx, ContainerScope{
			RunID: r.runID(pod), SessionID: string(pod.UID), PodName: pod.Name,
			Namespace: pod.Namespace, PodUID: string(pod.UID), NodeName: pod.Spec.NodeName,
			ContainerName: status.Name, ContainerID: containerID, Image: status.Image,
			ServiceAccount: pod.Spec.ServiceAccountName, Labels: cloneLabels(pod.Labels),
			PodIP: pod.Status.PodIP, CgroupID: cgroupID, PID: pid,
			StartedAt: startedAt, EndedAt: endedAt, ObservedAt: now.Format(time.RFC3339Nano),
		})
		if err != nil {
			errs = append(errs, fmt.Sprintf("bind %s: %v", status.Name, err))
			continue
		}
		r.mu.Lock()
		if observed.historical {
			r.recovered[key] = containerID
		} else {
			r.bindings[key] = bindingState{bindingID: bindingID, containerID: containerID, cgroupID: cgroupID, closed: endedAt != ""}
		}
		latency := now.Sub(pod.CreationTimestamp.Time).Seconds() * 1000
		if latency >= 0 {
			// Keep a bounded recent sample for a controller that lives for months.
			if len(r.latency) == 4096 {
				copy(r.latency, r.latency[1:])
				r.latency = r.latency[:4095]
			}
			r.latency = append(r.latency, latency)
		}
		r.mu.Unlock()
		r.bindingsCreated.Add(1)
		if !observed.historical && exists {
			r.containerRestarts.Add(1)
		}
		if endedAt != "" {
			r.bindingsClosed.Add(1)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("pod %s/%s attribution: %s", pod.Namespace, pod.Name, strings.Join(errs, "; "))
	}
	return nil
}

// Preserve the runtime interval even when the first watch notification arrives
// after exit. Using informer receipt time would exclude all early evidence.
func containerWindow(status corev1.ContainerStatus, now time.Time) (string, string, error) {
	if terminated := status.State.Terminated; terminated != nil {
		if terminated.StartedAt.IsZero() || terminated.FinishedAt.IsZero() ||
			terminated.FinishedAt.Before(&terminated.StartedAt) {
			return "", "", fmt.Errorf("terminated container has no valid execution interval")
		}
		return terminated.StartedAt.UTC().Format(time.RFC3339Nano), containerFinishedAt(terminated.FinishedAt.Time), nil
	}
	if running := status.State.Running; running != nil && !running.StartedAt.IsZero() {
		return running.StartedAt.UTC().Format(time.RFC3339Nano), "", nil
	}
	return now.Format(time.RFC3339Nano), "", nil
}

func containerFinishedAt(finished time.Time) string {
	// Kubernetes metav1.Time serializes to whole seconds. Include the reported
	// finishing second, otherwise a subsecond job whose start and end serialize
	// identically would lose all evidence. This is a passive identity bound, not
	// a claim that the container ran until the end of that second.
	if finished.Nanosecond() == 0 {
		finished = finished.Add(time.Second - time.Nanosecond)
	}
	return finished.UTC().Format(time.RFC3339Nano)
}

func (r *ScopeReconciler) Delete(ctx context.Context, _ string, uid string) error {
	if uid == "" {
		return nil
	}
	r.ensureDefaults()
	unlock := r.lockPod(uid)
	defer unlock()
	now := r.Now().UTC().Format(time.RFC3339Nano)
	prefix := uid + "/"
	r.mu.Lock()
	closing := make(map[string]bindingState)
	for key, state := range r.bindings {
		if strings.HasPrefix(key, prefix) {
			closing[key] = state
		}
	}
	r.mu.Unlock()
	var errs []string
	for key, state := range closing {
		if !state.closed {
			if err := r.Sink.Close(ctx, state.bindingID, now); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", key, err))
				continue
			}
			r.bindingsClosed.Add(1)
		}
		r.mu.Lock()
		delete(r.bindings, key)
		r.mu.Unlock()
	}
	if len(errs) > 0 {
		return fmt.Errorf("close pod %s scopes: %s", uid, strings.Join(errs, "; "))
	}
	r.mu.Lock()
	for key := range r.recovered {
		if strings.HasPrefix(key, prefix) {
			delete(r.recovered, key)
		}
	}
	r.mu.Unlock()
	return nil
}

func (r *ScopeReconciler) Report() ReconcilerReport {
	r.mu.Lock()
	latency := append([]float64(nil), r.latency...)
	active := 0
	for _, state := range r.bindings {
		if !state.closed {
			active++
		}
	}
	r.mu.Unlock()
	sort.Float64s(latency)
	return ReconcilerReport{
		SchemaVersion: "agentprovenance.k8s_scope_reconciler/v1",
		PodReconciles: r.podReconciles.Load(), ContainersObserved: r.containersObserved.Load(),
		BindingsCreated: r.bindingsCreated.Load(), BindingsClosed: r.bindingsClosed.Load(),
		ContainerRestarts: r.containerRestarts.Load(), ResolutionFailures: r.resolutionFailures.Load(),
		ActiveBindings:          active,
		AttributionLatencyP50MS: percentile(latency, 0.50), AttributionLatencyP95MS: percentile(latency, 0.95),
	}
}

func (r *ScopeReconciler) ensureDefaults() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bindings == nil {
		r.bindings = map[string]bindingState{}
	}
	if r.recovered == nil {
		r.recovered = map[string]string{}
	}
	if r.RunAnnotation == "" {
		r.RunAnnotation = "agentprov.io/run"
	}
	if r.RunPrefix == "" {
		r.RunPrefix = "auto-"
	}
	if r.Now == nil {
		r.Now = time.Now
	}
}

func (r *ScopeReconciler) lockPod(uid string) func() {
	return r.podLocks.lock(uid)
}

func (r *ScopeReconciler) runID(pod *corev1.Pod) string {
	if run := strings.TrimSpace(pod.Annotations[r.RunAnnotation]); run != "" {
		return run
	}
	return r.RunPrefix + string(pod.UID)
}

func scopeKey(uid types.UID, container string) string { return string(uid) + "/" + container }

func normalizeContainerID(value string) string {
	if i := strings.LastIndex(value, "://"); i >= 0 {
		return value[i+3:]
	}
	return strings.TrimSpace(value)
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	i := int(float64(len(values)-1)*p + 0.5)
	if i < 0 {
		i = 0
	}
	if i >= len(values) {
		i = len(values) - 1
	}
	return values[i]
}
