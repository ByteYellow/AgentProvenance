//go:build agentprov_tools

package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/producer"
	"github.com/byteyellow/agentprovenance/internal/producer/k8sinformer"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func runSandboxWatch(c *cobra.Command, dataDir *string, opts watchOptions) error {
	if opts.nodeName == "" {
		opts.nodeName = strings.TrimSpace(os.Getenv("NODE_NAME"))
	}
	if opts.nodeName == "" {
		opts.nodeName, _ = os.Hostname()
	}
	if opts.nodeName == "" {
		return commandErrorf("--node or NODE_NAME is required")
	}
	cfg, err := kubeConfig(opts.master, opts.kubeconfig)
	if err != nil {
		return commandErrorf("k8s client config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return commandErrorf("k8s client: %w", err)
	}
	paths, err := store.Init(*dataDir)
	if err != nil {
		return err
	}
	db, err := store.Open(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	reconciler := &k8sinformer.ScopeReconciler{
		Resolver: newProcScopeResolver(), Sink: localK8sScopeSink{db: db},
		RunAnnotation: opts.runAnnotation, RunPrefix: opts.runPrefix,
	}
	controller, err := k8sinformer.New(client, k8sinformer.Options{
		Namespace: opts.namespace, NodeName: opts.nodeName, LabelSelector: opts.selector, Resync: opts.resync,
		Workers: opts.workers, MaxRetries: opts.maxRetries, Reconciler: reconciler,
		OnError: func(key string, err error) {
			fmt.Fprintf(c.ErrOrStderr(), commandText(c, "informer: key=%s error=%v\n"), key, err)
		},
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if opts.runFor > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.runFor)
		defer cancel()
	}
	if !opts.jsonOut {
		fmt.Fprintf(c.OutOrStdout(), commandText(c, "k8s informer starting node=%s namespace=%s scope_source=k8s_cgroup\n"), opts.nodeName, displayNamespace(opts.namespace))
	}
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	var ticker *time.Ticker
	if opts.reportInterval > 0 && !opts.jsonOut {
		ticker = time.NewTicker(opts.reportInterval)
		defer ticker.Stop()
	}
	for {
		select {
		case err := <-done:
			report := informerReport{Controller: controller.Report(), Attribution: reconciler.Report()}
			if opts.jsonOut {
				return writeJSON(c.OutOrStdout(), report)
			}
			printInformerReport(c, report)
			return err
		case <-tickerChan(ticker):
			printInformerReport(c, informerReport{Controller: controller.Report(), Attribution: reconciler.Report()})
		}
	}
}

type procScopeResolver struct {
	root         string
	mu           sync.Mutex
	byContainer  map[string]string
	lastRefresh  time.Time
	refreshEvery time.Duration
}

func newProcScopeResolver() *procScopeResolver {
	return &procScopeResolver{
		root: "/sys/fs/cgroup", byContainer: map[string]string{}, refreshEvery: time.Second,
	}
}

func (r *procScopeResolver) Resolve(_ context.Context, pod *corev1.Pod, status corev1.ContainerStatus) (string, int64, error) {
	cgroupID, err := r.resolveContainer(status.ContainerID)
	if err != nil {
		// An exited container's directory and /proc entry may already be gone.
		// Its runtime container ID remains a usable, explicit join key for events
		// already captured by the sensor. Never invent a cgroup or reuse a PID.
		if status.State.Terminated != nil && normalizeRuntimeContainerID(status.ContainerID) != "" {
			return "", 0, nil
		}
		return "", 0, err
	}
	pid, err := findPodPID(string(pod.UID), status.ContainerID)
	if err != nil {
		// The kernel cgroup identity is sufficient even if the process exited
		// between the cgroup scan and the /proc scan.
		return cgroupID, 0, nil
	}
	return cgroupID, int64(pid), nil
}

func (r *procScopeResolver) resolveContainer(containerID string) (string, error) {
	containerID = normalizeRuntimeContainerID(containerID)
	if containerID == "" {
		return "", commandErrorf("empty container id")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cgroupID := r.byContainer[containerID]; cgroupID != "" {
		return cgroupID, nil
	}
	if r.lastRefresh.IsZero() || time.Since(r.lastRefresh) >= r.refreshEvery {
		r.refreshLocked()
	}
	if cgroupID := r.byContainer[containerID]; cgroupID != "" {
		return cgroupID, nil
	}
	return "", commandErrorf("container %s has no host cgroup", containerID)
}

func (r *procScopeResolver) refreshLocked() {
	next := map[string]string{}
	_ = filepath.WalkDir(r.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return nil
		}
		scope, ok := producer.ParseCgroupScope(path)
		if !ok || scope.ContainerID == "" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			next[scope.ContainerID] = fmt.Sprintf("%d", stat.Ino)
		}
		return nil
	})
	r.byContainer = next
	r.lastRefresh = time.Now()
}

func normalizeRuntimeContainerID(value string) string {
	if i := strings.LastIndex(value, "://"); i >= 0 {
		return value[i+3:]
	}
	return strings.TrimSpace(value)
}

type localK8sScopeSink struct{ db *sql.DB }

func (s localK8sScopeSink) Bind(ctx context.Context, scope k8sinformer.ContainerScope) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// The same final snapshot may be replayed after a database outage or an
	// informer restart. One runtime container attempt has one durable identity;
	// binding and metadata commit together, without half-written retry records.
	digest := sha256.Sum256([]byte(scope.PodUID + "\x00" + scope.ContainerName + "\x00" + scope.ContainerID))
	id := fmt.Sprintf("bind_k8s_%x", digest)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// Older informers assigned random binding IDs. Adopt the existing runtime
	// attempt during upgrade so deletion still closes that original binding,
	// and historical evidence keeps its original binding reference. Adoption
	// must be inside the first write statement: a separate SELECT establishes
	// a WAL snapshot which cannot upgrade while the sensor commits a batch,
	// producing SQLITE_BUSY despite busy_timeout. INSERT reserves the writer
	// before evaluating its subquery and waits for concurrent capture writers.
	err = tx.QueryRowContext(ctx, `INSERT INTO execution_context_bindings
		(id, run_id, session_id, container_id, cgroup_id, pid, started_at, ended_at, binding_source, confidence, created_at)
		VALUES (COALESCE((SELECT id FROM execution_context_bindings
			WHERE run_id = ? AND session_id = ? AND container_id = ? AND binding_source = ?
			ORDER BY (ended_at = '') DESC, created_at ASC, id ASC LIMIT 1), ?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET ended_at = CASE WHEN excluded.ended_at <> '' THEN excluded.ended_at ELSE execution_context_bindings.ended_at END
		RETURNING id`,
		scope.RunID, scope.SessionID, scope.ContainerID, correlation.BindingSourceK8sCgroup,
		id, scope.RunID, scope.SessionID, scope.ContainerID, scope.CgroupID, scope.PID,
		scope.StartedAt, scope.EndedAt, correlation.BindingSourceK8sCgroup,
		correlation.DefaultBindingConfidence(correlation.BindingSourceK8sCgroup), scope.ObservedAt).Scan(&id)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"pod_name": scope.PodName, "namespace": scope.Namespace, "pod_uid": scope.PodUID, "cgroup_id": scope.CgroupID,
		"cluster": "", "node": scope.NodeName, "container": scope.ContainerName, "image": scope.Image,
		"service_account": scope.ServiceAccount, "labels": labelsText(scope.Labels), "pod_ip": scope.PodIP,
	})
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, '', '', 'k8s', 'pod_metadata', ?, ?) ON CONFLICT(id) DO NOTHING`,
		fmt.Sprintf("evt_k8s_%x", digest), scope.RunID, scope.PodUID, string(payload), scope.ObservedAt)
	if err != nil {
		return "", err
	}
	if err := saveK8sAccessDeclarations(ctx, tx, scope); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func (s localK8sScopeSink) Close(ctx context.Context, bindingID, endedAt string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return correlation.CloseBindingByID(s.db, bindingID, endedAt)
}

type informerReport struct {
	SchemaVersion string                       `json:"schema_version"`
	Controller    k8sinformer.Report           `json:"controller"`
	Attribution   k8sinformer.ReconcilerReport `json:"attribution"`
}

func printInformerReport(c *cobra.Command, report informerReport) {
	r := report.Controller
	a := report.Attribution
	fmt.Fprintf(c.OutOrStdout(), commandText(c, "k8s informer node=%s synced=%t enqueued=%d reconciled=%d retries=%d failed=%d bindings=%d active=%d closed=%d restarts=%d resolution_failures=%d attribution_p95_ms=%.1f\n"),
		r.NodeName, r.CacheSynced, r.Enqueued, r.Reconciled, r.Retried, r.Failed,
		a.BindingsCreated, a.ActiveBindings, a.BindingsClosed, a.ContainerRestarts, a.ResolutionFailures, a.AttributionLatencyP95MS)
}

func kubeConfig(master, kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" || master != "" {
		return clientcmd.BuildConfigFromFlags(master, kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
}

func labelsText(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}

func displayNamespace(namespace string) string {
	if namespace == "" {
		return "*"
	}
	return namespace
}

func tickerChan(ticker *time.Ticker) <-chan time.Time {
	if ticker == nil {
		return nil
	}
	return ticker.C
}

func writeJSON(out interface{ Write([]byte) (int, error) }, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
