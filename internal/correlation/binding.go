package correlation

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

type Binding struct {
	ID            string  `json:"id"`
	RunID         string  `json:"run_id"`
	SessionID     string  `json:"session_id"`
	AttemptID     string  `json:"attempt_id"`
	ToolCallID    string  `json:"tool_call_id"`
	ProcessID     string  `json:"process_id"`
	ContainerID   string  `json:"container_id"`
	CgroupID      string  `json:"cgroup_id"`
	RootPID       int64   `json:"root_pid"`
	PID           int64   `json:"pid"`
	StartedAt     string  `json:"started_at"`
	EndedAt       string  `json:"ended_at"`
	BindingSource string  `json:"binding_source"`
	Confidence    float64 `json:"confidence"`
}

type RawIdentity struct {
	RunID       string
	ProcessID   string
	ContainerID string
	CgroupID    string
	PID         int64
	TGID        int64
	PPID        int64
	Timestamp   string
}

type Match struct {
	Binding
	Method     string
	Confidence float64
}

type BindingFilter struct {
	RunID      string
	SessionID  string
	AttemptID  string
	ToolCallID string
	ProcessID  string
}

// BindingSourceK8sCgroup marks a scope established by passive cgroup→pod
// attribution (a node sensor observing an externally-scheduled pod we did not
// launch), as opposed to a scope we launched via record/control-plane.
const BindingSourceK8sCgroup = "k8s_cgroup"

// DefaultBindingConfidence caps how much a binding may vouch for a match by how
// it was established, when the caller did not set an explicit confidence.
// scanOne takes the MIN of this binding confidence and the resolution method's
// own confidence, so an app-asserted (ai_asserted) join can never read as
// certain as a kernel-verified one even if it happens to match by pid. This is
// the honesty tier: a scope the model merely CLAIMED is worth less than one the
// control plane launched or the kernel witnessed.
func DefaultBindingConfidence(bindingSource string) float64 {
	switch bindingSource {
	case "ai_asserted":
		// App-asserted only: a join key the model provided. Real, but unverified.
		return 0.5
	case BindingSourceK8sCgroup:
		// Passive cgroup→pod attribution: the kernel really witnessed these
		// events in this cgroup, but we did not launch the scope via record, so
		// it sits below a control-plane/record binding and above a bare claim.
		return 0.8
	default:
		// Control-plane / record / rollout launches and direct API binds are
		// first-party facts about a process we started; keep them authoritative.
		return 1
	}
}

func RecordBinding(db *sql.DB, binding Binding) (string, error) {
	if binding.StartedAt == "" {
		binding.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	start, err := time.Parse(time.RFC3339Nano, binding.StartedAt)
	if err != nil {
		return "", fmt.Errorf("invalid binding start: %w", err)
	}
	if binding.EndedAt != "" {
		end, err := time.Parse(time.RFC3339Nano, binding.EndedAt)
		if err != nil {
			return "", fmt.Errorf("invalid binding end: %w", err)
		}
		if end.Before(start) {
			return "", fmt.Errorf("binding end precedes start")
		}
	}
	if binding.BindingSource == "" {
		binding.BindingSource = "control_plane"
	}
	if binding.Confidence <= 0 {
		binding.Confidence = DefaultBindingConfidence(binding.BindingSource)
	}
	if binding.ID == "" {
		binding.ID = ids.New("bind")
	}
	_, err = db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		binding.ID, binding.RunID, binding.SessionID, binding.AttemptID, binding.ToolCallID, binding.ProcessID, binding.ContainerID, binding.CgroupID, binding.RootPID, binding.PID, binding.StartedAt, binding.EndedAt, binding.BindingSource, binding.Confidence, time.Now().UTC().Format(time.RFC3339Nano))
	return binding.ID, err
}

func ListBindings(db *sql.DB, filter BindingFilter) ([]Binding, error) {
	query := `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings`
	args := []any{}
	clauses := []string{}
	if filter.RunID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, filter.RunID)
	}
	if filter.SessionID != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, filter.SessionID)
	}
	if filter.AttemptID != "" {
		clauses = append(clauses, "attempt_id = ?")
		args = append(args, filter.AttemptID)
	}
	if filter.ToolCallID != "" {
		clauses = append(clauses, "tool_call_id = ?")
		args = append(args, filter.ToolCallID)
	}
	if filter.ProcessID != "" {
		clauses = append(clauses, "process_id = ?")
		args = append(args, filter.ProcessID)
	}
	if len(clauses) > 0 {
		query += " WHERE " + clauses[0]
		for i := 1; i < len(clauses); i++ {
			query += " AND " + clauses[i]
		}
	}
	query += " ORDER BY started_at ASC, created_at ASC"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bindings []Binding
	for rows.Next() {
		var binding Binding
		if err := rows.Scan(&binding.ID, &binding.RunID, &binding.SessionID, &binding.AttemptID, &binding.ToolCallID, &binding.ProcessID, &binding.ContainerID, &binding.CgroupID, &binding.RootPID, &binding.PID, &binding.StartedAt, &binding.EndedAt, &binding.BindingSource, &binding.Confidence); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(bindings, func(i, j int) bool {
		left, le := time.Parse(time.RFC3339Nano, bindings[i].StartedAt)
		right, re := time.Parse(time.RFC3339Nano, bindings[j].StartedAt)
		if le != nil || re != nil {
			return le == nil && re != nil
		}
		return left.Before(right)
	})
	return bindings, nil
}

func GetBinding(db *sql.DB, id string) (Binding, bool, error) {
	if id == "" {
		return Binding{}, false, nil
	}
	var binding Binding
	err := db.QueryRow(`SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings WHERE id = ?`, id).
		Scan(&binding.ID, &binding.RunID, &binding.SessionID, &binding.AttemptID, &binding.ToolCallID, &binding.ProcessID,
			&binding.ContainerID, &binding.CgroupID, &binding.RootPID, &binding.PID, &binding.StartedAt, &binding.EndedAt,
			&binding.BindingSource, &binding.Confidence)
	if err == sql.ErrNoRows {
		return Binding{}, false, nil
	}
	if err != nil {
		return Binding{}, false, err
	}
	return binding, true, nil
}

func CloseBinding(db *sql.DB, processID, endedAt string) error {
	if processID == "" {
		return nil
	}
	if endedAt == "" {
		endedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := time.Parse(time.RFC3339Nano, endedAt); err != nil {
		return fmt.Errorf("invalid binding end: %w", err)
	}
	_, err := db.Exec(`UPDATE execution_context_bindings SET ended_at = ? WHERE process_id = ? AND ended_at = ''`, endedAt, processID)
	return err
}

// CloseBindingByID closes one exact binding. Kubernetes informer attribution
// uses this when a container restarts or its pod is deleted: closing by cgroup
// or session could accidentally terminate a sibling container's scope.
func CloseBindingByID(db bindingExecer, bindingID, endedAt string) error {
	if strings.TrimSpace(bindingID) == "" {
		return fmt.Errorf("binding id is required")
	}
	if endedAt == "" {
		endedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := time.Parse(time.RFC3339Nano, endedAt); err != nil {
		return fmt.Errorf("invalid binding end: %w", err)
	}
	_, err := db.Exec(`UPDATE execution_context_bindings SET ended_at = ? WHERE id = ? AND ended_at = ''`, endedAt, bindingID)
	return err
}

// CloseBindingByPID closes open bindings for an OS pid, used when a system
// process_exit is observed (the kernel pid is known, our internal process_id is
// not). Setting ended_at bounds the binding's match window so it no longer
// over-binds later, unrelated events that reuse the pid -- the stale-open
// problem MaxOpenBindingAge only partially guards. Matches pid, not root_pid: a
// child exiting must not close the scope-root's binding.
type bindingExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

type bindingPIDStore interface {
	bindingExecer
	Query(query string, args ...any) (*sql.Rows, error)
}

func CloseBindingByPID(db bindingPIDStore, pid int64, endedAt string) error {
	if pid == 0 {
		return nil
	}
	if endedAt == "" {
		endedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	ended, err := time.Parse(time.RFC3339Nano, endedAt)
	if err != nil {
		return fmt.Errorf("invalid process exit timestamp: %w", err)
	}
	rows, err := db.Query(`SELECT id, started_at FROM execution_context_bindings WHERE pid = ? AND ended_at = ''`, pid)
	if err != nil {
		return err
	}
	var candidates []string
	for rows.Next() {
		var id, startedAt string
		if err := rows.Scan(&id, &startedAt); err != nil {
			rows.Close()
			return err
		}
		started, err := time.Parse(time.RFC3339Nano, startedAt)
		// A delayed exit may be replayed after this PID has been reused. It
		// cannot close an execution that started after the captured exit.
		if err == nil && !started.After(ended) {
			candidates = append(candidates, id)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range candidates {
		if err := CloseBindingByID(db, id, endedAt); err != nil {
			return err
		}
	}
	return nil
}

// Queryer allows correlation to share the evidence transaction and observe
// binding changes made earlier in the same batch.
type Queryer interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func Resolve(db Queryer, raw RawIdentity) (Match, bool, error) {
	at := raw.Timestamp
	if at == "" {
		at = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if raw.ProcessID != "" {
		match, ok, err := resolveByProcess(db, raw.RunID, raw.ProcessID)
		if err != nil || ok {
			return match, ok, err
		}
	}
	if raw.CgroupID != "" {
		match, ok, err := resolveByCgroup(db, raw.RunID, raw.CgroupID, at)
		if err != nil || ok {
			return match, ok, err
		}
	}
	if raw.ContainerID != "" {
		match, ok, err := resolveByContainer(db, raw.RunID, raw.ContainerID, at)
		if err != nil || ok {
			return match, ok, err
		}
	}
	if raw.PID != 0 {
		match, ok, err := resolveByPID(db, raw.RunID, raw.PID, at)
		if err != nil || ok {
			return match, ok, err
		}
	}
	return Match{}, false, nil
}

func resolveByProcess(db Queryer, runID, processID string) (Match, bool, error) {
	if runID != "" {
		return scanOne(db, "process_id", "run_id+process_id", 1, `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
			FROM execution_context_bindings WHERE run_id = ? AND process_id = ? ORDER BY created_at DESC LIMIT 1`, runID, processID)
	}
	return scanOne(db, "process_id", "process_id", 1, `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings WHERE process_id = ? ORDER BY created_at DESC LIMIT 1`, processID)
}

// MaxOpenBindingAge bounds how long a binding left open (ended_at = "") is
// allowed to match telemetry. Without it, a binding whose CloseBinding was
// dropped - every close call is best-effort (record/control) - would
// match every future event for its container/pid forever, silently over-binding
// later, unrelated executions to a stale context. An open binding only matches
// events within this window after it started; older events fall through to the
// next resolution tier or to unresolved.
//
// PRODUCT SEMANTICS: this assumes an open binding represents a SHORT-LIVED
// ToolCallScope (a tool call / process lifetime), not a session-lifetime
// identity. A long-running agent or session that stays open past this window
// without a close/reopen will see its real events go unresolved rather than
// risk mis-binding - which is the safe failure here. Session-lifetime identity
// that legitimately exceeds 24h must keep its binding refreshed (re-record on
// activity) or model itself as a series of scoped bindings, not one perpetual
// open binding. Tune via this var if the deployment's scope lifetimes differ.
var MaxOpenBindingAge = 24 * time.Hour

const bindingColumns = `id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence`

// resolveWindow runs a time-windowed binding lookup, shared by the
// cgroup/container/pid tiers (previously six near-identical queries). matchExpr
// is the tier predicate (e.g. "cgroup_id = ?"); matchArgs are its bound values.
//
// boundOpen applies the stale-open guard (MaxOpenBindingAge) to bindings left
// open (ended_at = ""). It is enabled ONLY for the pid tier: pid reuse is the
// real over-matching threat for an accidentally-unclosed binding. container_id /
// cgroup_id are specific keys, and a long-lived open anchor on them (e.g. an
// external-telemetry bind with a far-past start meant to match all events for a
// container) is a legitimate, intentional pattern that must keep resolving.
func resolveWindow(db Queryer, runID, method, source, matchExpr string, confidence float64, at string, boundOpen bool, matchArgs ...any) (Match, bool, error) {
	var sb strings.Builder
	args := make([]any, 0, len(matchArgs)+4)
	sb.WriteString("SELECT " + bindingColumns + " FROM execution_context_bindings WHERE ")
	if runID != "" {
		sb.WriteString("run_id = ? AND ")
		args = append(args, runID)
	}
	sb.WriteString(matchExpr)
	args = append(args, matchArgs...)
	// RFC3339Nano strings are not ordered chronologically (whole seconds,
	// fractional precision and timezone offsets all differ). Keep raw binding
	// timestamps intact for evidence export; compare only identity candidates
	// as parsed instants, including nanosecond boundaries and latest-start wins.
	instant, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return Match{}, false, fmt.Errorf("invalid event timestamp: %w", err)
	}
	rows, err := db.Query(sb.String(), args...)
	if err != nil {
		return Match{}, false, err
	}
	defer rows.Close()
	var best Binding
	var latest time.Time
	found := false
	for rows.Next() {
		var item Binding
		if err := rows.Scan(&item.ID, &item.RunID, &item.SessionID, &item.AttemptID, &item.ToolCallID, &item.ProcessID, &item.ContainerID, &item.CgroupID, &item.RootPID, &item.PID, &item.StartedAt, &item.EndedAt, &item.BindingSource, &item.Confidence); err != nil {
			return Match{}, false, err
		}
		start, err := time.Parse(time.RFC3339Nano, item.StartedAt)
		if err != nil || start.After(instant) {
			continue
		}
		if item.EndedAt != "" {
			end, err := time.Parse(time.RFC3339Nano, item.EndedAt)
			if err != nil || end.Before(instant) {
				continue
			}
		} else if boundOpen && start.Before(instant.Add(-MaxOpenBindingAge)) {
			continue
		}
		if !found || start.After(latest) {
			best, latest, found = item, start, true
		}
	}
	if err := rows.Err(); err != nil {
		return Match{}, false, err
	}
	if !found {
		return Match{}, false, nil
	}
	if best.Confidence > 0 && best.Confidence < confidence {
		confidence = best.Confidence
	}
	return Match{Binding: best, Method: method + ":" + source, Confidence: confidence}, true, nil
}

func resolveByCgroup(db Queryer, runID, cgroupID, at string) (Match, bool, error) {
	source := "cgroup_id+time"
	if runID != "" {
		source = "run_id+cgroup_id+time"
	}
	return resolveWindow(db, runID, "cgroup_time_window", source, "cgroup_id = ?", 0.98, at, false, cgroupID)
}

func resolveByContainer(db Queryer, runID, containerID, at string) (Match, bool, error) {
	source := "container_id+time"
	if runID != "" {
		source = "run_id+container_id+time"
	}
	return resolveWindow(db, runID, "container_time_window", source, "container_id = ?", 0.92, at, false, containerID)
}

func resolveByPID(db Queryer, runID string, pid int64, at string) (Match, bool, error) {
	source := "pid+time"
	if runID != "" {
		source = "run_id+pid+time"
	}
	return resolveWindow(db, runID, "pid_time_window", source, "(pid = ? OR root_pid = ?)", 0.85, at, true, pid, pid)
}

func scanOne(db Queryer, method, source string, confidence float64, query string, args ...any) (Match, bool, error) {
	var item Binding
	err := db.QueryRow(query, args...).Scan(&item.ID, &item.RunID, &item.SessionID, &item.AttemptID, &item.ToolCallID, &item.ProcessID, &item.ContainerID, &item.CgroupID, &item.RootPID, &item.PID, &item.StartedAt, &item.EndedAt, &item.BindingSource, &item.Confidence)
	if err == sql.ErrNoRows {
		return Match{}, false, nil
	}
	if err != nil {
		return Match{}, false, err
	}
	if item.Confidence > 0 && item.Confidence < confidence {
		confidence = item.Confidence
	}
	return Match{Binding: item, Method: method + ":" + source, Confidence: confidence}, true, nil
}

func EventPayloadWithCorrelation(payload string, match Match, resolved bool) string {
	if payload == "" {
		payload = "{}"
	}
	if !resolved {
		return fmt.Sprintf(`{"raw":%s,"correlation":{"method":"unresolved","confidence":0}}`, payload)
	}
	return fmt.Sprintf(`{"raw":%s,"correlation":{"binding_id":%q,"method":%q,"confidence":%.2f}}`, payload, match.ID, match.Method, match.Confidence)
}
