package hooksbridge

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

const (
	CorrelationMethod         = correlation.AppProcessMethod
	CorrelationConfidence     = correlation.AppProcessConfidence
	maxCorrelationEvents      = 200000
	maxCorrelationCalls       = 10000
	maxCorrelationBytes       = 64 << 20
	maxCorrelationComparisons = 2000000
)

type CorrelationReport struct {
	SchemaVersion      string   `json:"schema_version"`
	RunID              string   `json:"run_id"`
	Method             string   `json:"method"`
	Confidence         float64  `json:"confidence"`
	Status             string   `json:"status"`
	InputComplete      bool     `json:"input_complete"`
	ObservedAt         string   `json:"observed_at"`
	Ref                string   `json:"ref,omitempty"`
	ToolCalls          int      `json:"tool_calls"`
	UnclockedCalls     int      `json:"unclocked_calls"`
	RuntimeEvents      int      `json:"runtime_events"`
	ExecEvents         int      `json:"exec_events"`
	MatchedExecs       int      `json:"matched_execs"`
	InheritedExecs     int      `json:"inherited_execs"`
	AmbiguousExecs     int      `json:"ambiguous_execs"`
	UnknownScopeEvents int      `json:"unknown_scope_events"`
	InvalidEvents      int      `json:"invalid_events"`
	Edges              int      `json:"edges"`
	Issues             []string `json:"issues,omitempty"`
}

type correlationCall struct {
	id, command string
	start, end  time.Time
}

type processScope struct {
	source, origin, cgroup, container string
	pid                               int64
}

type correlationEvent struct {
	id, typ, command string
	scope            processScope
	ppid             int64
	at               time.Time
	truncated        bool
}

type processOwner struct {
	call   correlationCall
	anchor string
	start  time.Time
	depth  int
}

type correlationLink struct{ call, event, anchor string }

// CorrelateSyscalls retains the existing entry point. The detailed variant
// exposes ambiguity and coverage without converting either into a guessed edge.
func CorrelateSyscalls(db *sql.DB, runID string) (int, error) {
	r, err := CorrelateSyscallsWithReport(db, runID)
	return r.Edges, err
}

// CorrelateSyscallsWithReport rebuilds only agent_syscall edges in one database
// snapshot/transaction. Scope association is already recorded by ingestion;
// this pass adds a weaker app-to-process inference, never kernel-certified intent.
func CorrelateSyscallsWithReport(db *sql.DB, runID string) (CorrelationReport, error) {
	r := CorrelationReport{SchemaVersion: "agentprovenance.runtime_correlation/v1", RunID: runID,
		Method: CorrelationMethod, Confidence: CorrelationConfidence, Status: "failed", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if strings.TrimSpace(runID) == "" {
		return r, fmt.Errorf("runtime correlation requires run_id")
	}
	tx, err := db.Begin()
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	calls, err := readCorrelationCalls(tx, runID, &r)
	if err != nil {
		return r, err
	}
	events, err := readCorrelationEvents(tx, runID, &r)
	if err != nil {
		return r, err
	}
	r.InputComplete = true
	links, err := associateProcesses(calls, events, &r)
	if err != nil {
		return r, err
	}
	if _, err := tx.Exec(`DELETE FROM graph_edges WHERE run_id=? AND edge_type=?`, runID, EdgeAgentSyscall); err != nil {
		return r, err
	}
	stmt, err := tx.Prepare(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,source_event_id,created_at) VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		return r, err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, link := range links {
		sum := sha256.Sum256([]byte(runID + "\x00" + link.call + "\x00" + link.event + "\x00" + link.anchor))
		id := correlation.AppProcessEdgePrefix + hex.EncodeToString(sum[:])
		if _, err := stmt.Exec(id, runID, link.call, "runtime_event/"+link.event, EdgeAgentSyscall, link.anchor, now); err != nil {
			return r, err
		}
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	r.Edges, r.Status = len(links), "ok"
	if r.ExecEvents == 0 {
		r.Status = "no_input"
	} else if r.ToolCalls == 0 {
		r.Status = "empty"
	}
	if r.UnclockedCalls+r.InvalidEvents+r.UnknownScopeEvents > 0 || r.MatchedExecs < r.ExecEvents {
		r.Status = "partial"
	}
	if r.AmbiguousExecs > 0 {
		r.Issues = append(r.Issues, "multiple_runtime_candidates")
		if r.MatchedExecs == 0 {
			r.Status = "ambiguous"
		}
	}
	if r.UnclockedCalls > 0 {
		r.Issues = append(r.Issues, "tool_time_not_recorded")
	}
	if r.UnknownScopeEvents > 0 {
		r.Issues = append(r.Issues, "runtime_scope_not_recorded")
	}
	if r.InvalidEvents > 0 {
		r.Issues = append(r.Issues, "runtime_time_or_payload_invalid")
	}
	if r.MatchedExecs < r.ExecEvents {
		r.Issues = append(r.Issues, "runtime_exec_unassociated")
	}
	return r, nil
}

func readCorrelationCalls(tx *sql.Tx, runID string, r *CorrelationReport) ([]correlationCall, error) {
	rows, err := tx.Query(`SELECT id,substr(command,1,65537),COALESCE(started_at,''),COALESCE(ended_at,'')
		FROM tool_calls WHERE run_id=? AND agent_id!='' AND command!='' ORDER BY id LIMIT ?`, runID, maxCorrelationCalls+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var calls []correlationCall
	commandBytes := 0
	for rows.Next() {
		var c correlationCall
		var start, end string
		if err := rows.Scan(&c.id, &c.command, &start, &end); err != nil {
			return nil, err
		}
		r.ToolCalls++
		commandBytes += len(c.command)
		if r.ToolCalls > maxCorrelationCalls || len(c.command) > 65536 || commandBytes > maxCorrelationBytes {
			return nil, fmt.Errorf("runtime correlation tool-input limit exceeded")
		}
		c.start, err = time.Parse(time.RFC3339Nano, start)
		if err != nil {
			r.UnclockedCalls++
			continue
		}
		if end == "" {
			r.UnclockedCalls++
			continue
		} else {
			c.end, err = time.Parse(time.RFC3339Nano, end)
			if err != nil || c.end.Before(c.start) {
				r.UnclockedCalls++
				continue
			}
		}
		calls = append(calls, c)
	}
	return calls, rows.Err()
}

func readCorrelationEvents(tx *sql.Tx, runID string, r *CorrelationReport) ([]correlationEvent, error) {
	rows, err := tx.Query(`SELECT id,event_type,source,COALESCE(cgroup_id,''),COALESCE(container_id,''),COALESCE(pid,0),COALESCE(ppid,0),created_at,substr(payload,1,65537)
		FROM events WHERE run_id=? AND source IN ('agentprov_ebpf','native_runtime','tetragon_jsonl','falco_jsonl','filtered_telemetry','wrapper_runtime','loongcollector_jsonl')
		AND event_type IN ('execve','process_exit','secret_path','metadata_ip','private_cidr','network_connect','file_open','file_write','file_unlink','file_rename','dns_query')
		ORDER BY id LIMIT ?`, runID, maxCorrelationEvents+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []correlationEvent
	type unsafePID struct {
		source string
		pid    int64
	}
	unsafe := map[unsafePID]bool{}
	bytes := 0
	for rows.Next() {
		var e correlationEvent
		var ts, raw string
		if err := rows.Scan(&e.id, &e.typ, &e.scope.source, &e.scope.cgroup, &e.scope.container, &e.scope.pid, &e.ppid, &ts, &raw); err != nil {
			return nil, err
		}
		r.RuntimeEvents++
		if e.typ == "execve" {
			r.ExecEvents++
		}
		bytes += len(raw)
		if r.RuntimeEvents > maxCorrelationEvents || bytes > maxCorrelationBytes || len(raw) > 65536 {
			return nil, fmt.Errorf("runtime correlation event-input limit exceeded")
		}
		var payload map[string]any
		parseErr := json.Unmarshal([]byte(raw), &payload)
		e.at, err = time.Parse(time.RFC3339Nano, ts)
		knownScope := e.scope.pid > 0 && (e.scope.cgroup != "" || e.scope.container != "")
		if err != nil || parseErr != nil || !knownScope {
			if !knownScope {
				r.UnknownScopeEvents++
			} else {
				r.InvalidEvents++
			}
			if e.typ == "execve" || e.typ == "process_exit" {
				unsafe[unsafePID{e.scope.source, e.scope.pid}] = true
			}
			continue
		}
		inner := mapAt(payload, "payload")
		for _, layer := range []map[string]any{mapAt(inner, "raw"), inner, mapAt(payload, "raw"), payload} {
			if e.scope.origin == "" {
				e.scope.origin = strArg(layer, "node_name", "node", "host_id", "hostname", "producer_id")
			}
			if e.command == "" {
				e.command = strArg(layer, "command", "cmdline")
				if e.command != "" {
					e.truncated, _ = layer["argv_truncated"].(bool)
				}
			}
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// An unlocated exec/exit makes that source's PID lifetime uncertain. Do not
	// propagate through a lifecycle gap using the nearest remaining event.
	filtered := events[:0]
	for _, e := range events {
		if !unsafe[unsafePID{e.scope.source, e.scope.pid}] {
			filtered = append(filtered, e)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].at.Equal(filtered[j].at) {
			return filtered[i].id < filtered[j].id
		}
		return filtered[i].at.Before(filtered[j].at)
	})
	return filtered, nil
}

func associateProcesses(calls []correlationCall, events []correlationEvent, r *CorrelationReport) ([]correlationLink, error) {
	active := map[processScope]processOwner{}
	type identity struct {
		source, origin string
		pid            int64
	}
	scopes := map[identity]processScope{}
	var links []correlationLink
	comparisons := 0
	for start := 0; start < len(events); {
		end := start + 1
		for end < len(events) && events[end].at.Equal(events[start].at) {
			end++
		}
		boundaries := map[identity]int{}
		for _, e := range events[start:end] {
			if e.typ == "execve" || e.typ == "process_exit" {
				key := identity{e.scope.source, e.scope.origin, e.scope.pid}
				boundaries[key]++
				if old, ok := scopes[key]; ok {
					delete(active, old)
					delete(scopes, key)
				}
				delete(active, e.scope)
			}
		}
		for _, e := range events[start:end] {
			key := identity{e.scope.source, e.scope.origin, e.scope.pid}
			if e.typ == "process_exit" {
				continue
			}
			if e.typ != "execve" {
				if owner, ok := active[e.scope]; ok && boundaries[key] == 0 && owner.start.Before(e.at) && !e.at.After(owner.call.end) {
					links = append(links, correlationLink{owner.call.id, e.id, owner.anchor})
				}
				continue
			}
			if boundaries[key] != 1 {
				r.AmbiguousExecs++
				continue
			}
			var candidate *correlationCall
			ambiguous := false
			for i := range calls {
				comparisons++
				if comparisons > maxCorrelationComparisons {
					return nil, fmt.Errorf("runtime correlation comparison limit exceeded")
				}
				c := &calls[i]
				if e.at.Before(c.start) || e.at.After(c.end) || !commandMatches(e.command, c.command, e.truncated) {
					continue
				}
				if candidate != nil {
					ambiguous = true
					break
				}
				candidate = c
			}
			parentScope := e.scope
			parentScope.pid = e.ppid
			parent, inherited := active[parentScope]
			inherited = inherited && e.ppid > 0 && parent.start.Before(e.at) && !e.at.After(parent.call.end) && parent.depth < 64
			if candidate != nil && inherited && candidate.id != parent.call.id {
				ambiguous = true
			}
			if ambiguous {
				r.AmbiguousExecs++
				continue
			}
			var owner processOwner
			linkAnchor := e.id
			if candidate != nil {
				owner = processOwner{call: *candidate, anchor: e.id, start: e.at}
			} else if inherited {
				owner = processOwner{call: parent.call, anchor: e.id, start: e.at, depth: parent.depth + 1}
				linkAnchor = parent.anchor
				r.InheritedExecs++
			} else {
				continue
			}
			active[e.scope] = owner
			scopes[identity{e.scope.source, e.scope.origin, e.scope.pid}] = e.scope
			r.MatchedExecs++
			links = append(links, correlationLink{owner.call.id, e.id, linkAnchor})
		}
		start = end
	}
	return links, nil
}

// Match literal commands without changing case or whitespace inside arguments.
// A known shell wrapper exposes the same command string; arbitrary substrings
// (for example a command printed by echo) are never treated as execution.
func commandMatches(actual, requested string, truncated bool) bool {
	a, b := strings.TrimSpace(actual), strings.TrimSpace(requested)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	program, rest, ok := strings.Cut(a, " ")
	if ok && (path.Base(program) == "bash" || path.Base(program) == "sh" || path.Base(program) == "zsh") {
		flag, command, ok := strings.Cut(rest, " ")
		if ok && (flag == "-c" || flag == "-lc") {
			a = command
		}
	}
	if a == b {
		return true
	}
	// Only a source-marked, possibly truncated argv may prefix-match. Two
	// tokens are required; the caller still needs a unique time-window candidate.
	return truncated && len(strings.Fields(a)) >= 2 && strings.HasPrefix(b, a)
}
