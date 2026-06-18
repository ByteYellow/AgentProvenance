package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type ExplainOptions struct {
	RunID    string
	Artifact string
	Attempt  string
	ToolCall string
	Process  string
	Event    string
	File     string
	WithJSON bool
}

type ExplainManifest struct {
	SchemaVersion string             `json:"schema_version"`
	Target        ExplainTarget      `json:"target"`
	Summary       []string           `json:"summary"`
	RuntimeEdges  []ExplainGraphEdge `json:"runtime_edges,omitempty"`
	RuntimeEvents []ExplainEvent     `json:"runtime_events,omitempty"`
	FileDiff      *FileDiffManifest  `json:"file_diff,omitempty"`
	FileBlame     *FileBlameManifest `json:"file_blame,omitempty"`
}

type ExplainTarget struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
	Run  string `json:"run_id,omitempty"`
	File string `json:"file,omitempty"`
}

type ExplainGraphEdge struct {
	RunID         string `json:"run_id"`
	RolloutID     string `json:"rollout_id"`
	FromID        string `json:"from_id"`
	ToID          string `json:"to_id"`
	EdgeType      string `json:"edge_type"`
	SourceEventID string `json:"source_event_id"`
	CreatedAt     string `json:"created_at"`
}

type ExplainEvent struct {
	ID                    string  `json:"id"`
	RunID                 string  `json:"run_id"`
	SessionID             string  `json:"session_id"`
	ToolCallID            string  `json:"tool_call_id"`
	ProcessID             string  `json:"process_id"`
	SnapshotID            string  `json:"snapshot_id"`
	RawEventID            string  `json:"raw_event_id"`
	CorrelationMethod     string  `json:"correlation_method"`
	CorrelationConfidence float64 `json:"correlation_confidence"`
	ContainerID           string  `json:"container_id"`
	CgroupID              string  `json:"cgroup_id"`
	PID                   int64   `json:"pid"`
	TGID                  int64   `json:"tgid"`
	PPID                  int64   `json:"ppid"`
	Source                string  `json:"source"`
	EventType             string  `json:"event_type"`
	Payload               string  `json:"payload"`
	CreatedAt             string  `json:"created_at"`
}

func Explain(db *sql.DB, opts ExplainOptions, out io.Writer) error {
	if opts.WithJSON {
		manifest, err := BuildExplain(db, opts)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(manifest)
	}
	selected := 0
	for _, value := range []string{opts.Artifact, opts.Attempt, opts.ToolCall, opts.Process, opts.Event, opts.File} {
		if strings.TrimSpace(value) != "" {
			selected++
		}
	}
	if selected != 1 {
		return fmt.Errorf("use exactly one of --artifact, --attempt, --tool-call, --process, --event, or --file")
	}
	if opts.File != "" && opts.RunID == "" {
		return fmt.Errorf("--run is required with --file")
	}
	fmt.Fprintln(out, "explain:")
	switch {
	case opts.Artifact != "":
		fmt.Fprintf(out, "  target=artifact id=%s\n", opts.Artifact)
		return explainArtifact(db, opts.Artifact, out)
	case opts.Attempt != "":
		fmt.Fprintf(out, "  target=attempt id=%s\n", opts.Attempt)
		return explainAttempt(db, opts.Attempt, out)
	case opts.ToolCall != "":
		fmt.Fprintf(out, "  target=tool_call id=%s\n", opts.ToolCall)
		return explainToolCall(db, opts.ToolCall, out)
	case opts.Process != "":
		fmt.Fprintf(out, "  target=process id=%s\n", opts.Process)
		return explainProcess(db, opts.Process, out)
	case opts.Event != "":
		fmt.Fprintf(out, "  target=event id=%s\n", opts.Event)
		return explainEvent(db, opts.Event, out)
	case opts.File != "":
		fmt.Fprintf(out, "  target=file run=%s path=%s\n", opts.RunID, opts.File)
		return explainFile(db, opts.RunID, opts.File, out)
	default:
		return nil
	}
}

func BuildExplain(db *sql.DB, opts ExplainOptions) (ExplainManifest, error) {
	target, err := explainTarget(opts)
	if err != nil {
		return ExplainManifest{}, err
	}
	manifest := ExplainManifest{
		SchemaVersion: "agentprovenance.explain/v1",
		Target:        target,
	}
	switch target.Type {
	case "file":
		diff, err := BuildDiffFile(db, target.Run, target.File)
		if err != nil {
			return ExplainManifest{}, err
		}
		blame, err := BuildBlameFile(db, target.Run, target.File)
		if err != nil {
			return ExplainManifest{}, err
		}
		events, err := runtimeFileEvents(db, target.Run, target.File)
		if err != nil {
			return ExplainManifest{}, err
		}
		manifest.FileDiff = &diff
		manifest.FileBlame = &blame
		manifest.RuntimeEvents = explainEvents(events)
		manifest.RuntimeEdges, err = runtimeEdgesForFile(db, target.Run, target.File)
		if err != nil {
			return ExplainManifest{}, err
		}
		manifest.Summary = append(manifest.Summary,
			fmt.Sprintf("file %s has %d attempt diff entries", target.File, len(diff.Attempts)),
			fmt.Sprintf("file %s has %d blame entries", target.File, len(blame.Entries)),
			fmt.Sprintf("file %s has %d runtime file events", target.File, len(events)),
		)
	default:
		edgeID := target.ID
		if target.Type == "event" {
			edgeID = "runtime_event/" + target.ID
		}
		manifest.RuntimeEdges, err = runtimeEdgesForID(db, edgeID)
		if err != nil {
			return ExplainManifest{}, err
		}
		manifest.Summary = append(manifest.Summary, fmt.Sprintf("%s %s has %d runtime causality edges", target.Type, target.ID, len(manifest.RuntimeEdges)))
		if target.Type == "event" {
			event, err := eventByID(db, target.ID)
			if err != nil {
				return ExplainManifest{}, err
			}
			manifest.RuntimeEvents = []ExplainEvent{event}
		}
	}
	return manifest, nil
}

func explainTarget(opts ExplainOptions) (ExplainTarget, error) {
	selected := 0
	for _, value := range []string{opts.Artifact, opts.Attempt, opts.ToolCall, opts.Process, opts.Event, opts.File} {
		if strings.TrimSpace(value) != "" {
			selected++
		}
	}
	if selected != 1 {
		return ExplainTarget{}, fmt.Errorf("use exactly one of --artifact, --attempt, --tool-call, --process, --event, or --file")
	}
	if opts.File != "" {
		if opts.RunID == "" {
			return ExplainTarget{}, fmt.Errorf("--run is required with --file")
		}
		return ExplainTarget{Type: "file", Run: opts.RunID, File: opts.File}, nil
	}
	if opts.Artifact != "" {
		return ExplainTarget{Type: "artifact", ID: opts.Artifact}, nil
	}
	if opts.Attempt != "" {
		return ExplainTarget{Type: "attempt", ID: opts.Attempt}, nil
	}
	if opts.ToolCall != "" {
		return ExplainTarget{Type: "tool_call", ID: opts.ToolCall}, nil
	}
	if opts.Process != "" {
		return ExplainTarget{Type: "process", ID: opts.Process}, nil
	}
	return ExplainTarget{Type: "event", ID: opts.Event}, nil
}

func explainArtifact(db *sql.DB, artifactRef string, out io.Writer) error {
	if err := TraceArtifact(db, artifactRef, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "decision:")
	fmt.Fprintln(out, "  artifact lineage is derived from graph edges and matching attempt result_ref")
	return nil
}

func explainAttempt(db *sql.DB, attemptID string, out io.Writer) error {
	if err := TraceAttempt(db, attemptID, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "promotion_barrier:")
	rows, err := db.Query(`SELECT p.id, p.status, p.risk_status, p.telemetry_watermark, p.drain_pending_after, p.reason
		FROM promotions p WHERE p.attempt_id = ? ORDER BY p.created_at ASC`, attemptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status, risk, watermark, reason string
		var pending int
		if err := rows.Scan(&id, &status, &risk, &watermark, &pending, &reason); err != nil {
			return err
		}
		fmt.Fprintf(out, "  promotion=%s status=%s risk=%s watermark=%s drain_pending_after=%d reason=%q\n", id, status, risk, watermark, pending, reason)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return printRuntimeEdgesForID(db, out, attemptID)
}

func explainToolCall(db *sql.DB, toolCallID string, out io.Writer) error {
	if err := TraceToolCall(db, toolCallID, out); err != nil {
		return err
	}
	return printRuntimeEdgesForID(db, out, toolCallID)
}

func explainProcess(db *sql.DB, processID string, out io.Writer) error {
	if err := TraceProcess(db, processID, out); err != nil {
		return err
	}
	return printRuntimeEdgesForID(db, out, processID)
}

func explainEvent(db *sql.DB, eventID string, out io.Writer) error {
	var runID, sessionID, toolCallID, processID, snapshotID, source, eventType, payload, createdAt string
	var pid, tgid, ppid int64
	err := db.QueryRow(`SELECT COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
			COALESCE(process_id, ''), COALESCE(snapshot_id, ''), source, event_type, payload, created_at,
			COALESCE(pid, 0), COALESCE(tgid, 0), COALESCE(ppid, 0)
		FROM events WHERE id = ?`, eventID).Scan(&runID, &sessionID, &toolCallID, &processID, &snapshotID, &source, &eventType, &payload, &createdAt, &pid, &tgid, &ppid)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "event:")
	fmt.Fprintf(out, "  event=%s run=%s session=%s tool_call=%s process=%s snapshot=%s source=%s type=%s pid=%d tgid=%d ppid=%d created_at=%s payload=%s\n",
		eventID, runID, sessionID, toolCallID, processID, snapshotID, source, eventType, pid, tgid, ppid, createdAt, payload)
	fmt.Fprintln(out, "runtime_causality:")
	if err := printEdgesForIDs(db, out, []string{"runtime_event/" + eventID}); err != nil {
		return err
	}
	if processID != "" {
		return printRuntimeEdgesForID(db, out, processID)
	}
	return nil
}

func explainFile(db *sql.DB, runID, filePath string, out io.Writer) error {
	fmt.Fprintln(out, "state_diff:")
	if err := DiffFile(db, runID, filePath, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "state_blame:")
	if err := BlameFile(db, runID, filePath, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "runtime_file_events:")
	events, err := runtimeFileEvents(db, runID, filePath)
	if err != nil {
		return err
	}
	for _, event := range events {
		fmt.Fprintf(out, "  event=%s type=%s tool_call=%s process=%s snapshot=%s correlation=%s pid=%d tgid=%d ppid=%d payload=%s\n",
			event.ID, event.EventType, event.ToolCallID, event.ProcessID, event.SnapshotID, event.CorrelationMethod, event.PID, event.TGID, event.PPID, event.Payload)
	}
	return nil
}

func runtimeFileEvents(db *sql.DB, runID, filePath string) ([]telemetry.EventRecord, error) {
	events, err := telemetry.ListEventsFiltered(db, telemetry.Filter{RunID: runID})
	if err != nil {
		return nil, err
	}
	needle1 := fmt.Sprintf(`"path":"%s"`, filePath)
	needle2 := fmt.Sprintf(`"file":"%s"`, filePath)
	filtered := []telemetry.EventRecord{}
	for _, event := range events {
		if event.EventType != "file_write" && event.EventType != "file_open" {
			continue
		}
		if !strings.Contains(event.Payload, needle1) && !strings.Contains(event.Payload, needle2) {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered, nil
}

func explainEvents(events []telemetry.EventRecord) []ExplainEvent {
	out := make([]ExplainEvent, 0, len(events))
	for _, event := range events {
		out = append(out, ExplainEvent{
			ID:                    event.ID,
			RunID:                 event.RunID,
			SessionID:             event.SessionID,
			ToolCallID:            event.ToolCallID,
			ProcessID:             event.ProcessID,
			SnapshotID:            event.SnapshotID,
			RawEventID:            event.RawEventID,
			CorrelationMethod:     event.CorrelationMethod,
			CorrelationConfidence: event.CorrelationConfidence,
			ContainerID:           event.ContainerID,
			CgroupID:              event.CgroupID,
			PID:                   event.PID,
			TGID:                  event.TGID,
			PPID:                  event.PPID,
			Source:                event.Source,
			EventType:             event.EventType,
			Payload:               event.Payload,
			CreatedAt:             event.CreatedAt,
		})
	}
	return out
}

func runtimeEdgesForFile(db *sql.DB, runID, filePath string) ([]ExplainGraphEdge, error) {
	return runtimeEdgesWhere(db, `run_id = ? AND (from_id = ? OR to_id = ?)`, runID, "workspace_file/"+filePath, "workspace_file/"+filePath)
}

func runtimeEdgesForID(db *sql.DB, id string) ([]ExplainGraphEdge, error) {
	if id == "" {
		return nil, nil
	}
	return runtimeEdgesWhere(db, `(from_id = ? OR to_id = ?)`, id, id)
}

func runtimeEdgesWhere(db *sql.DB, where string, args ...any) ([]ExplainGraphEdge, error) {
	query := `SELECT run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at
		FROM graph_edges WHERE edge_type LIKE 'runtime_%' AND ` + where + ` ORDER BY created_at ASC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edges []ExplainGraphEdge
	for rows.Next() {
		var edge ExplainGraphEdge
		if err := rows.Scan(&edge.RunID, &edge.RolloutID, &edge.FromID, &edge.ToID, &edge.EdgeType, &edge.SourceEventID, &edge.CreatedAt); err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, rows.Err()
}

func eventByID(db *sql.DB, eventID string) (ExplainEvent, error) {
	var event ExplainEvent
	err := db.QueryRow(`SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
			COALESCE(process_id, ''), COALESCE(snapshot_id, ''), COALESCE(raw_event_id, ''),
			COALESCE(correlation_method, ''), COALESCE(correlation_confidence, 0),
			COALESCE(container_id, ''), COALESCE(cgroup_id, ''), COALESCE(pid, 0), COALESCE(tgid, 0), COALESCE(ppid, 0),
			source, event_type, payload, created_at
		FROM events WHERE id = ?`, eventID).Scan(&event.ID, &event.RunID, &event.SessionID, &event.ToolCallID,
		&event.ProcessID, &event.SnapshotID, &event.RawEventID, &event.CorrelationMethod, &event.CorrelationConfidence,
		&event.ContainerID, &event.CgroupID, &event.PID, &event.TGID, &event.PPID, &event.Source, &event.EventType, &event.Payload, &event.CreatedAt)
	return event, err
}

func printRuntimeEdgesForID(db *sql.DB, out io.Writer, id string) error {
	if id == "" {
		return nil
	}
	fmt.Fprintln(out, "runtime_causality_explain:")
	rows, err := db.Query(`SELECT run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at
		FROM graph_edges
		WHERE edge_type LIKE 'runtime_%' AND (from_id = ? OR to_id = ?)
		ORDER BY created_at ASC`, id, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var runID, rolloutID, fromID, toID, edgeType, sourceEventID, createdAt string
		if err := rows.Scan(&runID, &rolloutID, &fromID, &toID, &edgeType, &sourceEventID, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  run=%s rollout=%s from=%s to=%s type=%s source_event=%s created_at=%s\n",
			runID, rolloutID, fromID, toID, edgeType, sourceEventID, createdAt)
	}
	return rows.Err()
}
