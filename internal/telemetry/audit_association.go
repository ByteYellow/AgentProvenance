package telemetry

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const AuditAssociationRule = "agentprov.audit_lifecycle_operation/v1"

const (
	maxAuditRuntimeRows  = 50000
	maxAuditRuntimeBytes = 32 << 20
	maxAuditCandidates   = 20
)

type AuditAssociationOptions struct {
	RunID   string
	EventID string
	Limit   int
	Cursor  string
}

// Association is a read-only projection. It does not change the audit record's
// PID, binding or Session, and may change when late evidence adds candidates.
type AuditAssociationReport struct {
	SchemaVersion string                 `json:"schema_version"`
	Rule          string                 `json:"rule"`
	RunID         string                 `json:"run_id"`
	Status        string                 `json:"status"`
	Limit         int                    `json:"limit"`
	NextCursor    string                 `json:"next_cursor,omitempty"`
	HasMore       bool                   `json:"has_more"`
	RuntimeRows   int                    `json:"runtime_rows_examined"`
	Issues        []string               `json:"issues,omitempty"`
	Items         []AuditAssociationItem `json:"items"`
}

type AuditAssociationItem struct {
	EventID       string           `json:"event_id"`
	Source        AuditSource      `json:"source"`
	TimeWindow    *AuditTimeWindow `json:"time_window,omitempty"`
	Mechanism     string           `json:"mechanism"`
	Decision      string           `json:"decision"`
	Process       AuditAssociation `json:"process"`
	Operation     AuditAssociation `json:"operation"`
	ProcessExits  []string         `json:"process_exit_refs,omitempty"`
	Operations    []AuditOperation `json:"operations,omitempty"`
	EvidenceScope string           `json:"evidence_scope"`
}

type AuditTimeWindow struct {
	From                  string `json:"from"`
	Until                 string `json:"until"`
	DecimalPrecisionNS    int64  `json:"decimal_precision_ns"`
	CoarseClockResolution int64  `json:"source_coarse_clock_resolution_ns"`
	Basis                 string `json:"basis"`
}

type AuditAssociation struct {
	Status              string           `json:"status"`
	Basis               string           `json:"basis,omitempty"`
	Reason              string           `json:"reason,omitempty"`
	CandidateCount      int              `json:"candidate_count"`
	CandidatesTruncated bool             `json:"candidates_truncated,omitempty"`
	Candidates          []AuditCandidate `json:"candidates,omitempty"`
}

type AuditCandidate struct {
	ID           string   `json:"id"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type AuditOperation struct {
	ID              string            `json:"id"`
	ProcessInstance string            `json:"process_instance_id"`
	ThreadInstance  string            `json:"thread_instance_id"`
	Kind            string            `json:"kind"`
	AttemptState    string            `json:"attempt_state"`
	ResultState     string            `json:"result_state"`
	AttemptCount    int               `json:"attempt_record_count"`
	ResultCount     int               `json:"result_record_count"`
	RefsTruncated   bool              `json:"refs_truncated,omitempty"`
	AttemptRefs     []string          `json:"attempt_refs,omitempty"`
	ResultRefs      []string          `json:"result_refs,omitempty"`
	Result          *int64            `json:"syscall_result,omitempty"`
	Outcome         string            `json:"syscall_outcome,omitempty"`
	Context         []AuditContextRef `json:"context,omitempty"`
}

// Context is cited from runtime records, not inferred from a shared PID/cgroup.
type AuditContextRef struct {
	EventID    string  `json:"event_id"`
	SessionID  string  `json:"session_id,omitempty"`
	ToolCallID string  `json:"tool_call_id,omitempty"`
	Method     string  `json:"method"`
	Confidence float64 `json:"confidence"`
}

type auditAssociationInput struct {
	id     string
	record AuditRecord
}

type auditAssociationCursor struct {
	Rule, RunID, EventID, After string
}

func BuildAuditAssociations(ctx context.Context, db *sql.DB, opts AuditAssociationOptions) (AuditAssociationReport, error) {
	report := AuditAssociationReport{SchemaVersion: "agentprovenance.audit_associations/v1", Rule: AuditAssociationRule,
		RunID: opts.RunID, Status: "complete", Items: []AuditAssociationItem{}}
	if db == nil || strings.TrimSpace(opts.RunID) == "" {
		return report, fmt.Errorf("audit association requires database and run")
	}
	if opts.Limit == 0 {
		opts.Limit = 100
	}
	if opts.Limit < 1 || opts.Limit > 500 {
		return report, fmt.Errorf("audit association limit must be between 1 and 500")
	}
	report.Limit = opts.Limit
	var cursor auditAssociationCursor
	if opts.Cursor != "" {
		if len(opts.Cursor) > 4096 {
			return report, fmt.Errorf("invalid audit association cursor")
		}
		raw, err := base64.RawURLEncoding.DecodeString(opts.Cursor)
		if err != nil || json.Unmarshal(raw, &cursor) != nil ||
			cursor.Rule != AuditAssociationRule || cursor.RunID != opts.RunID || cursor.EventID != opts.EventID || cursor.After == "" {
			return report, fmt.Errorf("invalid audit association cursor")
		}
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	query := `SELECT id,source,substr(payload,1,131073) FROM events WHERE run_id=? AND event_type='access_control'
		AND source IN ('apparmor_audit','seccomp_audit') AND id>?`
	args := []any{opts.RunID, cursor.After}
	if opts.EventID != "" {
		query += ` AND id=?`
		args = append(args, opts.EventID)
	}
	query += ` ORDER BY id LIMIT ?`
	args = append(args, opts.Limit+1)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return report, err
	}
	var inputs []auditAssociationInput
	pids := map[int64]bool{}
	for rows.Next() {
		var input auditAssociationInput
		var source, payload string
		if err := rows.Scan(&input.id, &source, &payload); err != nil {
			rows.Close()
			return report, err
		}
		if len(inputs) == opts.Limit {
			report.HasMore = true
			break
		}
		if len(payload) > 131072 {
			rows.Close()
			return report, fmt.Errorf("audit record %s exceeds association input limit", input.id)
		}
		body, err := decodePayloadObject(payload)
		if err == nil {
			var raw []byte
			raw, err = json.Marshal(unwrapStoredPayload(body))
			if err == nil {
				err = json.Unmarshal(raw, &input.record)
			}
		}
		if err != nil || input.record.SchemaVersion != AuditSchemaVersion || source != input.record.Mechanism+"_audit" {
			rows.Close()
			return report, fmt.Errorf("invalid stored audit record %s", input.id)
		}
		if input.record.AuditPID != nil && *input.record.AuditPID > 0 {
			pids[*input.record.AuditPID] = true
		}
		inputs = append(inputs, input)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil {
		return report, readErr
	}
	if closeErr != nil {
		return report, closeErr
	}
	if report.HasMore {
		raw, _ := json.Marshal(auditAssociationCursor{AuditAssociationRule, opts.RunID, opts.EventID, inputs[len(inputs)-1].id})
		report.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	runtime, limited, err := readAuditRuntime(ctx, tx, opts.RunID, pids)
	if err != nil {
		return report, err
	}
	report.RuntimeRows = len(runtime)
	if limited {
		report.Status = "incomplete"
		report.Issues = append(report.Issues, "runtime_input_limit")
	}
	index := indexAuditRuntime(runtime)
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		item := associateAudit(input, index)
		if limited {
			item.Process = auditUnknown("runtime_input_limit")
			item.Operation = auditUnknown("runtime_input_limit")
			item.Operations, item.ProcessExits = nil, nil
		}
		report.Items = append(report.Items, item)
	}
	if err := tx.Commit(); err != nil {
		return report, err
	}
	return report, nil
}

// Query the run/PID index once for the page, close its cursor before analysis,
// and bound both rows and payload bytes. Exhaustion disables all page matches.
func readAuditRuntime(ctx context.Context, tx *sql.Tx, run string, pids map[int64]bool) ([]auditRuntime, bool, error) {
	if len(pids) == 0 {
		return nil, false, nil
	}
	ids := make([]int64, 0, len(pids))
	for pid := range pids {
		ids = append(ids, pid)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	args := []any{run}
	for _, pid := range ids {
		args = append(args, pid)
	}
	args = append(args, maxAuditRuntimeRows+1)
	rows, err := tx.QueryContext(ctx, `SELECT id,pid,event_type,created_at,COALESCE(session_id,''),COALESCE(tool_call_id,''),
		COALESCE(correlation_method,''),COALESCE(correlation_confidence,0),substr(payload,1,65537)
		FROM events WHERE run_id=? AND source='agentprov_ebpf' AND event_type IN
		('process_observed','execve','process_exit','thread_exit','file_open','file_write','secret_path','network_connect','metadata_ip','private_cidr','syscall_result')
		AND pid IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`)
		LIMIT ?`, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var events []auditRuntime
	size := 0
	for rows.Next() {
		var e auditRuntime
		var payload, timestamp string
		if err := rows.Scan(&e.id, &e.pid, &e.etype, &timestamp, &e.context.SessionID, &e.context.ToolCallID,
			&e.context.Method, &e.context.Confidence, &payload); err != nil {
			return nil, false, err
		}
		size += len(payload)
		if len(events) == maxAuditRuntimeRows || size > maxAuditRuntimeBytes || len(payload) > 65536 {
			return events, true, nil
		}
		e.context.EventID = e.id
		e.at, _ = time.Parse(time.RFC3339Nano, timestamp)
		body, err := decodePayloadObject(payload)
		if err == nil {
			raw, marshalErr := json.Marshal(unwrapStoredPayload(body))
			if marshalErr == nil {
				if json.Unmarshal(raw, &e.fields) != nil {
					e.fields = auditRuntimeFields{}
				}
			}
		}
		events = append(events, e)
	}
	return events, false, rows.Err()
}
