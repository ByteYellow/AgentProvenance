package telemetry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
)

const secCheckPageBytes = 4 << 20
const secCheckRecordBytes = 256 << 10

// ReadSecCheckSequence reads an exact, contiguous prefix from the committed
// receiver store. A missing row stops the prefix; callers can wait for spool
// ingestion. No wall-clock ordering, run-wide scan, or host PID matching is used.
// Imported replay IDs intentionally do not satisfy this live receiver lookup.
func ReadSecCheckSequence(ctx context.Context, db *sql.DB, runID string, registration seccheck.Registration,
	connection string, first uint64, count int) ([]EventRecord, error) {
	if db == nil || runID == "" || len(connection) == 0 || len(connection) > 256 || count < 1 || count > 256 || first > math.MaxUint64-uint64(count-1) {
		return nil, fmt.Errorf("invalid SecCheck sequence page")
	}
	identity, err := seccheck.IdentityFor(registration, nil)
	if err != nil {
		return nil, err
	}
	ids := make([]string, count)
	args := make([]any, count)
	for i := range ids {
		raw, _ := json.Marshal([]any{identity.Scope, connection, first + uint64(i)})
		rawID := fmt.Sprintf("seccheck:%x", sha256.Sum256(raw))
		ids[i] = fmt.Sprintf("evt-seccheck-%x", sha256.Sum256([]byte(rawID)))
		args[i] = ids[i]
	}
	rows, err := db.QueryContext(ctx, `SELECT id,run_id,session_id,tool_call_id,process_id,snapshot_id,
		raw_event_id,correlation_method,correlation_confidence,container_id,cgroup_id,pid,tgid,ppid,
		source,event_type,CASE WHEN length(CAST(payload AS BLOB))<=262144 THEN payload ELSE '' END,
		created_at,length(CAST(payload AS BLOB)) FROM events WHERE id IN (`+strings.TrimSuffix(strings.Repeat("?,", count), ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := make(map[string]EventRecord, count)
	bytes := 0
	for rows.Next() {
		var e EventRecord
		var size int
		if err := rows.Scan(&e.ID, &e.RunID, &e.SessionID, &e.ToolCallID, &e.ProcessID, &e.SnapshotID,
			&e.RawEventID, &e.CorrelationMethod, &e.CorrelationConfidence, &e.ContainerID, &e.CgroupID,
			&e.PID, &e.TGID, &e.PPID, &e.Source, &e.EventType, &e.Payload, &e.CreatedAt, &size); err != nil {
			return nil, err
		}
		bytes += size
		if size > secCheckRecordBytes || bytes > secCheckPageBytes {
			return nil, fmt.Errorf("SecCheck sequence page exceeds evidence budget")
		}
		if _, exists := found[e.ID]; exists {
			return nil, fmt.Errorf("duplicate SecCheck observation")
		}
		found[e.ID] = e
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]EventRecord, 0, len(found))
	for i, id := range ids {
		e, ok := found[id]
		if !ok {
			break
		}
		observation, err := ReadSecCheckEvidence(e)
		if err != nil {
			return nil, err
		}
		if e.RunID != runID || observation.Registration != registration || observation.ConnectionID != connection || observation.Sequence != first+uint64(i) {
			return nil, fmt.Errorf("SecCheck committed observation differs from requested identity")
		}
		result = append(result, e)
	}
	return result, nil
}
