package signal

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/signals"
)

// PersistEvalSignals lands evaluator output on the unified, graph-attached
// signal model (the infra contract) under the Quality dimension. Previously
// quality lived only as a Python/JSONL EvalReport with no Go-side table; this
// makes quality a first-class citizen of the same `signals` store that security
// and cost use, keyed to the same causality graph.
//
// Each signal is idempotent on (source_table, source_id) so re-importing the
// same evaluator output does not duplicate rows. Returns how many new rows were
// recorded.
func PersistEvalSignals(db *sql.DB, engine string, evals []EvalSignal) (int, error) {
	if engine == "" {
		engine = "external-evaluator"
	}
	n := 0
	for i := range evals {
		e := evals[i]
		kind, refID := "run", e.RunID
		if e.ToolCallID != "" {
			kind, refID = "tool_call", e.ToolCallID
		} else if e.AttemptID != "" {
			kind, refID = "attempt", e.AttemptID
		}
		payload := map[string]any{"kind": string(e.Kind)}
		if len(e.Evidence) > 0 {
			payload["evidence"] = e.Evidence
		}
		payloadJSON, _ := json.Marshal(payload)

		recorded, err := signals.RecordCounting(db, signals.Signal{
			Dimension:    signals.Quality,
			Type:         e.Name,
			GraphRefKind: kind,
			GraphRefID:   refID,
			RunID:        e.RunID,
			ToolCallID:   e.ToolCallID,
			Label:        e.Label, // quality label (pass/candidate/...); severity is security-only
			Value:        e.Score,
			Reference:    e.Reason,
			ProducedBy:   "evaluator:" + engine,
			Payload:      string(payloadJSON),
			SourceTable:  "eval_signals",
			SourceID:     fmt.Sprintf("%s:%s:%s", e.RunID, engine, e.ID),
		})
		if err != nil {
			return n, fmt.Errorf("persist eval signal %q: %w", e.Name, err)
		}
		if recorded {
			n++
		}
	}
	return n, nil
}
