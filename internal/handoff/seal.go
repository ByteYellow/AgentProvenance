package handoff

import (
	"context"
	"fmt"
)

const SealSchema = "agentprovenance.execution_seal/v1"

type SealResult struct {
	SchemaVersion string    `json:"schema_version"`
	OperationID   string    `json:"operation_id"`
	AttemptID     string    `json:"attempt_id"`
	RunID         string    `json:"run_id"`
	Status        string    `json:"status"`
	Delivery      *Delivery `json:"delivery,omitempty"`
	BundlePath    string    `json:"bundle_path,omitempty"`
	Error         string    `json:"error,omitempty"`
}

type SealSummary struct {
	SchemaVersion string `json:"schema_version"`
	OperationID   string `json:"operation_id"`
	Target        Target `json:"target"`
	ReceiverID    string `json:"receiver_id"`
	Attempts      int64  `json:"attempts"`
	Prepared      int64  `json:"prepared"`
	Reused        int64  `json:"reused"`
	Unfinished    int64  `json:"unfinished"`
	Failed        int64  `json:"failed"`
	Complete      bool   `json:"complete"`
}

// SealStopped prepares signed outbox packages after the executor has stopped.
// It never starts, cancels, recovers or acknowledges an execution. One bounded
// page is materialized before Prepare opens its frozen export snapshot.
func (s *DeliveryService) SealStopped(ctx context.Context, p Principal, operationID string, emit func(SealResult) error) (SealSummary, error) {
	summary := SealSummary{SchemaVersion: SealSchema, OperationID: operationID, Target: s.Ledger.Target, ReceiverID: s.ReceiverID}
	if err := s.validate(); err != nil {
		return summary, err
	}
	if !validID(operationID) {
		return summary, ErrInvalid
	}
	if err := p.Authorize(Source{ProducerID: p.ProducerID, Namespace: p.Namespace}, s.Ledger.Target); err != nil {
		return summary, err
	}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	lock, err := lockExecutor(s.Paths.Root)
	if err != nil {
		return summary, fmt.Errorf("execution sealing requires a stopped executor: %w", err)
	}
	defer lock.Close()
	var upper int64
	if err := s.Ledger.DB.QueryRowContext(ctx, `SELECT coalesce(max(sequence),0) FROM execution_attempts`).Scan(&upper); err != nil {
		return summary, err
	}
	var after int64
	var firstFailure error
	for {
		page, err := s.sealPage(ctx, p, after, upper)
		if err != nil {
			return summary, err
		}
		if len(page) == 0 {
			break
		}
		for _, a := range page {
			if err := ctx.Err(); err != nil {
				return summary, err
			}
			summary.Attempts++
			result := SealResult{SchemaVersion: SealSchema, OperationID: operationID, AttemptID: a.ID, RunID: a.LocalRunID}
			if !a.State.Execution.CanReexecute() {
				result.Status, result.Error = "unfinished", "execution has not reached a terminal checkpoint"
				summary.Unfinished++
			} else {
				delivery, reused, err := s.Prepare(ctx, p, a.ID, operationID)
				if err != nil {
					result.Status, result.Error = "failed", err.Error()
					summary.Failed++
					if firstFailure == nil {
						firstFailure = err
					}
				} else {
					result.Delivery, result.BundlePath = &delivery, delivery.BundlePath
					if reused {
						result.Status = "reused"
						summary.Reused++
					} else {
						result.Status = "prepared"
						summary.Prepared++
					}
				}
			}
			if emit != nil {
				if err := emit(result); err != nil {
					return summary, err
				}
			}
			after = a.Sequence
		}
	}
	if firstFailure != nil {
		return summary, fmt.Errorf("execution sealing failed for %d attempts: %w", summary.Failed, firstFailure)
	}
	if summary.Unfinished != 0 {
		return summary, fmt.Errorf("%w: %d executions remain unfinished", ErrConflict, summary.Unfinished)
	}
	summary.Complete = true
	return summary, nil
}

func (s *DeliveryService) sealPage(ctx context.Context, p Principal, after, upper int64) ([]Attempt, error) {
	rows, err := s.Ledger.DB.QueryContext(ctx, attemptSelect+` WHERE a.sequence>? AND a.sequence<=? AND d.principal_id=?
		AND json_extract(a.request_json,'$.source.producer_id')=? AND json_extract(a.request_json,'$.source.namespace')=?
		AND json_extract(a.request_json,'$.target.producer_id')=? AND json_extract(a.request_json,'$.target.instance_id')=?
		AND json_extract(a.request_json,'$.target.generation')=? ORDER BY a.sequence LIMIT 100`,
		after, upper, p.ID, p.ProducerID, p.Namespace, s.Ledger.Target.ProducerID, s.Ledger.Target.InstanceID, s.Ledger.Target.Generation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var page []Attempt
	for rows.Next() {
		a, err := scanAttempt(rows)
		if err != nil {
			return nil, err
		}
		if a.principalID != p.ID || a.Request.Target != s.Ledger.Target || p.Authorize(a.Request.Source, a.Request.Target) != nil {
			return nil, ErrForbidden
		}
		page = append(page, a)
	}
	return page, rows.Err()
}
