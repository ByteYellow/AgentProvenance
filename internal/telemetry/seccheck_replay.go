package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const SecCheckReplaySchema = "agentprovenance.seccheck_spool_replay/v1"

// SecCheckReplayReceipt describes delivery of old observations, not new
// execution. The uploader is an operator-owned registration outside the copy.
type SecCheckReplayReceipt struct {
	SchemaVersion  string                `json:"schema_version"`
	ReceiptID      string                `json:"receipt_id"`
	Uploader       seccheck.Registration `json:"uploader"`
	AuthorityBasis string                `json:"authority_basis"`
	FileSHA256     string                `json:"file_sha256"`
	SizeBytes      int                   `json:"size_bytes"`
	Records        int                   `json:"records"`
	Ingested       int                   `json:"ingested"`
	Duplicates     int                   `json:"duplicates"`
	EventIDs       []string              `json:"event_ids"`
	ReceivedAt     string                `json:"received_at"`
}

type SecCheckReplayDelivery struct {
	RunID string `json:"run_id"`
	SecCheckReplayReceipt
}

type SecCheckReplayResult struct {
	SchemaVersion string                   `json:"schema_version"`
	Receipts      []SecCheckReplayDelivery `json:"receipts"`
	Reused        []string                 `json:"reused_receipt_ids"`
}

// ReplaySecCheckSpool imports one immutable normalized batch. The local
// operator supplies its independently retained digest and current uploader;
// copied records never supply either authority. No network listener is added.
func ReplaySecCheckSpool(ctx context.Context, db *sql.DB, input io.Reader, expected string, uploader seccheck.Target) (SecCheckReplayResult, error) {
	out := SecCheckReplayResult{SchemaVersion: SecCheckReplaySchema, Receipts: []SecCheckReplayDelivery{}, Reused: []string{}}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	cfg := seccheck.CollectionConfig{SchemaVersion: seccheck.CollectionConfigSchema, RuntimeRelease: seccheck.RuntimeRelease, Targets: []seccheck.Target{uploader}}
	if err := cfg.Validate(); err != nil {
		return out, err
	}
	digest, err := hex.DecodeString(expected)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != expected {
		return out, fmt.Errorf("SecCheck replay requires a lowercase SHA-256 digest")
	}
	raw, err := io.ReadAll(io.LimitReader(input, (16<<20)+1))
	if err != nil {
		return out, err
	}
	if len(raw) == 0 || len(raw) > 16<<20 || raw[len(raw)-1] != '\n' {
		return out, fmt.Errorf("SecCheck replay requires a complete batch of at most 16 MiB")
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != expected {
		return out, fmt.Errorf("SecCheck replay digest mismatch")
	}
	groups := map[string][]IngestEvent{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	count := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		count++
		if count > 4096 {
			return out, fmt.Errorf("SecCheck replay exceeds 4096 records")
		}
		var event IngestEvent
		dec := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&event); err != nil {
			return out, fmt.Errorf("SecCheck replay line %d: %w", count, err)
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return out, fmt.Errorf("SecCheck replay line %d contains trailing data", count)
		}
		if err := validateSecCheckReplayEvent(event, uploader.Registration.Namespace); err != nil {
			return out, fmt.Errorf("SecCheck replay line %d: %w", count, err)
		}
		groups[event.RunID] = append(groups[event.RunID], event)
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	err = store.WithWriteTx(ctx, db, func(tx *sql.Tx) error {
		for _, run := range keys {
			at := time.Now().UTC()
			connection := fmt.Sprintf("spool:%s:%x", expected, sha256.Sum256([]byte(run)))
			marker, err := MapSecCheckRecord(run, seccheck.Record{Registration: uploader.Registration,
				ConnectionID: connection, ReceivedAt: at, Kind: "stream", Reason: "historical_spool_replayed"})
			if err != nil {
				return err
			}
			receipt := SecCheckReplayReceipt{SchemaVersion: SecCheckReplaySchema,
				ReceiptID: fmt.Sprintf("evt-seccheck-%x", sha256.Sum256([]byte(marker.RawEventID))),
				Uploader:  uploader.Registration, AuthorityBasis: "local_operator_registration",
				FileSHA256: expected, SizeBytes: len(raw), Records: len(groups[run]),
				EventIDs: []string{}, ReceivedAt: at.Format(time.RFC3339Nano)}
			for _, event := range groups[run] {
				if err := ctx.Err(); err != nil {
					return err
				}
				id, duplicate, err := ingestSecCheckEvent(tx, event)
				if err != nil {
					return err
				}
				receipt.EventIDs = append(receipt.EventIDs, id)
				if duplicate {
					receipt.Duplicates++
				} else {
					receipt.Ingested++
					record, err := eventRecordByID(tx, id)
					if err != nil {
						return err
					}
					if err := updateNativeWindows(tx, record); err != nil {
						return err
					}
				}
			}
			old, err := eventRecordByID(tx, receipt.ReceiptID)
			if err == nil {
				var body struct {
					Receipt SecCheckReplayReceipt `json:"spool_replay"`
				}
				if err := json.Unmarshal([]byte(old.Payload), &body); err != nil {
					return err
				}
				previous := body.Receipt
				comparison := receipt
				comparison.ReceivedAt, comparison.Ingested, comparison.Duplicates = previous.ReceivedAt, previous.Ingested, previous.Duplicates
				if receipt.Ingested != 0 || old.RunID != run || ValidateSecCheckStoredEvent(old) != nil || !reflect.DeepEqual(comparison, previous) {
					return fmt.Errorf("conflicting or incomplete SecCheck replay receipt")
				}
				out.Receipts = append(out.Receipts, SecCheckReplayDelivery{RunID: run, SecCheckReplayReceipt: previous})
				out.Reused = append(out.Reused, receipt.ReceiptID)
				continue
			}
			if err != sql.ErrNoRows {
				return err
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal([]byte(marker.Payload), &body); err != nil {
				return err
			}
			body["spool_replay"], err = json.Marshal(receipt)
			if err != nil {
				return err
			}
			payload, err := json.Marshal(body)
			if err != nil {
				return err
			}
			marker.Payload = string(payload)
			if _, _, err := ingestSecCheckEvent(tx, marker); err != nil {
				return err
			}
			out.Receipts = append(out.Receipts, SecCheckReplayDelivery{RunID: run, SecCheckReplayReceipt: receipt})
		}
		return nil
	})
	if err != nil {
		return SecCheckReplayResult{}, err
	}
	return out, nil
}

func validateSecCheckReplayEvent(event IngestEvent, namespace string) error {
	e, err := readSecCheckEvidence(event.Payload)
	if err != nil {
		return err
	}
	if e.Registration.Namespace != namespace || event.RolloutID != "" || event.AttemptID != "" || event.SnapshotID != "" || event.BindingSource != "" || event.CaptureCgroupID != "" {
		return fmt.Errorf("SecCheck replay source is outside the registered namespace or carries extra bindings")
	}
	if e.Reason == "historical_spool_replayed" {
		return fmt.Errorf("SecCheck replay receipts are not captured spool observations")
	}
	if err := ValidateRawPayload(event.EventType, event.Payload); err != nil {
		return err
	}
	return ValidateSecCheckStoredEvent(EventRecord{RunID: event.RunID, SessionID: event.SessionID,
		ToolCallID: event.ToolCallID, ProcessID: event.ProcessID, RawEventID: event.RawEventID,
		ContainerID: event.ContainerID, CgroupID: event.CgroupID, Source: event.Source,
		PID: event.PID, TGID: event.TGID, PPID: event.PPID, Payload: event.Payload,
		CreatedAt: event.Timestamp, CorrelationMethod: "runtime_scope"})
}

// ReadSecCheckReplayReceipt returns delivery metadata without altering its
// historical event references. Readers may encounter legacy nested envelopes.
func ReadSecCheckReplayReceipt(payload string) (*SecCheckReplayReceipt, error) {
	for i := 0; i < 8; i++ {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(payload), &fields); err != nil {
			return nil, err
		}
		if inner, ok := fields["payload"]; ok {
			payload = string(inner)
			continue
		}
		raw, ok := fields["spool_replay"]
		if !ok {
			return nil, nil
		}
		var receipt SecCheckReplayReceipt
		if err := json.Unmarshal(raw, &receipt); err != nil {
			return nil, err
		}
		return &receipt, nil
	}
	return nil, fmt.Errorf("SecCheck replay payload nesting exceeds limit")
}

func validateSecCheckReplayReceipt(event EventRecord, evidence SecCheckEvidence) error {
	receipt, err := ReadSecCheckReplayReceipt(event.Payload)
	if err != nil {
		return err
	}
	if receipt == nil && evidence.Reason != "historical_spool_replayed" {
		return nil
	}
	if receipt == nil || evidence.Kind != "stream" || evidence.Reason != "historical_spool_replayed" {
		return fmt.Errorf("SecCheck replay receipt is missing or attached to an execution observation")
	}
	digest, err := hex.DecodeString(receipt.FileSHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != receipt.FileSHA256 ||
		receipt.SchemaVersion != SecCheckReplaySchema || receipt.AuthorityBasis != "local_operator_registration" ||
		receipt.Uploader != evidence.Registration ||
		receipt.ReceiptID != event.ID || receipt.ReceivedAt != event.CreatedAt ||
		receipt.SizeBytes <= 0 || receipt.SizeBytes > 16<<20 || receipt.Records <= 0 || receipt.Records > 4096 ||
		receipt.Ingested < 0 || receipt.Duplicates < 0 || receipt.Ingested+receipt.Duplicates != receipt.Records || len(receipt.EventIDs) != receipt.Records {
		return fmt.Errorf("invalid SecCheck replay receipt")
	}
	for _, id := range receipt.EventIDs {
		if len(id) != len("evt-seccheck-")+64 || id[:len("evt-seccheck-")] != "evt-seccheck-" || id == event.ID {
			return fmt.Errorf("invalid SecCheck replay event reference")
		}
		if _, err := hex.DecodeString(id[len("evt-seccheck-"):]); err != nil {
			return err
		}
	}
	return nil
}
