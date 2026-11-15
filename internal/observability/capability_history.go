package observability

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const CapabilityIntervalSchema = "agentprovenance.sensor_capability_interval/v1"

type CapabilityInterval struct {
	SchemaVersion string                  `json:"schema_version"`
	RunID         string                  `json:"run_id"`
	StartedAt     time.Time               `json:"started_at"`
	EndedAt       time.Time               `json:"ended_at"`
	Basis         string                  `json:"basis"`
	Report        sensor.CapabilityReport `json:"report"`
	BatchID       string                  `json:"batch_id,omitempty"`
	ReceiverID    string                  `json:"receiver_id,omitempty"`
	WindowSealed  *bool                   `json:"window_sealed,omitempty"`
}

// Saved changes are scoped by the capture lifecycle, never by a reader's clock
// or current health. Each interval is a separate CAS object for bounded readers.
func SaveCapabilityHistory(ctx context.Context, db *sql.DB, paths store.Paths, run string, first, last sensor.CapabilityReport, start, end time.Time) (sensor.CapabilityHistoryRange, error) {
	return saveCapabilityHistory(ctx, provenance.ObjectStore{DB: db, Paths: paths}, run, first, last, start, end,
		CapabilityInterval{Basis: "recorded_capability_changes"})
}

// Native streams can attribute events after the workload exits. Persist the
// original collector window in the same transaction as its row receipts.
func NativeCaptureObserver(db *sql.DB, paths store.Paths) telemetry.NativeCaptureObserver {
	return func(ctx context.Context, tx *sql.Tx, run string, window telemetry.NativeCaptureWindow) error {
		if window.SchemaVersion != telemetry.NativeCaptureWindowSchema || window.BatchID == "" || window.StreamID == "" || run == "" || window.StartedAt.IsZero() {
			return fmt.Errorf("invalid native capture window")
		}
		prefix := "sensor-window/" + window.BatchID + "/"
		var saved bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM provenance_objects WHERE run_id=? AND object_type='sensor_capability_interval' AND source_id>=? AND source_id<?)`, run, prefix, "sensor-window/"+window.BatchID+"0").Scan(&saved); err != nil {
			return err
		}
		if saved {
			return nil
		}
		sealed := !window.EndedAt.IsZero()
		end := window.EndedAt
		if !sealed {
			var err error
			end, err = time.Parse(time.RFC3339Nano, window.Last.UpdatedAt)
			if err != nil {
				return err
			}
			if end.Before(window.StartedAt) {
				end = window.StartedAt
			}
		}
		_, err := saveCapabilityHistory(ctx, provenance.ObjectStore{DB: db, Paths: paths, Tx: tx}, run,
			window.First, window.Last, window.StartedAt, end, CapabilityInterval{
				Basis: "collector_receive_window", BatchID: window.BatchID, ReceiverID: window.StreamID, WindowSealed: &sealed})
		return err
	}
}

func saveCapabilityHistory(ctx context.Context, objects provenance.ObjectStore, run string, first, last sensor.CapabilityReport, start, end time.Time, template CapabilityInterval) (sensor.CapabilityHistoryRange, error) {
	return sensor.WalkCapabilityChanges(ctx, objects.Paths.Logs, first, last, start, end, func(report sensor.CapabilityReport, from, until time.Time) error {
		value := template
		value.SchemaVersion, value.RunID, value.StartedAt, value.EndedAt, value.Report = CapabilityIntervalSchema, run, from, until, report
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		var payload map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			return err
		}
		source := fmt.Sprintf("sensor-capability/%s/%s", report.CollectorID, strconv.FormatUint(report.Revision, 10))
		if value.BatchID != "" {
			source = "sensor-window/" + value.BatchID + "/" + strconv.FormatUint(report.Revision, 10)
		}
		_, err = objects.PutExternalObject(provenance.ExternalObjectInput{
			Type: "sensor_capability_interval", SourceID: source, RunID: run, Payload: payload})
		return err
	})
}
