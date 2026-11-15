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
)

const CapabilityIntervalSchema = "agentprovenance.sensor_capability_interval/v1"

type CapabilityInterval struct {
	SchemaVersion string                  `json:"schema_version"`
	RunID         string                  `json:"run_id"`
	StartedAt     time.Time               `json:"started_at"`
	EndedAt       time.Time               `json:"ended_at"`
	Basis         string                  `json:"basis"`
	Report        sensor.CapabilityReport `json:"report"`
}

// Saved changes are scoped by the capture lifecycle, never by a reader's clock
// or current health. Each interval is a separate CAS object for bounded readers.
func SaveCapabilityHistory(ctx context.Context, db *sql.DB, paths store.Paths, run string, first, last sensor.CapabilityReport, start, end time.Time) (sensor.CapabilityHistoryRange, error) {
	return sensor.WalkCapabilityChanges(ctx, paths.Logs, first, last, start, end, func(report sensor.CapabilityReport, from, until time.Time) error {
		value := CapabilityInterval{SchemaVersion: CapabilityIntervalSchema, RunID: run, StartedAt: from, EndedAt: until,
			Basis: "recorded_capability_changes", Report: report}
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
		_, err = (provenance.ObjectStore{DB: db, Paths: paths}).PutExternalObject(provenance.ExternalObjectInput{
			Type: "sensor_capability_interval", SourceID: fmt.Sprintf("sensor-capability/%s/%s", report.CollectorID, strconv.FormatUint(report.Revision, 10)), RunID: run, Payload: payload})
		return err
	})
}
