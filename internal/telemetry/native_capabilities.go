package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const NativeCaptureWindowSchema = "agentprovenance.native_capture_window/v1"

// This is the collector's receive window, not a syscall's probe attachment
// interval. Buffered events and late bindings keep their original timestamps.
type NativeCaptureWindow struct {
	SchemaVersion string                  `json:"schema_version"`
	BatchID       string                  `json:"batch_id"`
	StreamID      string                  `json:"stream_id"`
	StartedAt     time.Time               `json:"started_at"`
	EndedAt       time.Time               `json:"ended_at,omitempty"`
	First         sensor.CapabilityReport `json:"first"`
	Last          sensor.CapabilityReport `json:"last"`
}

type NativeCaptureObserver func(context.Context, *sql.Tx, string, NativeCaptureWindow) error

// ObserveCapabilities is called by the supervisor that owns this sensor. It
// persists changes before exposing them to the spool; readers never call it.
func (n *NativeStream) ObserveCapabilities(report sensor.CapabilityReport) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.format != "native" {
		return fmt.Errorf("native capability observation requires an open native stream")
	}
	if err := sensor.SaveCapabilityChange(n.service.Paths.Logs, report); err != nil {
		return err
	}
	if n.capabilities != nil {
		previous := n.capabilities
		oldAt, _ := time.Parse(time.RFC3339Nano, previous.UpdatedAt)
		newAt, _ := time.Parse(time.RFC3339Nano, report.UpdatedAt)
		if previous.CollectorID != report.CollectorID || report.Revision < previous.Revision || newAt.Before(oldAt) {
			return fmt.Errorf("native capability collector or revision changed out of order")
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var copy sensor.CapabilityReport
	if err := json.Unmarshal(encoded, &copy); err != nil {
		return err
	}
	if n.captureWindow != nil {
		window := *n.captureWindow
		window.Last = copy
		opts := n.opts
		opts.CaptureWindow = &window
		raw, err := json.Marshal(opts)
		if err != nil {
			return err
		}
		if _, err := store.ExecRetry(context.Background(), n.service.DB,
			`UPDATE telemetry_spool_batches SET native_options=? WHERE id=? AND status='capturing'`, string(raw), n.id); err != nil {
			return err
		}
		n.captureWindow = &window
	}
	if n.capabilities == nil {
		n.capabilityStart, _ = time.Parse(time.RFC3339Nano, copy.UpdatedAt)
		n.capabilityFirst = &copy
	}
	n.capabilities = &copy
	return nil
}

func (n *NativeStream) newCaptureWindow(id string) *NativeCaptureWindow {
	if n.capabilities == nil {
		return nil
	}
	return &NativeCaptureWindow{SchemaVersion: NativeCaptureWindowSchema, BatchID: id,
		StreamID: n.producerID, StartedAt: n.capabilityStart, First: *n.capabilityFirst, Last: *n.capabilities}
}
