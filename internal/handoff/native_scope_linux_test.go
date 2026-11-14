//go:build linux && (amd64 || arm64)

package handoff

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

// This checks a real cgroup's lifetime with a synthetic collector boundary.
// TestLiveExecutorSealsNativeCapture separately exercises the actual sensor.
type ownedScopeBoundary struct {
	fixtureBoundary
	db   *sql.DB
	path string
}

func (b *ownedScopeBoundary) Checkpoint(ctx context.Context, callback func(sensor.CaptureBoundary) error) (sensor.CaptureBoundary, error) {
	if b.sequence != 0 {
		var attempt string
		if err := b.db.QueryRow(`SELECT attempt_id FROM execution_context_bindings WHERE root_pid>0 LIMIT 1`).Scan(&attempt); err != nil {
			return sensor.CaptureBoundary{}, err
		}
		parent := os.Getenv("AGENTPROV_CGROUP_PARENT")
		if parent == "" {
			parent = "/sys/fs/cgroup/agentprov"
		}
		b.path = filepath.Join(parent, attempt)
		if _, err := os.Stat(filepath.Join(b.path, "cgroup.events")); err != nil {
			return sensor.CaptureBoundary{}, fmt.Errorf("scope released before end boundary: %w", err)
		}
	}
	return b.fixtureBoundary.Checkpoint(ctx, callback)
}

func TestLinuxExecutorRetainsScopeDuringCapture(t *testing.T) {
	if os.Getenv("AGENTPROV_TEST_EXECUTION_CAPTURE") != "1" {
		t.Skip("set AGENTPROV_TEST_EXECUTION_CAPTURE=1 with delegated cgroup v2 permissions")
	}
	e, p, request := testExecutor(t)
	stream, err := telemetry.NewNativeStream(e.Ledger.DB, e.Paths, telemetry.NativeStreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	boundary := &ownedScopeBoundary{db: e.Ledger.DB}
	e.Capture = &NativeCapture{Checkpointer: boundary, Stream: stream,
		Capabilities: func() sensor.CapabilityReport { return sensor.CapabilityReport{Ready: true} }}
	a, _, err := e.Ledger.Admit(context.Background(), p, request)
	if err != nil {
		t.Fatal(err)
	}
	stop := startExecutor(t, e)
	r := waitCapture(t, e, p, a.ID)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if r.Attempt.State.Capture != Sealed || r.Checkpoint.Capture.End == nil {
		t.Fatalf("scope lifetime: state=%s capture=%+v", r.Attempt.State.Capture, r.Checkpoint.Capture)
	}
	if boundary.path == "" {
		t.Fatal("end boundary did not inspect the owned scope")
	}
	if _, err := os.Stat(boundary.path); !os.IsNotExist(err) {
		t.Fatalf("scope not released after capture: %v", err)
	}
	t.Log("owned cgroup present at end boundary and removed after capture")
}
