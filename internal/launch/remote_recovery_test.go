package launch

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestRemoteCaptureWaitingConfiguration(t *testing.T) {
	x := newRemoteFixture(t)
	policy, _ := agentcontext.NewCapturePolicy("detailed", nil)
	yes, no := true, false
	for _, test := range []struct {
		name     string
		native   bool
		explicit *bool
		want     bool
	}{
		{"separate_default", false, nil, false},
		{"native_default", true, nil, true},
		{"explicit_wait", false, &yes, true},
		{"explicit_early", true, &no, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config RemoteExecutionConfig
			if err := readRouteJSON(x.config, &config, 64<<10); err != nil {
				t.Fatal(err)
			}
			executionPath := filepath.Join(filepath.Dir(x.config), config.ExecutionConfig)
			var execution handoff.Config
			if err := readRouteJSON(executionPath, &execution, 64<<10); err != nil {
				t.Fatal(err)
			}
			execution.Capture = nil
			if test.native {
				execution.Capture = &handoff.CaptureConfig{Mode: "native"}
			}
			if err := saveRouteJSON(executionPath, execution, true); err != nil {
				t.Fatal(err)
			}
			config.WaitCapture = test.explicit
			if err := saveRouteJSON(x.config, config, true); err != nil {
				t.Fatal(err)
			}
			path, err := prepareRemoteRoute(Options{RemoteExecution: x.config, SelfExe: "/agentprov"}, x.paths, test.name, policy)
			if err != nil {
				t.Fatal(err)
			}
			route, err := ReadRemoteRoute(path)
			if err != nil || route.WaitCapture != test.want {
				t.Fatalf("wait capture: got %v want %v err=%v", route.WaitCapture, test.want, err)
			}
		})
	}
}

func TestNativeRemoteCaptureMismatchCanRecoverSameRequest(t *testing.T) {
	x := newRemoteFixture(t)
	route, err := ReadRemoteRoute(x.route)
	if err != nil {
		t.Fatal(err)
	}
	route.WaitCapture = true
	if err := saveRouteJSON(x.route, route, true); err != nil {
		t.Fatal(err)
	}
	command := "printf 'once\\n' >> effects.txt; printf 'saved-result\\n'"
	if _, err := PrepareClaudeRemoteCall(x.route, nativeBash("session", "mismatch", command)); err != nil {
		t.Fatal(err)
	}
	request := preparedCalls(t, x.route)[0]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	_, err = ExecuteRemoteCall(ctx, x.route, request, command, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "set wait_capture=false") || ctx.Err() != nil {
		t.Fatalf("capture mismatch did not produce a useful diagnosis before timeout: %v", err)
	}
	route.WaitCapture = false
	if err := saveRouteJSON(x.route, route, true); err != nil {
		t.Fatal(err)
	}
	code, err := ExecuteRemoteCall(ctx, x.route, request, command, &stdout, &stderr)
	if err != nil || code != 0 || stdout.String() != "saved-result\n" {
		t.Fatalf("recovery: %d %v %q", code, err, stdout.String())
	}
	effects, err := os.ReadFile(filepath.Join(route.Config.Workdir, "effects.txt"))
	if err != nil || string(effects) != "once\n" {
		t.Fatalf("recovery reexecuted command: %q %v", effects, err)
	}
}

func TestNativeRemoteReplayUsesDeliveredCheckpoint(t *testing.T) {
	for _, failure := range []string{"none", "ack_request_lost", "ack_response_lost"} {
		t.Run(failure, func(t *testing.T) {
			var acknowledgments atomic.Int32
			x := remoteFixtureWithTransport(t, record.Options{AllowShell: true}, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if strings.HasSuffix(r.URL.Path, "/receipt") && acknowledgments.Add(1) == 1 && failure != "none" {
					if failure == "ack_response_lost" {
						saved := httptest.NewRecorder()
						next.ServeHTTP(saved, r)
						if saved.Code != http.StatusOK {
							t.Errorf("persisting ACK: %d %s", saved.Code, saved.Body.String())
						}
					}
					http.Error(w, "lost acknowledgment", http.StatusServiceUnavailable)
					return
				}
				next.ServeHTTP(w, r)
			})
			route, err := ReadRemoteRoute(x.route)
			if err != nil {
				t.Fatal(err)
			}
			command := "printf 'once\\n' >> effects.txt; printf 'saved-result\\n'; exit 7"
			if _, err := PrepareClaudeRemoteCall(x.route, nativeBash("session", "call", command)); err != nil {
				t.Fatal(err)
			}
			request := preparedCalls(t, x.route)[0]
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			code, err := ExecuteRemoteCall(ctx, x.route, request, command, &stdout, &stderr)
			if failure == "none" {
				if err != nil || code != 7 || stdout.String() != "saved-result\n" {
					t.Fatalf("first call: exit=%d err=%v stdout=%q stderr=%q", code, err, stdout.String(), stderr.String())
				}
			} else if err == nil || !strings.Contains(err.Error(), "receipt_persisted") {
				t.Fatalf("ACK loss was not reported: %v", err)
			}
			var admission daemon.ExecutionAdmission
			if err := readRouteJSON(strings.TrimSuffix(request, ".json")+"-admission.json", &admission, 2<<20); err != nil {
				t.Fatal(err)
			}
			collectionPath := strings.TrimSuffix(request, ".json") + "-collection.json"
			var first daemon.ExecutionCollection
			if err := readRouteJSON(collectionPath, &first, 2<<20); err != nil {
				t.Fatal(err)
			}
			before, err := x.server.Execution.Ledger.Report(ctx, x.server.ExecutionCaller, admission.Attempt.ID)
			if err != nil || before.Checkpoint == nil || before.Attempt.State.Capture != handoff.Draining {
				t.Fatalf("initial checkpoint: %+v %v", before, err)
			}
			if err := x.stop(); err != nil {
				t.Fatal(err)
			}
			// Model collector completion after the first immutable package was
			// received. The receiver has never received this newer checkpoint.
			advanceRemoteCapture(t, x, before)
			x.stop, err = x.server.Execution.Start(ctx)
			if err != nil {
				t.Fatal(err)
			}
			latest, err := x.server.Execution.Ledger.Report(ctx, x.server.ExecutionCaller, admission.Attempt.ID)
			if err != nil || latest.CheckpointRef == before.CheckpointRef || latest.Attempt.State.Capture != handoff.Sealed {
				t.Fatalf("new checkpoint: %+v %v", latest, err)
			}
			local, err := store.Open(x.paths)
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			var missing handoff.Checkpoint
			if err := provenance.ReadObjectPayload(local, admission.Attempt.LocalRunID, latest.CheckpointRef, &missing); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("fixture unexpectedly has the latest remote checkpoint: %v", err)
			}
			for range 2 {
				stdout.Reset()
				stderr.Reset()
				code, err := ExecuteRemoteCall(ctx, x.route, request, command, &stdout, &stderr)
				if err != nil || code != 7 || stdout.String() != "saved-result\n" || !strings.Contains(stderr.String(), "capture=draining delivery=acknowledged") {
					t.Fatalf("replay: exit=%d err=%v stdout=%q stderr=%q", code, err, stdout.String(), stderr.String())
				}
				if !strings.Contains(stderr.String(), "returned saved delivery version 1") ||
					!strings.Contains(stderr.String(), "latest remote status: execution=failed capture=sealed") {
					t.Fatalf("historical delivery and latest status were not distinguished: %q", stderr.String())
				}
				var received daemon.ExecutionCollection
				if err := readRouteJSON(collectionPath, &received, 2<<20); err != nil {
					t.Fatal(err)
				}
				if received.DeliveryID != first.DeliveryID || received.ManifestSHA256 != first.ManifestSHA256 ||
					received.BundleSHA256 != first.BundleSHA256 || !bytes.Equal(received.Receipt, first.Receipt) {
					t.Fatal("recovery replaced the original delivery or receipt")
				}
			}
			effects, err := os.ReadFile(filepath.Join(route.Config.Workdir, "effects.txt"))
			if err != nil || string(effects) != "once\n" {
				t.Fatalf("recovery repeated command side effects: %q %v", effects, err)
			}
			for _, table := range []string{"execution_attempts", "tool_calls", "execution_deliveries"} {
				var count int
				if err := x.server.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 1 {
					t.Fatalf("recovery duplicated %s: count=%d err=%v", table, count, err)
				}
			}
		})
	}
}

func advanceRemoteCapture(t *testing.T, x *remoteFixture, r handoff.Report) {
	t.Helper()
	c := *r.Checkpoint
	c.State = r.Attempt.State
	c.State.Capture = handoff.Sealed
	c.Revision, c.Reason, c.At = r.Attempt.Revision+1, "capture_finished", time.Now().UTC()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	err = store.WithWriteTx(context.Background(), x.server.DB, func(tx *sql.Tx) error {
		_, err := (provenance.ObjectStore{DB: x.server.DB, Paths: x.server.Paths, Tx: tx}).PutExternalObject(provenance.ExternalObjectInput{
			Type: "execution_checkpoint", RunID: r.Attempt.LocalRunID,
			SourceID: fmt.Sprintf("%s/%020d", r.Attempt.ID, c.Revision), Parents: []string{r.CheckpointRef}, Payload: payload,
		})
		if err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE execution_attempts SET capture_state=?,revision=?,updated_at_ns=? WHERE id=?`,
			c.State.Capture, c.Revision, c.At.UnixNano(), c.AttemptID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
