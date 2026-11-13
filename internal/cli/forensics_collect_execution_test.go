package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
)

func TestReadExecutionAdmissionValidatesIndependentSource(t *testing.T) {
	r := handoff.Request{SchemaVersion: handoff.SchemaVersion,
		Source: handoff.Source{ProducerID: "mac", Namespace: "user", RunID: "run", Harness: "fixture", SessionID: "s", ToolCallID: "t"},
		Target: handoff.Target{ProducerID: "vm", InstanceID: "i", Generation: "g"}, DispatchID: "d", OperationID: "o", ValidUntil: time.Now().Add(time.Hour), Command: handoff.Command{Argv: []string{"true"}}}
	normal, _, hash, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	a := daemon.ExecutionAdmission{SchemaVersion: handoff.SchemaVersion, Attempt: handoff.Attempt{SchemaVersion: handoff.SchemaVersion, ID: "attempt", LocalRunID: "remote-run", Request: normal, RequestHash: hash, DigestVersion: handoff.DigestVersion}}
	path := filepath.Join(t.TempDir(), "admission.json")
	write := func(v any) {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(a)
	if got, err := readExecutionAdmission(path); err != nil || got.Attempt.RequestHash != hash {
		t.Fatalf("admission: %+v %v", got, err)
	}
	a.Attempt.Request.Source.SessionID = "other-session"
	write(a)
	if _, err := readExecutionAdmission(path); err == nil {
		t.Fatal("changed admission request accepted")
	}
	write(map[string]any{"schema_version": handoff.DeliverySchema, "manifest": a})
	if _, err := readExecutionAdmission(path); err == nil {
		t.Fatal("package used as independent admission")
	}
}

func TestExecutionCollectionRequiresEndpointBeforeOpeningStore(t *testing.T) {
	dataDir, url := filepath.Join(t.TempDir(), "not-created"), ""
	cmd := forensicsCollectExecutionCmd(&dataDir, &url)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"unused.json", "--execution-config", "config.json", "--receiver", "receiver", "--sign-key", "key", "--pub-key", "pub", "--operation", "collect"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("collection without endpoint accepted")
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatal("invalid collection created a local store")
	}
}
