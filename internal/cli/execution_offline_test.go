package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type offlineExecutionFixture struct {
	root, config, admission string
	sender                  *handoff.DeliveryService
	principal               handoff.Principal
	attempt                 handoff.Attempt
	packageOne              handoff.Delivery
}

func offlineExecution(t *testing.T) offlineExecutionFixture {
	t.Helper()
	root, configPath := sealCLIConfig(t)
	for _, name := range []string{"sender", "receiver"} {
		pub, key, _, err := attest.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		for suffix, value := range map[string][]byte{".key": key, ".pub": pub} {
			if err := os.WriteFile(filepath.Join(root, name+suffix), []byte(hex.EncodeToString(value)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	config, err := handoff.ReadConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	paths, err := store.Init(filepath.Join(root, "sender-store"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ledger := handoff.Ledger{DB: db, Target: config.Target}
	principal := config.Principal()
	request := handoff.Request{SchemaVersion: handoff.SchemaVersion,
		Source: handoff.Source{ProducerID: principal.ProducerID, Namespace: principal.Namespace,
			RunID: "caller-run", Harness: "fixture", SessionID: "session", ToolCallID: "call"},
		Target: config.Target, DispatchID: "dispatch", OperationID: "operation", ValidUntil: time.Now().Add(time.Hour),
		Command: handoff.Command{Argv: []string{"printf", "offline evidence"}, DisableSnapshot: true, PostRootGraceMS: 1}}
	attempt, _, err := ledger.Admit(context.Background(), principal, request)
	if err != nil {
		t.Fatal(err)
	}
	admission := filepath.Join(root, "admission.json")
	raw, err = json.Marshal(daemon.ExecutionAdmission{SchemaVersion: handoff.SchemaVersion, Attempt: attempt})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(admission, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	executor := &handoff.Executor{Ledger: ledger, Paths: paths, PollInterval: time.Millisecond}
	stop, err := executor.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stop() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		report, err := ledger.Report(context.Background(), principal, attempt.ID)
		if err != nil {
			t.Fatal(err)
		}
		if report.Attempt.State.Execution == handoff.Succeeded && report.Checkpoint != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("command did not finish: %+v", report)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	sender, err := config.DeliveryService(root, ledger, paths)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := sender.Prepare(context.Background(), principal, attempt.ID, "stop-package")
	if err != nil {
		t.Fatal(err)
	}
	return offlineExecutionFixture{root, configPath, admission, sender, principal, attempt, first}
}

func (f offlineExecutionFixture) collect(t *testing.T, pkg handoff.Delivery, extra ...string) (daemon.ExecutionCollection, error) {
	t.Helper()
	args := []string{"--data-dir", filepath.Join(f.root, "receiver-store"), "--lang", "zh-CN", "forensics", "collect-execution", f.admission,
		"--execution-config", f.config, "--receiver", "receiver", "--sign-key", filepath.Join(f.root, "receiver.key"),
		"--pub-key", filepath.Join(f.root, "sender.pub"), "--package-dir", filepath.Dir(pkg.BundlePath)}
	cmd := NewRootCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append(args, extra...))
	err := cmd.Execute()
	var result daemon.ExecutionCollection
	if err == nil {
		if e := json.Unmarshal(output.Bytes(), &result); e != nil {
			t.Fatalf("collection JSON: %s: %v", output.String(), e)
		}
	}
	return result, err
}

func (f offlineExecutionFixture) acknowledge(t *testing.T, delivery string, receipt []byte, extra ...string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append([]string{"--data-dir", f.sender.Paths.Root, "forensics", "acknowledge-execution", delivery, path,
		"--execution-config", f.config}, extra...))
	return cmd.Execute()
}

func TestExecutionOfflineRoundTrip(t *testing.T) {
	f := offlineExecution(t)
	first, err := f.collect(t, f.packageOne)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "receipt_persisted" || first.DeliveryID != f.packageOne.Manifest.ID || first.LocalRunID != f.attempt.LocalRunID ||
		first.ManifestSHA256 != f.packageOne.ManifestSHA256 || first.BundleSHA256 != f.packageOne.Manifest.BundleSHA256 || len(first.Receipt) == 0 {
		t.Fatalf("offline collection identity/status: %+v", first)
	}
	before, err := f.sender.Ledger.Get(context.Background(), f.principal, f.attempt.ID)
	if err != nil || before.State.Delivery != handoff.Transferring {
		t.Fatalf("receiver collection prematurely acknowledged sender: %+v %v", before, err)
	}
	retry, err := f.collect(t, f.packageOne)
	if err != nil || !bytes.Equal(first.Receipt, retry.Receipt) {
		t.Fatalf("lost receipt retry changed signed receipt: %+v %v", retry, err)
	}
	if err := f.acknowledge(t, first.DeliveryID, first.Receipt); err != nil {
		t.Fatal(err)
	}
	if err := f.acknowledge(t, first.DeliveryID, first.Receipt); err != nil {
		t.Fatal(err)
	}
	after, err := f.sender.Ledger.Get(context.Background(), f.principal, f.attempt.ID)
	if err != nil || after.State.Delivery != handoff.Acknowledged || after.State.Execution != before.State.Execution || after.State.Capture != before.State.Capture {
		t.Fatalf("sender receipt/state: %+v %v", after, err)
	}
	if err := f.acknowledge(t, first.DeliveryID, []byte(`{"payload":"forged"}`)); err == nil {
		t.Fatal("forged receipt accepted after acknowledgment")
	}
}

func TestExecutionOfflinePredecessorAndTransportBoundaries(t *testing.T) {
	f := offlineExecution(t)
	second, _, err := f.sender.Prepare(context.Background(), f.principal, f.attempt.ID, "later-package")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.collect(t, second); err == nil || !strings.Contains(err.Error(), "predecessor") {
		t.Fatalf("missing predecessor accepted: %v", err)
	}
	for _, test := range []struct {
		extra []string
		want  string
	}{{[]string{"--daemon-url", "http://127.0.0.1:1"}, "exactly one"}, {[]string{"--operation", "ignored"}, "applies only"}} {
		if _, err := f.collect(t, f.packageOne, test.extra...); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("mixed/ambiguous transport: %v: %v", test.extra, err)
		}
	}
	first, err := f.collect(t, f.packageOne)
	if err != nil {
		t.Fatal(err)
	}
	last, err := f.collect(t, second)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.acknowledge(t, second.Manifest.ID, first.Receipt); err == nil {
		t.Fatal("earlier receipt acknowledged a later package")
	}
	if err := f.acknowledge(t, second.Manifest.ID, last.Receipt, "--daemon-url", "http://127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "requires the stopped local store") {
		t.Fatalf("local receipt command accepted remote transport: %v", err)
	}
	if err := f.acknowledge(t, second.Manifest.ID, last.Receipt); err != nil {
		t.Fatal(err)
	}
	current, err := f.sender.Ledger.Get(context.Background(), f.principal, f.attempt.ID)
	if err != nil || current.State.Delivery != handoff.Transferring {
		t.Fatalf("unacknowledged predecessor was hidden: %+v %v", current, err)
	}
	if err := f.acknowledge(t, f.packageOne.Manifest.ID, first.Receipt); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionOfflineRejectsUntrustedOrDamagedPackages(t *testing.T) {
	f := offlineExecution(t)
	for _, name := range []string{"bad-signature", "oversized-envelope", "missing-body", "changed-body", "wrong-key", "wrong-receiver", "wrong-call"} {
		t.Run(name, func(t *testing.T) {
			pkg := f.packageOne
			pkg.BundlePath = filepath.Join(t.TempDir(), "bundle.json")
			for _, file := range []string{"bundle.json", "manifest.dsse.json"} {
				raw, err := os.ReadFile(filepath.Join(filepath.Dir(f.packageOne.BundlePath), file))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(pkg.BundlePath), file), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			changed := f
			var extra []string
			switch name {
			case "bad-signature", "oversized-envelope":
				body := []byte(`{"payload":"forged"}`)
				if name == "oversized-envelope" {
					body = bytes.Repeat([]byte("x"), handoff.MaxEnvelopeBytes+1)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(pkg.BundlePath), "manifest.dsse.json"), body, 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing-body":
				if err := os.Remove(pkg.BundlePath); err != nil {
					t.Fatal(err)
				}
			case "changed-body":
				body, err := os.ReadFile(pkg.BundlePath)
				if err != nil {
					t.Fatal(err)
				}
				body[len(body)/2] ^= 1
				if err := os.WriteFile(pkg.BundlePath, body, 0o600); err != nil {
					t.Fatal(err)
				}
			case "wrong-key":
				extra = []string{"--pub-key", filepath.Join(f.root, "receiver.pub")}
			case "wrong-receiver":
				extra = []string{"--receiver", "another-receiver"}
			case "wrong-call":
				admission, err := readExecutionAdmission(f.admission)
				if err != nil {
					t.Fatal(err)
				}
				admission.Attempt.Request.Source.ToolCallID = "another-call"
				request, _, hash, err := admission.Attempt.Request.Canonical()
				if err != nil {
					t.Fatal(err)
				}
				admission.Attempt.Request, admission.Attempt.RequestHash = request, hash
				raw, err := json.Marshal(admission)
				if err != nil {
					t.Fatal(err)
				}
				changed.admission = filepath.Join(t.TempDir(), "different-admission.json")
				if err := os.WriteFile(changed.admission, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := changed.collect(t, pkg, extra...); err == nil {
				t.Fatal("invalid package was received")
			}
		})
	}
	paths, err := store.Init(filepath.Join(f.root, "receiver-store"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var receipts int
	if err := db.QueryRow("SELECT count(*) FROM execution_delivery_receipts").Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("failed imports persisted receipts: %d %v", receipts, err)
	}
}
