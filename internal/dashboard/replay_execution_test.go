package dashboard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
)

type replayExecutionFixture struct {
	server           Server
	source           handoff.Source
	run, entry, tool string
}

func signedReplayExecution(t *testing.T) replayExecutionFixture {
	t.Helper()
	ctx := context.Background()
	paths, db, _ := artifactStore(t)
	receiverPaths, receiverDB, _ := artifactStore(t)
	source := handoff.Source{ProducerID: "caller", Namespace: "router", RunID: "caller-run", Harness: "codex", SessionID: "selected", ToolCallID: "native-call"}
	target := handoff.Target{ProducerID: "worker", InstanceID: "vm", Generation: "generation-1"}
	principal := handoff.Principal{ID: "router", ProducerID: source.ProducerID, Namespace: source.Namespace, AllowedTargets: []handoff.Target{target}}
	request := handoff.Request{SchemaVersion: handoff.SchemaVersion, Source: source, Target: target,
		DispatchID: "dispatch", OperationID: "operation", ValidUntil: time.Now().UTC().Add(time.Hour),
		Command: handoff.Command{Argv: []string{"printf", "EXECUTION-CHECKPOINT-COMMAND"}, Workdir: t.TempDir(), DisableSnapshot: true, PostRootGraceMS: 1}}
	ledger := handoff.Ledger{DB: db, Target: target}
	attempt, _, err := ledger.Admit(ctx, principal, request)
	if err != nil {
		t.Fatal(err)
	}
	executor := handoff.Executor{Ledger: ledger, Paths: paths, PollInterval: 5 * time.Millisecond}
	executor.Options.WorkspaceRoot = request.Command.Workdir
	stop, err := executor.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	var report handoff.Report
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		report, err = ledger.Report(ctx, principal, attempt.ID)
		if err != nil {
			t.Fatal(err)
		}
		if report.Attempt.State.Execution == handoff.Succeeded || report.Attempt.State.Execution == handoff.Failed {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if report.Attempt.State.Execution != handoff.Succeeded || report.Checkpoint == nil {
		t.Fatalf("execution: %+v checkpoint: %+v", report, report.Checkpoint)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiverPub, receiverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiver := handoff.DeliveryReceiver{DB: receiverDB, Paths: receiverPaths, ID: "reader", SignKey: receiverKey, Target: target, TargetKey: pub, Caller: principal}
	receiver.SourceAdmissionRef, err = receiver.RecordAdmission(ctx, request, report.Attempt)
	if err != nil {
		t.Fatal(err)
	}
	sender := handoff.DeliveryService{Ledger: ledger, Paths: paths, SignKey: key, ReceiverID: receiver.ID, ReceiverKey: receiverPub}
	delivery, _, err := sender.Prepare(ctx, principal, attempt.ID, "delivery")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.Open(delivery.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	_, receiveErr := receiver.Receive(ctx, handoff.IdentityOf(report.Attempt), delivery.Envelope, bundle)
	closeErr := bundle.Close()
	if receiveErr != nil || closeErr != nil {
		t.Fatalf("receive: %v %v", receiveErr, closeErr)
	}
	service := agentcontext.Service{DB: receiverDB, Paths: receiverPaths}
	for _, session := range []string{"selected", "private"} {
		body := `{"cmd":"SOURCE-` + session + `-CALL-BODY"}`
		_, err := service.Save(ctx, source.RunID, agentcontext.Source{Harness: source.Harness, SessionID: session, Binding: "explicit", ParserVersion: "fixture/v1"},
			[]agentcontext.Record{{Key: "call", Sequence: 1, Kind: "tool_call", ToolCallID: source.ToolCallID, ToolName: "exec_command", Body: &body}}, agentcontext.Coverage{Status: agentcontext.OK})
		if err != nil {
			t.Fatal(err)
		}
	}
	message := "EXECUTION-KEPT-MESSAGE"
	_, err = service.Save(ctx, attempt.LocalRunID, agentcontext.Source{Harness: "codex", SessionID: "worker", Binding: "explicit", ParserVersion: "fixture/v1"},
		[]agentcontext.Record{{Key: "message", Sequence: 1, Kind: "message", Role: "user", Body: &message}}, agentcontext.Coverage{Status: agentcontext.OK})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hooksbridge.IngestContext(ctx, receiverDB, receiverPaths, source.RunID); err != nil {
		t.Fatal(err)
	}
	page, err := service.Entries(ctx, agentcontext.PageOptions{RunID: source.RunID, Harness: source.Harness, SessionID: source.SessionID})
	if err != nil || len(page.Entries) != 1 {
		t.Fatalf("caller entries: %+v %v", page, err)
	}
	var tool string
	if err := receiverDB.QueryRow(`SELECT to_id FROM graph_edges WHERE run_id=? AND from_id=? AND edge_type='context_tool_call'`, source.RunID, page.Entries[0].ObjectHash).Scan(&tool); err != nil {
		t.Fatal(err)
	}
	return replayExecutionFixture{Server{DB: receiverDB}, source, attempt.LocalRunID, "entry/" + page.Entries[0].ID, "2/" + tool}
}

func readReplayExecutionLinks(t *testing.T, files map[string][]byte, run, direction string) []handoff.ExecutionLink {
	t.Helper()
	wrapper := string(files["assets/catalog.js"])
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(wrapper, `window.AgentProvOfflineCatalog="`), `";`))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Runs map[string]struct {
			ExecutionLinks *struct {
				SchemaVersion string `json:"schema_version"`
				Directions    map[string][]struct {
					Count int            `json:"count"`
					Data  staticdata.Ref `json:"data"`
				} `json:"directions"`
			} `json:"execution_links"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	index := catalog.Runs[run].ExecutionLinks
	if index == nil || index.SchemaVersion != "agentprovenance.replay_execution_links/v1" {
		t.Fatalf("missing offline execution index for %s", run)
	}
	shards, ok := index.Directions[direction]
	if !ok {
		t.Fatalf("missing direction %s", direction)
	}
	links := []handoff.ExecutionLink{}
	for _, shard := range shards {
		var page []handoff.ExecutionLink
		if err := json.Unmarshal(files[strings.TrimSuffix(shard.Data.Path, ".json.gz")+".js"], &page); err != nil {
			t.Fatal(err)
		}
		if len(page) != shard.Count {
			t.Fatal("shard count mismatch")
		}
		links = append(links, page...)
	}
	return links
}

func TestOfflineExecutionLinksSignedSelection(t *testing.T) {
	f := signedReplayExecution(t)
	caller := ReplaySelection{RunID: f.source.RunID, Scope: "whole_run"}
	worker := ReplaySelection{RunID: f.run, Scope: "whole_run"}
	for _, name := range []string{"whole", "caller-only", "worker-only", "caller-session", "other-session", "excluded-entry", "excluded-tool", "excluded-tools", "partial-worker"} {
		t.Run(name, func(t *testing.T) {
			a, b := caller, worker
			inputs := []ReplaySelection{a, b}
			switch name {
			case "caller-only":
				inputs = []ReplaySelection{a}
			case "worker-only":
				inputs = []ReplaySelection{b}
			case "caller-session":
				inputs[0].Scope, inputs[0].Harness, inputs[0].SessionID = "session", f.source.Harness, f.source.SessionID
			case "other-session":
				inputs[0].Scope, inputs[0].Harness, inputs[0].SessionID = "session", f.source.Harness, "private"
			case "excluded-entry":
				inputs[0].ExcludeRecords = []string{f.entry}
			case "excluded-tool":
				inputs[0].ExcludeRecords = []string{f.tool}
			case "excluded-tools":
				inputs[0].ExcludeCategories = []string{"tools"}
			case "partial-worker":
				inputs[1].ExcludeCategories = []string{"tools", "files", "runtime"}
			}
			p, err := f.server.PrepareOfflineReplaySet(context.Background(), inputs)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			files, all := replayZIPData(t, p)
			var outgoing, incoming []handoff.ExecutionLink
			if name != "worker-only" {
				outgoing = readReplayExecutionLinks(t, files, f.source.RunID, "outgoing")
			}
			if name != "caller-only" {
				incoming = readReplayExecutionLinks(t, files, f.run, "incoming")
			}
			excluded := strings.HasPrefix(name, "excluded-") || name == "other-session"
			if excluded {
				if len(outgoing) != 0 || len(incoming) != 1 || incoming[0].Admission != nil || incoming[0].Basis != "unanchored_delivery" || !slices.Contains(incoming[0].Issues, "source_call_excluded_by_selection") {
					t.Fatalf("excluded source: %+v %+v", outgoing, incoming)
				}
				if strings.Contains(all, "SOURCE-selected-CALL-BODY") {
					t.Fatal("excluded caller body leaked")
				}
			} else if name == "caller-only" {
				if len(outgoing) != 1 || outgoing[0].Admission == nil || outgoing[0].Manifest != nil || outgoing[0].Receipt != nil || outgoing[0].Checkpoint != nil || !slices.Contains(outgoing[0].Issues, "execution_run_not_selected") {
					t.Fatalf("caller boundary: %+v", outgoing)
				}
				if strings.Contains(all, "EXECUTION-CHECKPOINT-COMMAND") || strings.Contains(all, "EXECUTION-KEPT-MESSAGE") {
					t.Fatal("unselected execution content leaked")
				}
			} else if name == "worker-only" {
				if len(incoming) != 1 || incoming[0].Admission != nil || incoming[0].Basis != "unanchored_delivery" || !slices.Contains(incoming[0].Issues, "source_run_not_selected") {
					t.Fatalf("worker boundary: %+v", incoming)
				}
				if strings.Contains(all, "SOURCE-selected-CALL-BODY") || strings.Contains(all, "SOURCE-private-CALL-BODY") {
					t.Fatal("unselected caller content leaked")
				}
			} else {
				if len(incoming) != 1 || len(outgoing) != 1 || !reflect.DeepEqual(incoming, outgoing) || outgoing[0].Basis != "authenticated_delivery" {
					t.Fatalf("bidirectional links: %+v %+v", outgoing, incoming)
				}
				link := outgoing[0]
				if link.Identity.Source != f.source || link.Identity.LocalRunID != f.run || link.Admission == nil || link.Manifest == nil || link.Receipt == nil || link.AdmissionRef == "" || link.DeliveryRef == "" {
					t.Fatalf("lost authenticated identity: %+v", link)
				}
				if name == "partial-worker" {
					if link.Checkpoint != nil || !slices.Contains(link.Issues, "checkpoint_excluded_by_selection") || strings.Contains(all, "EXECUTION-CHECKPOINT-COMMAND") || !strings.Contains(all, "EXECUTION-KEPT-MESSAGE") {
						t.Fatal("partial execution bypassed selection through checkpoint")
					}
				} else if link.Checkpoint == nil {
					t.Fatal("whole execution lost checkpoint")
				}
				if name == "caller-session" && strings.Contains(all, "SOURCE-private-CALL-BODY") {
					t.Fatal("same native call ID widened session selection")
				}
			}
			writeReplaySetFixture(t, "execution-"+name+".zip", p)
		})
	}
}

func TestOfflineExecutionLinksUseFrozenSource(t *testing.T) {
	f := signedReplayExecution(t)
	ctx := context.Background()
	snapshot, err := f.server.freezeReplaySource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if _, err := f.server.DB.Exec(`DELETE FROM provenance_objects WHERE object_type='execution_delivery_evidence'`); err != nil {
		t.Fatal(err)
	}
	p, err := f.server.prepareReplaySet(ctx, snapshot, []ReplaySelection{{RunID: f.source.RunID, Scope: "whole_run"}, {RunID: f.run, Scope: "whole_run"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := f.server.DB.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := replayZIPData(t, p)
	links := readReplayExecutionLinks(t, files, f.source.RunID, "outgoing")
	if len(links) != 1 || links[0].Basis != "authenticated_delivery" {
		t.Fatalf("link escaped export snapshot: %+v", links)
	}
}

func TestOfflineExecutionLinksRejectCorruptedEvidence(t *testing.T) {
	f := signedReplayExecution(t)
	var path string
	if err := f.server.DB.QueryRow(`SELECT path FROM provenance_objects WHERE object_type='execution_delivery_evidence'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(path), []byte(`{"tampered":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if p, err := f.server.PrepareOfflineReplaySet(context.Background(), []ReplaySelection{{RunID: f.source.RunID, Scope: "whole_run"}, {RunID: f.run, Scope: "whole_run"}}); err == nil || p != nil {
		if p != nil {
			p.Close()
		}
		t.Fatalf("invalid proof published: %v", err)
	}
}

func TestOfflineExecutionLinksPagination(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	target := handoff.Target{ProducerID: "worker", InstanceID: "vm", Generation: "one"}
	source := handoff.Source{ProducerID: "caller", Namespace: "router", RunID: "source", Harness: "codex", SessionID: "session", ToolCallID: "call"}
	principal := handoff.Principal{ID: "router", ProducerID: source.ProducerID, Namespace: source.Namespace, AllowedTargets: []handoff.Target{target}}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiver := handoff.DeliveryReceiver{DB: db, Paths: paths, ID: "reader", Target: target, TargetKey: pub, SignKey: key, Caller: principal}
	ledger := handoff.Ledger{DB: db, Target: target}
	for i := 0; i < 51; i++ {
		r := handoff.Request{SchemaVersion: handoff.SchemaVersion, Source: source, Target: target, DispatchID: fmt.Sprintf("dispatch-%d", i), OperationID: fmt.Sprintf("op-%d", i), ValidUntil: time.Now().Add(time.Hour), Command: handoff.Command{Argv: []string{"printf", "not executed"}}}
		a, _, err := ledger.Admit(ctx, principal, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.RecordAdmission(ctx, r, a); err != nil {
			t.Fatal(err)
		}
	}
	p, err := (Server{DB: db}).PrepareOfflineReplaySet(ctx, []ReplaySelection{{RunID: source.RunID, Scope: "whole_run"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	files, _ := replayZIPData(t, p)
	links := readReplayExecutionLinks(t, files, source.RunID, "outgoing")
	seen := map[string]bool{}
	for _, link := range links {
		seen[link.Identity.AttemptID] = true
	}
	if len(links) != 51 || len(seen) != 51 {
		t.Fatalf("pagination: %d links / %d attempts", len(links), len(seen))
	}
}
