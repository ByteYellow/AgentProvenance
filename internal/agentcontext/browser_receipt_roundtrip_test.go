package agentcontext_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestBrowserReceiptSignedRoundtripAndSelection(t *testing.T) {
	ctx := context.Background()
	src := forkRoundtripService(t)
	policy, _ := agentcontext.NewCapturePolicy("basic", nil)
	src.CapturePolicy = &policy
	scope := agentcontext.BrowserScope{ProducerID: "p", Namespace: "n", InstanceID: "i", Generation: "original", BrowserID: "b", ContextID: "c"}
	at := "2026-11-16T00:00:00Z"
	hash := "sha256:" + strings.Repeat("1", 64)
	ref := agentcontext.BrowserOperation{Scope: scope, TargetID: "page", OperationID: "op", Operation: "click"}
	// These digest claims are deliberately not authenticated by parsing. Bundle
	// signing authenticates this retained evidence object, not the bridge author.
	receipt := agentcontext.BrowserReceipt{
		SchemaVersion: agentcontext.BrowserReceiptVersion, Scope: scope, TargetID: ref.TargetID, OperationID: ref.OperationID, Action: ref.Operation,
		NormalizedInputDigest: hash, InputDigestBasis: "privacy_projected_input/v1", InputRedactions: []string{"selector"},
		AcceptedAt: at, StartedAt: &at, EndedAt: &at, Sequence: 1, CaptureEpoch: "b", Outcome: "ok", GapRefs: []string{},
		SourceRefs: map[string]agentcontext.BrowserReceiptSourceRef{
			"accept": {Log: "browser.jsonl", EventID: "accept", SHA256: strings.Repeat("2", 64)},
			"start":  {Log: "browser.jsonl", EventID: "start", SHA256: strings.Repeat("3", 64)},
			"end":    {Log: "browser.jsonl", EventID: "end", SHA256: strings.Repeat("4", 64)},
		},
		ResultDigest: &hash, Digest: hash,
		BridgeIdentity: &agentcontext.BrowserBridgeIdentity{Source: "local_bridge_configuration", Authentication: "verified", TranscriptIdentity: "source_asserted_only",
			Identity: agentcontext.BrowserBridgePlacement{ProducerID: "p", Namespace: "n", InstanceID: "i", Generation: "original"}},
	}
	line := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw) + "\n"
	}
	header := map[string]any{"schema_version": agentcontext.BrowserCaptureVersion, "type": "browser_session",
		"producer_id": "p", "namespace": "n", "instance_id": "i", "generation": "original", "browser_id": "b", "context_id": "c", "timestamp": at}
	event := func(id, kind string, payload any) string {
		return line(map[string]any{"schema_version": agentcontext.BrowserCaptureVersion, "type": "browser_event", "event_id": id, "kind": kind,
			"context_id": "c", "target_id": "page", "target_type": "page", "cdp_session_id": "cdp", "operation_id": "op", "operation": "click", "timestamp": at, "payload": payload})
	}
	admission := map[string]any{"schema_version": agentcontext.BrowserReceiptVersion, "normalized_input_digest": hash, "input_digest_basis": "privacy_projected_input/v1",
		"input_redactions": []string{"selector"}, "sequence": 1, "capture_epoch": "b"}
	journal := line(header) + event("accept", "action_accept", admission) + event("start", "action_start", map[string]any{}) +
		event("end", "action_end", map[string]any{}) + event("result", "action_result", receipt)
	response := map[string]any{"schema_version": agentcontext.BrowserToolResultVersion, "operation": "execute", "browser_operation": ref,
		"browser_receipt": receipt, "execution_status": "ok", "output": map[string]any{}}
	transcript := line(map[string]any{"session_id": "agent", "hook_event_name": "PreToolUse", "tool_use_id": "call", "tool_name": "browser_execute", "tool_input": map[string]any{"action": "click"}}) +
		line(map[string]any{"session_id": "agent", "hook_event_name": "PostToolUse", "tool_use_id": "call", "tool_name": "browser_execute", "tool_response": response})
	for harness, input := range map[string]string{"browser": journal, "claude": transcript} {
		parsed, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: harness, Binding: "explicit",
			BindingEvidence: []string{agentcontext.BrowserLocalOperatorEvidence}})
		if err != nil || parsed.Coverage.Status != agentcontext.OK {
			t.Fatalf("parse receipt fixture: %s %v", parsed.Coverage.Status, err)
		}
		if _, err := src.Save(ctx, "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hooksbridge.IngestContext(ctx, src.DB, src.Paths, "run"); err != nil {
		t.Fatal(err)
	}
	before, err := src.Entries(ctx, agentcontext.PageOptions{RunID: "run", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: src.DB, Paths: src.Paths, SignKey: key}).ExportBundle("run")
	if err != nil || !bundle.Signed {
		t.Fatalf("signed export: %v", err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	src.DB.Close()
	if err := os.Rename(src.Paths.Provenance, src.Paths.Provenance+"-offline"); err != nil {
		t.Fatal(err)
	}
	dst := forkRoundtripService(t)
	if result, err := (forensics.Service{DB: dst.DB, Paths: dst.Paths}).ImportBundle(bundle.Path); err != nil || result.Omitted != 0 {
		t.Fatalf("offline import: omitted=%d err=%v", result.Omitted, err)
	}
	if verification, err := provenance.Verify(dst.DB, "run"); err != nil || verification.ErrorCount != 0 {
		t.Fatalf("offline evidence verification: %v", err)
	}
	after, err := dst.Entries(ctx, agentcontext.PageOptions{RunID: "run", Limit: 200})
	if err != nil || len(after.Entries) != len(before.Entries) {
		t.Fatal("offline entries missing")
	}
	var caller, operation agentcontext.Entry
	for i, entry := range after.Entries {
		if !reflect.DeepEqual(entry.Browser, before.Entries[i].Browser) || !reflect.DeepEqual(entry.BrowserOperation, before.Entries[i].BrowserOperation) {
			t.Fatal("signed roundtrip changed receipt metadata")
		}
		if entry.Source.Harness == "browser" && entry.Kind == "tool_call" {
			operation = entry
		}
		if entry.BrowserOperation != nil {
			caller = entry
			observation := entry.BrowserOperation.Receipt
			if observation.Authentication != "unverified" || observation.Origin != "transcript" || !reflect.DeepEqual(observation.Receipt, receipt) || entry.Content.State != "omitted" {
				t.Fatal("bundle signature or basic retention changed receipt meaning")
			}
		}
	}
	if caller.ID == "" || operation.ID == "" {
		t.Fatal("operation binding missing")
	}
	for _, excluded := range []bool{false, true} {
		selection := dashboard.ReplaySelection{RunID: "run", Scope: "whole_run"}
		if excluded {
			selection.ExcludeRecords = []string{"entry/" + operation.ID}
		}
		prepared, err := (dashboard.Server{DB: dst.DB}).PrepareOfflineReplaySet(ctx, []dashboard.ReplaySelection{selection})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		err = prepared.WriteZIP(ctx, &output)
		prepared.Close()
		if err != nil {
			t.Fatal(err)
		}
		archive, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, file := range archive.File {
			if !strings.HasPrefix(file.Name, "data/") || !strings.HasSuffix(file.Name, ".js") {
				continue
			}
			stream, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			wrapper, err := io.ReadAll(stream)
			stream.Close()
			if err != nil {
				t.Fatal(err)
			}
			prefix := `window.AgentProvOffline.accept("` + strings.TrimSuffix(file.Name, ".js") + `.json.gz","`
			if !bytes.HasPrefix(wrapper, []byte(prefix)) || !bytes.HasSuffix(wrapper, []byte(`");`)) {
				t.Fatalf("unexpected offline data wrapper: %s", file.Name)
			}
			data, err := base64.StdEncoding.DecodeString(string(wrapper[len(prefix) : len(wrapper)-3]))
			if err != nil {
				t.Fatal(err)
			}
			compressed, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(compressed)
			compressed.Close()
			if err != nil {
				t.Fatal(err)
			}
			var page struct {
				Links map[string]agentcontext.EntryLinks `json:"links"`
			}
			if json.Unmarshal(raw, &page) != nil {
				continue
			}
			links, exists := page.Links[caller.ID]
			if !exists {
				continue
			}
			found = true
			associations := 0
			for _, link := range links.Links {
				if link.Relation == "context_browser_operation" {
					associations++
				}
			}
			if excluded && (associations != 0 || links.Reason != "browser_operation_unresolved") || !excluded && associations != 1 {
				t.Fatalf("receipt bypassed selected supporting operation: excluded=%v links=%+v", excluded, links)
			}
		}
		if !found {
			t.Fatal("offline caller link index missing")
		}
	}
}
