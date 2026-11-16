//go:build linux || darwin

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func browserCLIJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func browserCLIHash(raw []byte) string {
	hash := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func browserCLIFixture(t *testing.T) (string, string, agentcontext.BrowserLocalImportConfig) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	owned, receiver := filepath.Join(root, "capture"), filepath.Join(root, "receiver")
	for _, directory := range []string{owned, receiver} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	scope := agentcontext.BrowserScope{ProducerID: "p", Namespace: "n", InstanceID: "i", Generation: "original", BrowserID: "b", ContextID: "c"}
	at := "2026-11-16T00:00:00Z"
	inputHash := browserCLIHash([]byte(`{"action":"click","selector":"__redacted__"}`))
	resultHash := browserCLIHash([]byte(`{"output":{},"output_truncated":false}`))
	header := map[string]any{"type": "browser_session", "schema_version": agentcontext.BrowserCaptureVersion, "timestamp": at,
		"producer_id": "p", "namespace": "n", "instance_id": "i", "generation": "original", "browser_id": "b", "context_id": "c"}
	journal := append(browserCLIJSON(t, header), '\n')
	refs := map[string]agentcontext.BrowserReceiptSourceRef{}
	for _, phase := range []string{"accept", "start", "end"} {
		payload := map[string]any{}
		if phase == "accept" {
			payload = map[string]any{"schema_version": agentcontext.BrowserReceiptVersion, "normalized_input_digest": inputHash,
				"input_digest_basis": "privacy_projected_input/v1", "input_redactions": []string{"selector"}, "sequence": 1, "capture_epoch": "b"}
		}
		event := map[string]any{"type": "browser_event", "schema_version": agentcontext.BrowserCaptureVersion, "timestamp": at,
			"context_id": "c", "target_id": "page", "target_type": "page", "cdp_session_id": "cdp", "operation_id": "op", "operation": "click",
			"event_id": phase, "kind": "action_" + phase, "payload": payload}
		line := append(browserCLIJSON(t, event), '\n')
		refs[phase] = agentcontext.BrowserReceiptSourceRef{Log: "browser.jsonl", EventID: phase, SHA256: browserCLIHash(line)[7:]}
		journal = append(journal, line...)
	}
	receipt := agentcontext.BrowserReceipt{SchemaVersion: agentcontext.BrowserReceiptVersion, Scope: scope, TargetID: "page", OperationID: "op", Action: "click",
		NormalizedInputDigest: inputHash, InputDigestBasis: "privacy_projected_input/v1", InputRedactions: []string{"selector"},
		AcceptedAt: at, StartedAt: &at, EndedAt: &at, Sequence: 1, CaptureEpoch: "b", Outcome: "ok", GapRefs: []string{}, SourceRefs: refs, ResultDigest: &resultHash,
		BridgeIdentity: &agentcontext.BrowserBridgeIdentity{Source: "local_bridge_configuration", Authentication: "unverified", TranscriptIdentity: "source_asserted_only",
			Identity: agentcontext.BrowserBridgePlacement{ProducerID: "p", Namespace: "n", InstanceID: "i", Generation: "original"}}}
	// This fixture is ASCII-only; sorted maps match the Python canonical form.
	var fields map[string]any
	_ = json.Unmarshal(browserCLIJSON(t, receipt), &fields)
	receipt.Digest = browserCLIHash(browserCLIJSON(t, fields))
	cfg := agentcontext.BrowserLocalImportConfig{Directory: owned, ManifestName: "browser-owned.json", RunID: "run", Placement: receipt.BridgeIdentity.Identity,
		BridgeID: "fixture-bridge", BridgeConfigDigest: browserCLIHash([]byte("fixture-config"))}
	manifest := agentcontext.BrowserOwnedManifest{SchemaVersion: agentcontext.BrowserOwnedCaptureVersion, RunID: cfg.RunID, Placement: cfg.Placement,
		BridgeID: cfg.BridgeID, BridgeConfigDigest: cfg.BridgeConfigDigest,
		Logs: []agentcontext.BrowserOwnedLog{{Name: "browser.jsonl", Scope: scope, PrefixBytes: int64(len(journal)), SHA256: browserCLIHash(journal)}}}
	cfg.ManifestSHA256 = browserCLIHash(browserCLIJSON(t, manifest))
	configPath, receiptPath := filepath.Join(receiver, "config.json"), filepath.Join(owned, "receipts.json")
	for path, raw := range map[string][]byte{configPath: browserCLIJSON(t, cfg), receiptPath: browserCLIJSON(t, []agentcontext.BrowserReceipt{receipt}),
		filepath.Join(owned, cfg.ManifestName): browserCLIJSON(t, manifest), filepath.Join(owned, "browser.jsonl"): journal} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return configPath, receiptPath, cfg
}

func TestContextOwnedBrowserImportCLI(t *testing.T) {
	config, receipts, cfg := browserCLIFixture(t)
	data := t.TempDir()
	args := []string{"import", "--run", "run", "--harness", "browser", "--browser-owned-config", config, "--browser-receipts", receipts, "--capture", "basic"}
	var previous agentcontext.BrowserOwnedImportResult
	for i := 0; i < 2; i++ {
		out, err := runContextCLI(t, data, args...)
		var result agentcontext.BrowserOwnedImportResult
		if err != nil || json.Unmarshal(out, &result) != nil || result.VerifiedReceipts != 1 || len(result.BindingRefs) != 1 {
			t.Fatalf("owned CLI import: %s %v", out, err)
		}
		if result.Bindings[0].Binding.Authentication != "verified" || result.Bindings[0].Receipt.BridgeIdentity.Authentication != "unverified" ||
			result.Bindings[0].Binding.ManifestSHA256 != cfg.ManifestSHA256 {
			t.Fatal("CLI lost the independent verification boundary")
		}
		if i > 0 && (result.Imports[0].Stored != 0 || result.BindingRefs[0] != previous.BindingRefs[0]) {
			t.Fatal("repeat CLI import duplicated evidence")
		}
		previous = result
	}
	paths, _ := store.Init(data)
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var record agentcontext.BrowserReceiptBindingRecord
	if err := provenance.ReadObjectPayload(db, "run", previous.BindingRefs[0], &record); err != nil || record.Binding.ReceiptDigest != previous.Bindings[0].Binding.ReceiptDigest {
		t.Fatalf("durable binding missing: %v", err)
	}
	plain, err := runContextCLI(t, data, "import", "--run", "ordinary", "--harness", "browser", "--file", filepath.Join(cfg.Directory, "browser.jsonl"))
	if err != nil || len(plain) == 0 {
		t.Fatal("ordinary import regressed")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id='ordinary' AND object_type='browser_receipt_binding'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("ordinary source import acquired authentication")
	}
}

func TestContextOwnedBrowserImportRejectsArtifactAuthority(t *testing.T) {
	for _, mode := range []string{"inside_capture", "wrong_pin", "wrong_run", "source_override", "missing_config", "tampered_receipt"} {
		t.Run(mode, func(t *testing.T) {
			config, receipts, cfg := browserCLIFixture(t)
			args := []string{"import", "--run", "run", "--harness", "browser", "--browser-owned-config", config, "--browser-receipts", receipts}
			switch mode {
			case "inside_capture":
				config = filepath.Join(cfg.Directory, "self-trust.json")
				if err := os.WriteFile(config, browserCLIJSON(t, cfg), 0o600); err != nil {
					t.Fatal(err)
				}
				args[6] = config
			case "wrong_pin":
				cfg.ManifestSHA256 = browserCLIHash([]byte("another"))
				if err := os.WriteFile(config, browserCLIJSON(t, cfg), 0o600); err != nil {
					t.Fatal(err)
				}
			case "wrong_run":
				args[2] = "another"
			case "source_override":
				args = append(args, "--file", filepath.Join(cfg.Directory, "browser.jsonl"))
			case "missing_config":
				args[6] = ""
			case "tampered_receipt":
				raw, _ := os.ReadFile(receipts)
				var list []map[string]any
				_ = json.Unmarshal(raw, &list)
				list[0]["result_digest"] = browserCLIHash([]byte("another"))
				delete(list[0], "digest")
				list[0]["digest"] = browserCLIHash(browserCLIJSON(t, list[0]))
				if err := os.WriteFile(receipts, browserCLIJSON(t, list), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := runContextCLI(t, t.TempDir(), args...); err == nil {
				t.Fatal("untrusted import reported success")
			}
		})
	}
}
