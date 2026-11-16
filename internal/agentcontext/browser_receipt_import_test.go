//go:build linux || darwin

package agentcontext

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func ownedReceiptJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ownedReceiptDigest(t *testing.T, value any) string {
	t.Helper()
	digest, err := browserValueDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func ownedReceiptFixture(t *testing.T, action string, started, finished bool) ([]byte, []byte) {
	t.Helper()
	full := receiptFixture()
	full["action"] = action
	input := map[string]any{"action": action}
	redactions := []string{}
	if action == "click" {
		input["selector"], redactions = "__redacted__", []string{"selector"}
	} else if action == "navigate" {
		input["url"], redactions = "http://example.test/path?__redacted__", []string{"url.userinfo", "url.query", "url.fragment"}
	}
	full["normalized_input_digest"], full["input_redactions"] = ownedReceiptDigest(t, input), redactions
	accept, start, end := receiptAccept(), receiptAction("start", "action_start"), receiptAction("end", "action_end")
	for _, event := range []map[string]any{accept, start, end} {
		event["operation"] = action
	}
	accept["payload"].(map[string]any)["normalized_input_digest"] = full["normalized_input_digest"]
	accept["payload"].(map[string]any)["input_redactions"] = redactions
	if action == "navigate" {
		start["payload"] = map[string]any{"url": input["url"]}
	}
	output := map[string]any{"text": "<>&\n\u4f60\u597d\U0001f680", "bytes": 12}
	end["payload"] = output
	full["accepted_at"], full["started_at"], full["ended_at"], full["result_digest"] = accept["timestamp"], nil, nil, nil
	full["outcome"], full["gap_refs"] = "unknown", []string{"result_not_recorded"}
	values := []map[string]any{browserHeader(), accept}
	if started {
		values = append(values, start)
		full["started_at"] = start["timestamp"]
	}
	if finished {
		values = append(values, end)
		full["ended_at"], full["outcome"], full["gap_refs"] = end["timestamp"], "ok", []string{}
		full["result_digest"] = ownedReceiptDigest(t, map[string]any{"output": output, "output_truncated": false})
	}
	refs := map[string]any{}
	var journal []byte
	for i, value := range values {
		line := append(ownedReceiptJSON(t, value), '\n')
		journal = append(journal, line...)
		if i > 0 {
			phase := strings.TrimPrefix(value["kind"].(string), "action_")
			refs[phase] = map[string]any{"log": "browser.jsonl", "event_id": value["event_id"], "sha256": strings.TrimPrefix(browserBytesDigest(line), "sha256:")}
		}
	}
	full["source_refs"] = refs
	delete(full, "digest")
	full["digest"] = ownedReceiptDigest(t, full)
	return journal, ownedReceiptJSON(t, full)
}

// Only test fixtures mint pins here. Production pins must come from an operator
// launcher/collector outside the source author's control.
func ownedReceiptConfig(t *testing.T, name string, journal []byte) BrowserLocalImportConfig {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	var scope BrowserScope
	if json.Unmarshal(bytes.SplitN(journal, []byte("\n"), 2)[0], &scope) != nil {
		t.Fatal("invalid fixture header")
	}
	cfg := BrowserLocalImportConfig{Directory: directory, ManifestName: "browser-owned.json", RunID: "run",
		Placement: browserPlacement(scope), BridgeID: "fixture-owned-bridge", BridgeConfigDigest: browserBytesDigest([]byte("operator-launch-config"))}
	manifest := BrowserOwnedManifest{SchemaVersion: BrowserOwnedCaptureVersion, RunID: cfg.RunID, Placement: cfg.Placement,
		BridgeID: cfg.BridgeID, BridgeConfigDigest: cfg.BridgeConfigDigest,
		Logs: []BrowserOwnedLog{{Name: name, Scope: scope, PrefixBytes: int64(len(journal)), SHA256: browserBytesDigest(journal)}}}
	for file, raw := range map[string][]byte{name: journal, cfg.ManifestName: ownedReceiptJSON(t, manifest)} {
		if err := os.WriteFile(filepath.Join(directory, file), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.ManifestSHA256 = browserBytesDigest(ownedReceiptJSON(t, manifest))
	return cfg
}

func TestBrowserReceiptCanonicalPythonContract(t *testing.T) {
	raw := []byte(`{"z":"\u4f60\u597d\ud83d\ude80<>&/\u2028\n\b\f\r\t","n":1,"a":[null,true,false]}`)
	want := `{"a":[null,true,false],"n":1,"z":"\u4f60\u597d\ud83d\ude80<>&/\u2028\n\b\f\r\t"}`
	got, err := canonicalBrowserJSON(raw)
	if err != nil || string(got) != want {
		t.Fatalf("Python canonical bytes differ: %s %v", got, err)
	}
	for _, raw := range []string{`{"n":1.5}`, `{"a":1,"a":2}`, `{"n":1e9}`, `NaN`} {
		if _, err := canonicalBrowserJSON([]byte(raw)); err == nil {
			t.Fatal("unsupported canonical input accepted")
		}
	}
}

func TestBrowserReceiptOwnedImportAuthenticatesSeparately(t *testing.T) {
	for _, action := range []string{"navigate", "click", "read_text", "screenshot"} {
		t.Run(action, func(t *testing.T) {
			journal, raw := ownedReceiptFixture(t, action, true, true)
			cfg := ownedReceiptConfig(t, "browser.jsonl", journal)
			capture, err := ImportOwnedBrowserCapture(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := capture.VerifyReceipt(raw)
			if err != nil || !verified.Verified() {
				t.Fatalf("owned receipt verification: %v", err)
			}
			binding := verified.Binding()
			if binding.Authentication != "verified" || binding.Basis != "local_operator_pinned_capture" || binding.RunID != cfg.RunID ||
				binding.ManifestSHA256 != cfg.ManifestSHA256 || len(binding.VerifiedSourceRefs) != 3 || verified.Receipt().BridgeIdentity.Authentication != "unverified" {
				t.Fatal("binding lost custody or rewrote source claims")
			}
			parsed, err := capture.ParsedCaptures(context.Background())
			if err != nil || len(parsed) != 1 || parsed[0].Records[1].Browser.Receipt.Authentication != "unverified" {
				t.Fatal("ordinary parsed receipt acquired verification authority")
			}
			body := verified.Receipt()
			body.SourceRefs["accept"] = BrowserReceiptSourceRef{}
			binding.VerifiedSourceRefs["accept"] = BrowserReceiptSourceRef{}
			if verified.Binding().VerifiedSourceRefs["accept"].EventID == "" || verified.Receipt().SourceRefs["accept"].EventID == "" {
				t.Fatal("returned mutable view changed verified state")
			}
			var restored VerifiedBrowserReceipt
			if err := json.Unmarshal(ownedReceiptJSON(t, verified.Binding()), &restored); err == nil || restored.Verified() {
				t.Fatal("serialized evidence manufactured a verified capability")
			}
			receiptEvidence(t, map[string]any{"passed": true, "binding": verified.Binding(), "source_authentication": "unverified", "fixture_operator_pin": true})
		})
	}
}

func TestBrowserReceiptOwnedImportUnknownAndSnapshot(t *testing.T) {
	for _, started := range []bool{false, true} {
		journal, raw := ownedReceiptFixture(t, "click", started, false)
		cfg := ownedReceiptConfig(t, "browser.jsonl", journal)
		capture, err := ImportOwnedBrowserCapture(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := capture.VerifyReceipt(raw)
		if err != nil || verified.Receipt().Outcome != "unknown" || verified.Receipt().EndedAt != nil || verified.Receipt().Scope.Generation != "g1" {
			t.Fatalf("unknown outcome changed: %v", err)
		}
		before, _ := os.ReadFile(filepath.Join(cfg.Directory, "browser.jsonl"))
		var workers sync.WaitGroup
		for i := 0; i < 16; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				if v, err := capture.VerifyReceipt(raw); err != nil || !reflect.DeepEqual(v.Binding(), verified.Binding()) {
					t.Error("concurrent query changed receipt")
				}
			}()
		}
		workers.Wait()
		after, _ := os.ReadFile(filepath.Join(cfg.Directory, "browser.jsonl"))
		if !bytes.Equal(before, after) {
			t.Fatal("verification wrote to journal")
		}
		// Growth beyond the pinned complete-line prefix remains outside this view.
		if err := os.WriteFile(filepath.Join(cfg.Directory, "browser.jsonl"), append(journal, []byte(`{"partial":`)...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ImportOwnedBrowserCapture(context.Background(), cfg); err != nil {
			t.Fatal("append outside pinned prefix changed historical snapshot")
		}
	}
	journal, raw := ownedReceiptFixture(t, "navigate", false, false)
	cfg := ownedReceiptConfig(t, "browser.jsonl", journal)
	capture, err := ImportOwnedBrowserCapture(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capture.VerifyReceipt(raw); err == nil || err.Error() != "browser_import_input_projection_unavailable" {
		t.Fatal("navigation admission without recorded projected URL was authenticated")
	}
}

func TestBrowserReceiptOwnedImportRejectsClaimsAndTampering(t *testing.T) {
	journal, original := ownedReceiptFixture(t, "click", true, true)
	cfg := ownedReceiptConfig(t, "browser.jsonl", journal)
	capture, err := ImportOwnedBrowserCapture(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"scope": func(r map[string]any) {
			r["scope"].(map[string]any)["generation"] = "later"
			r["bridge_identity"].(map[string]any)["identity"].(map[string]any)["generation"] = "later"
		},
		"input":  func(r map[string]any) { r["normalized_input_digest"] = browserBytesDigest([]byte("different")) },
		"result": func(r map[string]any) { r["result_digest"] = browserBytesDigest([]byte("different")) },
		"source_hash": func(r map[string]any) {
			r["source_refs"].(map[string]any)["end"].(map[string]any)["sha256"] = strings.Repeat("a", 64)
		},
		"source_id": func(r map[string]any) {
			r["source_refs"].(map[string]any)["end"].(map[string]any)["event_id"] = "another"
		},
		"source_log": func(r map[string]any) {
			r["source_refs"].(map[string]any)["end"].(map[string]any)["log"] = "other.jsonl"
		},
		"self_trust":  func(r map[string]any) { r["bridge_identity"].(map[string]any)["authentication"] = "verified" },
		"extra_field": func(r map[string]any) { r["private_extra"] = "unselected" },
		"sequence":    func(r map[string]any) { r["sequence"] = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			var fields map[string]any
			_ = json.Unmarshal(original, &fields)
			mutate(fields)
			delete(fields, "digest")
			fields["digest"] = ownedReceiptDigest(t, fields)
			if _, err := capture.VerifyReceipt(ownedReceiptJSON(t, fields)); err == nil {
				t.Fatal("self-consistent claim was not checked against owned journal")
			}
		})
	}
	for name, mutate := range map[string]func(*BrowserLocalImportConfig){
		"no_pin":     func(c *BrowserLocalImportConfig) { c.ManifestSHA256 = "" },
		"wrong_pin":  func(c *BrowserLocalImportConfig) { c.ManifestSHA256 = browserBytesDigest([]byte("other")) },
		"run":        func(c *BrowserLocalImportConfig) { c.RunID = "other" },
		"generation": func(c *BrowserLocalImportConfig) { c.Placement.Generation = "other" },
		"bridge":     func(c *BrowserLocalImportConfig) { c.BridgeID = "other" },
		"config":     func(c *BrowserLocalImportConfig) { c.BridgeConfigDigest = browserBytesDigest([]byte("other")) },
		"escape":     func(c *BrowserLocalImportConfig) { c.ManifestName = "../browser-owned.json" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := cfg
			mutate(&copy)
			if _, err := ImportOwnedBrowserCapture(context.Background(), copy); err == nil {
				t.Fatal("unconfigured origin accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ImportOwnedBrowserCapture(ctx, cfg); err != context.Canceled {
		t.Fatal("canceled import did not stop")
	}
}

func TestBrowserReceiptOwnedImportRejectsUnsafeFiles(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "fifo", "permissions", "directory_permissions", "directory_symlink", "modified", "truncated", "partial_prefix", "corrupt", "duplicate_id"} {
		t.Run(mode, func(t *testing.T) {
			journal, _ := ownedReceiptFixture(t, "click", true, true)
			if mode == "partial_prefix" {
				journal = journal[:len(journal)-1]
			} else if mode == "corrupt" {
				journal = append(journal, []byte("{broken}\n")...)
			} else if mode == "duplicate_id" {
				lines := bytes.SplitAfter(journal, []byte("\n"))
				journal = append(journal, lines[1]...)
			}
			cfg := ownedReceiptConfig(t, "browser.jsonl", journal)
			path := filepath.Join(cfg.Directory, "browser.jsonl")
			var err error
			switch mode {
			case "symlink", "hardlink", "fifo":
				other := filepath.Join(t.TempDir(), "outside.jsonl")
				if err := os.WriteFile(other, journal, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if mode == "symlink" {
					err = os.Symlink(other, path)
				} else if mode == "hardlink" {
					err = os.Link(other, path)
				} else {
					err = syscall.Mkfifo(path, 0o600)
				}
			case "permissions":
				err = os.Chmod(path, 0o644)
			case "directory_permissions":
				err = os.Chmod(cfg.Directory, 0o755)
			case "directory_symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				err = os.Symlink(cfg.Directory, alias)
				cfg.Directory = alias
			case "modified":
				err = os.WriteFile(path, bytes.ReplaceAll(journal, []byte(`"bytes":12`), []byte(`"bytes":13`)), 0o600)
			case "truncated":
				err = os.Truncate(path, int64(len(journal)-5))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ImportOwnedBrowserCapture(context.Background(), cfg); err == nil {
				t.Fatal("unsafe file imported")
			}
		})
	}
}

func TestBrowserReceiptOwnedImportPythonLiveDigests(t *testing.T) {
	directory := os.Getenv("AGENTPROV_BROWSER_LIVE_RECEIPT_DIR")
	if directory == "" {
		t.Skip("opt-in existing Python/Chrome receipt artifacts")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var results struct {
		Observations []struct {
			Result struct {
				Receipt json.RawMessage `json:"browser_receipt"`
			} `json:"result"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatal(err)
	}
	captures := map[string]*OwnedBrowserCapture{}
	count := 0
	for _, observation := range results.Observations {
		raw := observation.Result.Receipt
		if len(raw) == 0 {
			continue
		}
		var receipt BrowserReceipt
		if json.Unmarshal(raw, &receipt) != nil {
			t.Fatal("invalid live receipt")
		}
		name := receipt.SourceRefs["accept"].Log
		capture := captures[name]
		if capture == nil {
			journal, err := os.ReadFile(filepath.Join(directory, "capture", name))
			if err != nil {
				t.Fatal(err)
			}
			capture, err = ImportOwnedBrowserCapture(context.Background(), ownedReceiptConfig(t, name, journal))
			if err != nil {
				t.Fatal(err)
			}
			captures[name] = capture
		}
		verified, err := capture.VerifyReceipt(raw)
		if err != nil || !verified.Verified() || !reflect.DeepEqual(verified.Receipt(), receipt) {
			t.Fatalf("Python digest/source-ref cross-check: %v", err)
		}
		count++
	}
	if count != 10 || len(captures) != 2 {
		t.Fatalf("incomplete live coverage: receipts=%d generations=%d", count, len(captures))
	}
	receiptEvidence(t, map[string]any{"passed": true, "verified_receipts": count, "generations": len(captures), "fixture_operator_pin": true})
}

func TestBrowserReceiptOwnedServiceAtomicAndIdempotent(t *testing.T) {
	journal, receipt := ownedReceiptFixture(t, "click", true, true)
	cfg := ownedReceiptConfig(t, "browser.jsonl", journal)
	svc := testService(t)
	svc.CapturePolicy = capturePreset(t, "basic", nil)
	if _, err := svc.DB.Exec(`CREATE TRIGGER reject_browser_binding BEFORE INSERT ON provenance_objects
		WHEN NEW.object_type='browser_receipt_binding' BEGIN SELECT RAISE(ABORT, 'fixture failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportOwnedBrowser(context.Background(), "run", cfg, []json.RawMessage{receipt}); err == nil {
		t.Fatal("failed binding write reported success")
	}
	var count int
	if err := svc.DB.QueryRow(`SELECT COUNT(*) FROM agent_context_entries`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed import left context records committed")
	}
	if _, err := svc.DB.Exec(`DROP TRIGGER reject_browser_binding`); err != nil {
		t.Fatal(err)
	}
	var previous BrowserOwnedImportResult
	for i := 0; i < 2; i++ {
		result, err := svc.ImportOwnedBrowser(context.Background(), "run", cfg, []json.RawMessage{receipt})
		if err != nil || len(result.BindingRefs) != 1 || result.VerifiedReceipts != 1 {
			t.Fatalf("synchronous service import: %v", err)
		}
		if i == 1 && (result.Imports[0].Stored != 0 || !reflect.DeepEqual(result.BindingRefs, previous.BindingRefs)) {
			t.Fatal("repeated trusted import changed records or bindings")
		}
		previous = result
	}
	if err := svc.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE object_type='browser_receipt_binding'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("binding evidence was not stored independently")
	}
}
