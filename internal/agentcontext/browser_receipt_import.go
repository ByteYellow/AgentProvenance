package agentcontext

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

const BrowserOwnedCaptureVersion = "agentprovenance.browser_owned_capture/v1"
const BrowserReceiptBindingVersion = "agentprovenance.browser_receipt_binding/v1"

// BrowserLocalImportConfig is operator configuration, never transcript input.
// The external manifest pin is the authority: the operator must acquire it from
// its launcher/collector, not by hashing an arbitrary agent-supplied manifest.
// Directory permissions alone do not authenticate a same-UID bridge process.
type BrowserLocalImportConfig struct {
	Directory          string                 `json:"directory"`
	ManifestName       string                 `json:"manifest_name"`
	ManifestSHA256     string                 `json:"manifest_sha256"`
	RunID              string                 `json:"run_id"`
	Placement          BrowserBridgePlacement `json:"placement"`
	BridgeID           string                 `json:"bridge_id"`
	BridgeConfigDigest string                 `json:"bridge_config_digest"`
}

type BrowserOwnedLog struct {
	Name        string       `json:"name"`
	Scope       BrowserScope `json:"scope"`
	PrefixBytes int64        `json:"prefix_bytes"`
	SHA256      string       `json:"sha256"`
}

// A manifest seals complete physical lines. A subsequent append requires a new
// operator pin before it can support a receipt; reads never execute an action.
type BrowserOwnedManifest struct {
	SchemaVersion      string                 `json:"schema_version"`
	RunID              string                 `json:"run_id"`
	Placement          BrowserBridgePlacement `json:"placement"`
	BridgeID           string                 `json:"bridge_id"`
	BridgeConfigDigest string                 `json:"bridge_config_digest"`
	Logs               []BrowserOwnedLog      `json:"logs"`
}

// BrowserReceiptBinding is portable evidence about a successful local check.
// Decoding this JSON does not create a VerifiedBrowserReceipt capability.
type BrowserReceiptBinding struct {
	SchemaVersion      string                             `json:"schema_version"`
	Authentication     string                             `json:"authentication"`
	Basis              string                             `json:"basis"`
	RunID              string                             `json:"run_id"`
	Scope              BrowserScope                       `json:"scope"`
	TargetID           string                             `json:"target_id"`
	OperationID        string                             `json:"operation_id"`
	Action             string                             `json:"action"`
	ReceiptDigest      string                             `json:"receipt_digest"`
	ManifestSHA256     string                             `json:"manifest_sha256"`
	BridgeID           string                             `json:"bridge_id"`
	BridgeConfigDigest string                             `json:"bridge_config_digest"`
	VerifiedSourceRefs map[string]BrowserReceiptSourceRef `json:"verified_source_refs"`
}

type VerifiedBrowserReceipt struct {
	bound *BrowserReceiptBinding
	raw   json.RawMessage
}

func (v *VerifiedBrowserReceipt) Verified() bool { return v != nil && v.bound != nil }

func (v *VerifiedBrowserReceipt) Binding() BrowserReceiptBinding {
	if !v.Verified() {
		return BrowserReceiptBinding{}
	}
	value := *v.bound
	value.VerifiedSourceRefs = make(map[string]BrowserReceiptSourceRef, len(v.bound.VerifiedSourceRefs))
	for key, ref := range v.bound.VerifiedSourceRefs {
		value.VerifiedSourceRefs[key] = ref
	}
	return value
}

func (v *VerifiedBrowserReceipt) Receipt() BrowserReceipt {
	var value BrowserReceipt
	if v.Verified() {
		_ = json.Unmarshal(v.raw, &value)
	}
	return value
}

func (v *VerifiedBrowserReceipt) UnmarshalJSON([]byte) error {
	v.bound, v.raw = nil, nil
	return browserImportError("binding_requires_reverification")
}

type OwnedBrowserCapture struct {
	config   BrowserLocalImportConfig
	manifest BrowserOwnedManifest
	logs     []*ownedBrowserJournal
}

func browserImportError(code string) error { return errors.New("browser_import_" + code) }

func browserBytesDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func browserLocalName(name string) bool {
	return notebookIDValid(name) && name != "." && name != ".." && !strings.ContainsAny(name, "/\\:")
}

func browserPlacement(scope BrowserScope) BrowserBridgePlacement {
	return BrowserBridgePlacement{scope.ProducerID, scope.Namespace, scope.InstanceID, scope.Generation}
}

func strictBrowserJSON(raw []byte, value any) bool {
	if !nativeResultJSON(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value) == nil
}

// ImportOwnedBrowserCapture snapshots only configured, pinned local files.
// Receipt authentication is separate from Parse's retained source assertions.
func ImportOwnedBrowserCapture(ctx context.Context, cfg BrowserLocalImportConfig) (*OwnedBrowserCapture, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	placement := BrowserScope{ProducerID: cfg.Placement.ProducerID, Namespace: cfg.Placement.Namespace,
		InstanceID: cfg.Placement.InstanceID, Generation: cfg.Placement.Generation, BrowserID: "check", ContextID: "check"}
	if !filepath.IsAbs(cfg.Directory) || filepath.Clean(cfg.Directory) != cfg.Directory ||
		!browserLocalName(cfg.ManifestName) || !browserSHA256(cfg.ManifestSHA256, true) ||
		!notebookIDValid(cfg.RunID) || !placement.valid() || !notebookIDValid(cfg.BridgeID) || !browserSHA256(cfg.BridgeConfigDigest, true) {
		return nil, browserImportError("invalid_config")
	}
	directory, err := openBrowserOwnedDirectory(cfg.Directory)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	raw, err := readBrowserOwnedFile(ctx, directory, cfg.ManifestName, 0, 64<<10)
	if err != nil {
		return nil, err
	}
	if browserBytesDigest(raw) != cfg.ManifestSHA256 {
		return nil, browserImportError("manifest_digest_mismatch")
	}
	var manifest BrowserOwnedManifest
	if !strictBrowserJSON(raw, &manifest) || manifest.SchemaVersion != BrowserOwnedCaptureVersion ||
		manifest.RunID != cfg.RunID || manifest.Placement != cfg.Placement || manifest.BridgeID != cfg.BridgeID ||
		manifest.BridgeConfigDigest != cfg.BridgeConfigDigest || len(manifest.Logs) == 0 || len(manifest.Logs) > 64 {
		return nil, browserImportError("manifest_binding_mismatch")
	}
	result := &OwnedBrowserCapture{config: cfg, manifest: manifest}
	names, scopes := map[string]bool{}, map[BrowserScope]bool{}
	var total int64
	for _, file := range manifest.Logs {
		if !browserLocalName(file.Name) || !strings.HasSuffix(file.Name, ".jsonl") || names[file.Name] || scopes[file.Scope] ||
			!file.Scope.valid() || browserPlacement(file.Scope) != cfg.Placement ||
			file.PrefixBytes <= 0 || file.PrefixBytes > MaxInputBytes || !browserSHA256(file.SHA256, true) {
			return nil, browserImportError("invalid_log_manifest")
		}
		total += file.PrefixBytes
		if total > 256<<20 {
			return nil, browserImportError("history_budget_exceeded")
		}
		names[file.Name], scopes[file.Scope] = true, true
		data, err := readBrowserOwnedFile(ctx, directory, file.Name, file.PrefixBytes, MaxInputBytes)
		if err != nil {
			return nil, err
		}
		if browserBytesDigest(data) != file.SHA256 {
			return nil, browserImportError("log_digest_mismatch")
		}
		journal, err := readOwnedBrowserJournal(ctx, file, data)
		if err != nil {
			return nil, err
		}
		result.logs = append(result.logs, journal)
	}
	if err := checkBrowserOwnedDirectory(directory, cfg.Directory); err != nil {
		return nil, err
	}
	if _, err := result.ParsedCaptures(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

// ParsedCaptures returns fresh projections; modifying one cannot change the
// immutable bytes used by VerifyReceipt. No serialized trust fields are added.
func (c *OwnedBrowserCapture) ParsedCaptures(ctx context.Context) ([]Parsed, error) {
	if c == nil || len(c.logs) == 0 {
		return nil, browserImportError("capture_not_verified")
	}
	var out []Parsed
	for _, log := range c.logs {
		parsed, err := Parse(ctx, bytes.NewReader(log.data), ParseOptions{Harness: "browser", Binding: "exact",
			Path:            filepath.Join(c.config.Directory, log.file.Name),
			BindingEvidence: []string{BrowserLocalOperatorEvidence, "browser_owned_manifest:" + c.config.ManifestSHA256}})
		if err != nil {
			return nil, err
		}
		if parsed.Coverage.Status != OK && parsed.Coverage.Status != Partial {
			return nil, browserImportError("journal_parse_failed")
		}
		for _, issue := range parsed.Coverage.Issues {
			if issue.Code != "browser_capture_gap" {
				return nil, browserImportError("journal_parse_incomplete")
			}
		}
		out = append(out, parsed)
	}
	return out, nil
}
