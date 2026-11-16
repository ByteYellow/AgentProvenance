package agentcontext

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/redact"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type BrowserReceiptBindingRecord struct {
	Binding BrowserReceiptBinding `json:"binding"`
	Receipt BrowserReceipt        `json:"receipt"`
}

type BrowserOwnedImportResult struct {
	RunID            string                        `json:"run_id"`
	ManifestSHA256   string                        `json:"manifest_sha256"`
	VerifiedReceipts int                           `json:"verified_receipts"`
	Imports          []SaveResult                  `json:"imports"`
	Bindings         []BrowserReceiptBindingRecord `json:"bindings"`
	BindingRefs      []string                      `json:"binding_refs"`
}

func readBrowserPrivateJSON(ctx context.Context, path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !browserLocalName(filepath.Base(path)) {
		return nil, browserImportError("invalid_local_path")
	}
	directory, err := openBrowserOwnedDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	raw, err := readBrowserOwnedFile(ctx, directory, filepath.Base(path), 0, limit)
	if err != nil {
		return nil, err
	}
	if err := checkBrowserOwnedDirectory(directory, filepath.Dir(path)); err != nil {
		return nil, err
	}
	return raw, nil
}

// LoadBrowserLocalImportConfig only reads an explicitly selected receiver file.
// A config shipped inside the capture directory is never an authority source.
func LoadBrowserLocalImportConfig(ctx context.Context, path string) (BrowserLocalImportConfig, error) {
	var cfg BrowserLocalImportConfig
	raw, err := readBrowserPrivateJSON(ctx, path, 64<<10)
	if err != nil {
		return cfg, err
	}
	if !strictBrowserJSON(raw, &cfg) || !filepath.IsAbs(cfg.Directory) || filepath.Clean(cfg.Directory) != cfg.Directory {
		return cfg, browserImportError("invalid_config")
	}
	relative, err := filepath.Rel(cfg.Directory, path)
	if err != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return cfg, browserImportError("receiver_config_inside_capture")
	}
	return cfg, nil
}

// LoadBrowserReceiptList reads untrusted receipt JSON, not a trust configuration.
func LoadBrowserReceiptList(ctx context.Context, path string) ([]json.RawMessage, error) {
	raw, err := readBrowserPrivateJSON(ctx, path, 4<<20)
	if err != nil {
		return nil, err
	}
	var receipts []json.RawMessage
	if !strictBrowserJSON(raw, &receipts) || len(receipts) == 0 || len(receipts) > 1024 {
		return nil, browserImportError("invalid_receipt_list")
	}
	return receipts, nil
}

// ImportOwnedBrowser validates every receipt before the first evidence write.
// The existing transaction/object store persists the raw claims and independent
// verification records together. Stored binding JSON must be reverified against
// the receiver's configuration before another process treats it as authority.
func (s Service) ImportOwnedBrowser(ctx context.Context, runID string, cfg BrowserLocalImportConfig, receipts []json.RawMessage) (BrowserOwnedImportResult, error) {
	result := BrowserOwnedImportResult{RunID: runID, ManifestSHA256: cfg.ManifestSHA256}
	if s.DB == nil || runID == "" || runID != cfg.RunID || cleanIdentifier(runID) != runID || len(receipts) == 0 || len(receipts) > 1024 {
		return result, browserImportError("invalid_import")
	}
	capture, err := ImportOwnedBrowserCapture(ctx, cfg)
	if err != nil {
		return result, err
	}
	parsed, err := capture.ParsedCaptures(ctx)
	if err != nil {
		return result, err
	}
	var total int
	var bindings []BrowserReceiptBindingRecord
	for _, raw := range receipts {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		total += len(raw)
		if total > 4<<20 {
			return result, browserImportError("receipt_budget_exceeded")
		}
		verified, err := capture.VerifyReceipt(raw)
		if err != nil {
			return result, err
		}
		bindings = append(bindings, BrowserReceiptBindingRecord{Binding: verified.Binding(), Receipt: verified.Receipt()})
	}
	result.Bindings = bindings
	result.VerifiedReceipts = len(receipts)
	err = store.WithWriteTx(ctx, s.DB, func(tx *sql.Tx) error {
		for _, input := range parsed {
			// Match Save's source privacy boundary without changing a verified
			// identity to a redacted alias inside the saved run.
			raw, err := json.Marshal(input.Source)
			if err != nil {
				return err
			}
			var source Source
			if err := json.Unmarshal([]byte(redact.RedactString(string(raw))), &source); err != nil {
				return err
			}
			if source.Browser == nil || *source.Browser != *input.Source.Browser || source.SessionID != input.Source.SessionID {
				return browserImportError("identity_redaction_conflict")
			}
			source.ID = sourceID(source)
			saved, err := s.saveTx(ctx, tx, runID, source, input.Records, input.Coverage)
			if err != nil {
				return err
			}
			result.Imports = append(result.Imports, saved)
		}
		objects := provenance.ObjectStore{DB: s.DB, Paths: s.Paths, Tx: tx}
		for _, record := range result.Bindings {
			payload, err := mapPayload(record)
			if err != nil {
				return err
			}
			object, err := objects.PutExternalObject(provenance.ExternalObjectInput{RunID: runID, Type: "browser_receipt_binding",
				SourceID: "browser-receipt-binding-" + digest(record.Binding), Payload: payload})
			if err != nil {
				return err
			}
			result.BindingRefs = append(result.BindingRefs, object.Hash)
		}
		return nil
	})
	if err != nil {
		return BrowserOwnedImportResult{RunID: runID, ManifestSHA256: cfg.ManifestSHA256}, err
	}
	return result, nil
}
