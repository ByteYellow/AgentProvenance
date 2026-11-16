// Package browsercustody authorizes Browser/runtime mappings at the receiver's
// local configuration boundary. Imported evidence never constructs a Verified.
package browsercustody

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/browserlink"
	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const SchemaVersion = "agentprovenance.browser_runtime_custody/v1"

// Config is receiver-owned input, supplied explicitly by a local operator. Both
// this file and CaptureConfig must be outside the capture and store evidence
// directories. ReceiptDigest selects a receipt verified against the external pin.
type Config struct {
	SchemaVersion      string    `json:"schema_version"`
	CaptureConfig      string    `json:"capture_config"`
	Receipts           string    `json:"receipts"`
	RunID              string    `json:"run_id"`
	ManifestSHA256     string    `json:"manifest_sha256"`
	BridgeID           string    `json:"bridge_id"`
	BridgeConfigDigest string    `json:"bridge_config_digest"`
	Mappings           []Mapping `json:"mappings"`
}

type Mapping struct {
	Scope             browserlink.Scope `json:"scope"`
	ReceiptDigest     string            `json:"receipt_digest"`
	Role              string            `json:"role"`
	HostID            string            `json:"host_id"`
	PID               int64             `json:"pid"`
	ProcessInstanceID string            `json:"process_instance_id"`
}

type witness struct {
	log    string
	record agentcontext.Record
}

type claim struct {
	mapping   Mapping
	witnesses []witness
}

// Verified is an immutable local capability, not serializable trust evidence.
// Resolve rechecks its source records in each online/frozen/selected database.
type Verified struct {
	run    string
	claims []claim
}

func (v *Verified) RunID() string {
	if v == nil {
		return ""
	}
	return v.run
}

func (*Verified) UnmarshalJSON([]byte) error {
	return i18n.Errorf("browser custody requires local operator verification")
}

// Load verifies the receiver config, owned capture and every selected receipt.
// It never imports or modifies the evidence store or the original capture.
func Load(ctx context.Context, path string, paths store.Paths) (*Verified, error) {
	raw, err := readPrivate(ctx, path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := decodeConfig(raw, &cfg); err != nil {
		return nil, i18n.Errorf("invalid browser custody config JSON: %w", err)
	}
	if cfg.SchemaVersion != SchemaVersion || cfg.RunID == "" || len(cfg.Mappings) == 0 || len(cfg.Mappings) > 128 {
		return nil, i18n.Errorf("invalid browser custody config")
	}
	receiver, err := agentcontext.LoadBrowserLocalImportConfig(ctx, cfg.CaptureConfig)
	if err != nil {
		return nil, err
	}
	for _, auth := range []string{path, cfg.CaptureConfig} {
		for _, root := range []string{receiver.Directory, paths.Artifacts, paths.Provenance, paths.Snapshots, paths.Workspaces, paths.Spool} {
			if root != "" && inside(root, auth) {
				return nil, i18n.Errorf("browser custody authority must be outside capture and evidence directories")
			}
		}
	}
	if cfg.RunID != receiver.RunID || cfg.ManifestSHA256 != receiver.ManifestSHA256 || cfg.BridgeID != receiver.BridgeID || cfg.BridgeConfigDigest != receiver.BridgeConfigDigest {
		return nil, i18n.Errorf("browser custody capture/bridge/run mismatch")
	}
	capture, err := agentcontext.ImportOwnedBrowserCapture(ctx, receiver)
	if err != nil {
		return nil, err
	}
	receipts, err := agentcontext.LoadBrowserReceiptList(ctx, cfg.Receipts)
	if err != nil {
		return nil, err
	}
	bindings := map[string]agentcontext.BrowserReceiptBinding{}
	for _, raw := range receipts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v, err := capture.VerifyReceipt(raw)
		if err != nil {
			return nil, i18n.Errorf("browser custody receipt verification: %w", err)
		}
		if !v.Verified() {
			return nil, i18n.Errorf("browser custody requires local operator verification")
		}
		binding := v.Binding()
		bindings[binding.ReceiptDigest] = binding
	}
	parsed, err := capture.ParsedCaptures(ctx)
	if err != nil {
		return nil, err
	}
	observations := map[string][]witness{}
	for _, input := range parsed {
		log := filepath.Base(input.Source.Path)
		for _, record := range input.Records {
			if record.Browser != nil {
				key := log + "\x00" + record.Browser.EventID
				observations[key] = append(observations[key], witness{log, record})
			}
		}
	}
	result := &Verified{run: cfg.RunID}
	owners := map[string]string{}
	for _, mapping := range cfg.Mappings {
		binding, ok := bindings[mapping.ReceiptDigest]
		if !ok || binding.RunID != cfg.RunID || browserlink.Scope(binding.Scope) != mapping.Scope || binding.ManifestSHA256 != cfg.ManifestSHA256 || binding.BridgeID != cfg.BridgeID || binding.BridgeConfigDigest != cfg.BridgeConfigDigest {
			return nil, i18n.Errorf("browser custody receipt/scope mismatch")
		}
		if mapping.HostID == "" || len(mapping.HostID) > 512 || strings.TrimSpace(mapping.HostID) != mapping.HostID || mapping.ProcessInstanceID == "" || correlation.CanonicalProcessInstance(mapping.ProcessInstanceID, mapping.PID) != mapping.ProcessInstanceID {
			return nil, i18n.Errorf("browser custody requires exact host and process birth identity")
		}
		switch mapping.Role {
		case "browser", "renderer", "network":
		default:
			return nil, i18n.Errorf("unsupported browser runtime role")
		}
		key, _ := json.Marshal([]any{mapping.Scope, mapping.Role})
		process := fmt.Sprintf("%s/%s", mapping.HostID, mapping.ProcessInstanceID)
		if old, ok := owners[string(key)]; ok && old != process {
			return nil, i18n.Errorf("conflicting browser runtime custody")
		}
		owners[string(key)] = process
		c := claim{mapping: mapping}
		for _, ref := range binding.VerifiedSourceRefs {
			found := observations[ref.Log+"\x00"+ref.EventID]
			if len(found) != 1 || found[0].record.RawBody == nil {
				return nil, i18n.Errorf("browser custody source projection is ambiguous or absent")
			}
			c.witnesses = append(c.witnesses, found[0])
		}
		if len(c.witnesses) == 0 {
			return nil, i18n.Errorf("browser custody has no authenticated source references")
		}
		result.claims = append(result.claims, c)
	}
	return result, nil
}

func inside(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err != nil || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Resolve drops a mapping when selection omitted any supporting observation.
// Object corruption is an error, never a reason to accept an unverified claim.
// Other runs receive no authority from this run-specific capability.
func (v *Verified) Resolve(ctx context.Context, db *sql.DB, run string) ([]browserlink.RuntimeCustody, error) {
	if v == nil || v.run == "" || run != v.run {
		return nil, nil
	}
	var entries []agentcontext.Entry
	svc := agentcontext.Service{DB: db}
	cursor := ""
	for {
		page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: run, Harness: "browser", Cursor: cursor, Limit: 200})
		if err != nil {
			return nil, err
		}
		entries = append(entries, page.Entries...)
		if len(entries) > browserlink.MaxRecords {
			return nil, i18n.Errorf("browser custody source record limit exceeded")
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	byEvent := map[string][]agentcontext.Entry{}
	for _, e := range entries {
		if e.Browser != nil && e.Source.Browser != nil && e.ExecutionScope == agentcontext.CurrentExecution {
			key := filepath.Base(e.Source.Path) + "\x00" + e.Browser.EventID
			byEvent[key] = append(byEvent[key], e)
		}
	}
	var out []browserlink.RuntimeCustody
	for _, c := range v.claims {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		custody := browserlink.RuntimeCustody{RunID: run, Scope: c.mapping.Scope, Role: c.mapping.Role, HostID: c.mapping.HostID, PID: c.mapping.PID, ProcessInstanceID: c.mapping.ProcessInstanceID}
		complete := true
		for _, w := range c.witnesses {
			var matches []agentcontext.Entry
			for _, e := range byEvent[w.log+"\x00"+w.record.Browser.EventID] {
				if browserlink.Scope(*e.Source.Browser) == c.mapping.Scope && e.Kind == w.record.Kind && e.SourceKey == w.record.Key && e.Sequence == w.record.Sequence && e.ToolCallID == w.record.ToolCallID && e.Status == w.record.Status && reflect.DeepEqual(e.Browser, w.record.Browser) {
					matches = append(matches, e)
				}
			}
			if len(matches) != 1 {
				complete = false
				break
			}
			e := matches[0]
			// Basic capture retains the native projection but omits raw text.
			// Its complete projection was matched to the independently pinned
			// original above; no author-supplied authentication field is consulted.
			if e.RawContent.State == "omitted" && e.RawContent.Reason == "capture_policy" {
				custody.SourceRefs = append(custody.SourceRefs, e.ObjectHash)
				continue
			}
			if e.RawContent.State != "stored" || e.RawContent.Ref == "" {
				complete = false
				break
			}
			var body strings.Builder
			for offset := int64(0); ; {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				page, err := provenance.ReadTextContentPage(db, run, e.RawContent.Ref, offset, 64<<10)
				if errors.Is(err, sql.ErrNoRows) {
					complete = false
					break
				}
				if err != nil {
					return nil, err
				}
				body.WriteString(page.Content)
				if body.Len() > browserlink.MaxRecordBytes {
					return nil, i18n.Errorf("browser custody source body limit exceeded")
				}
				if !page.HasMore {
					break
				}
				offset = page.NextOffset
			}
			if !complete || body.String() != *w.record.RawBody {
				complete = false
				break
			}
			custody.SourceRefs = append(custody.SourceRefs, e.ObjectHash)
		}
		if complete {
			sort.Strings(custody.SourceRefs)
			out = append(out, custody)
		}
	}
	return out, nil
}
