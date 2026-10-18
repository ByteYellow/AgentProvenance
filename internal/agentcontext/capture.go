package agentcontext

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const CapturePolicyVersion = "agentprovenance.context_capture/v1"

// CapturePolicy governs additional context retention, independently of sensor,
// TLS and workspace snapshots. Once recorded, a run's policy is immutable.
type CapturePolicy struct {
	Version       string          `json:"version"`
	Preset        string          `json:"preset"`
	ToolResults   bool            `json:"tool_results"`
	SourceRecords bool            `json:"source_records"`
	History       bool            `json:"history"`
	Configuration bool            `json:"configuration"`
	Overrides     map[string]bool `json:"overrides,omitempty"`
}

type CaptureOmission struct {
	Category string `json:"category"`
	Reason   string `json:"reason"`
	Records  int64  `json:"records"`
}

func NewCapturePolicy(preset string, toolResults *bool) (CapturePolicy, error) {
	if preset == "" {
		preset = "detailed"
	}
	if preset != "basic" && preset != "detailed" {
		return CapturePolicy{}, fmt.Errorf("capture preset must be basic or detailed")
	}
	detailed := preset == "detailed"
	p := CapturePolicy{Version: CapturePolicyVersion, Preset: preset,
		ToolResults: detailed, SourceRecords: detailed, History: detailed, Configuration: detailed}
	if toolResults != nil {
		p.ToolResults = *toolResults
		p.Overrides = map[string]bool{"tool_results": *toolResults}
		// Native source records may embed the very results being excluded.
		if !*toolResults {
			p.SourceRecords = false
		}
	}
	return p, nil
}

func (p CapturePolicy) validate() error {
	var override *bool
	if len(p.Overrides) > 0 {
		value, ok := p.Overrides["tool_results"]
		if !ok || len(p.Overrides) != 1 {
			return fmt.Errorf("unsupported context capture override")
		}
		override = &value
	}
	want, err := NewCapturePolicy(p.Preset, override)
	if err != nil || p.Version != CapturePolicyVersion || p.Preset == "" ||
		p.ToolResults != want.ToolResults || p.SourceRecords != want.SourceRecords ||
		p.History != want.History || p.Configuration != want.Configuration {
		return fmt.Errorf("invalid context capture policy")
	}
	return nil
}

type captureReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func readCapturePolicy(ctx context.Context, db captureReader, run string) (*CapturePolicy, error) {
	rows, err := db.QueryContext(ctx, `SELECT hash FROM provenance_objects
		WHERE run_id=? AND object_type='context_capture_policy' LIMIT 2`, run)
	if err != nil {
		return nil, err
	}
	var refs []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			rows.Close()
			return nil, err
		}
		refs = append(refs, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}
	if len(refs) != 1 {
		return nil, fmt.Errorf("run has conflicting context capture policies")
	}
	var p CapturePolicy
	if err := provenance.ReadObjectPayload(db, run, refs[0], &p); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s Service) capturePolicyForWrite(ctx context.Context, tx *sql.Tx, run string) (CapturePolicy, error) {
	saved, err := readCapturePolicy(ctx, tx, run)
	if err != nil {
		return CapturePolicy{}, err
	}
	requested := s.CapturePolicy
	if requested != nil {
		if err := requested.validate(); err != nil {
			return CapturePolicy{}, err
		}
	}
	if saved != nil {
		if requested != nil && digest(*saved) != digest(*requested) {
			return CapturePolicy{}, fmt.Errorf("context capture policy is fixed for this run; choose a new run to change it")
		}
		return *saved, nil
	}
	p, _ := NewCapturePolicy("detailed", nil)
	if requested != nil {
		p = *requested
	}
	// A historical run without recorded settings remains detailed on append.
	// A preset is not an instruction to rewrite or thin its saved evidence.
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_context_entries WHERE run_id=?`, run).Scan(&existing); err != nil {
		return CapturePolicy{}, err
	}
	if existing > 0 && (p.Preset != "detailed" || len(p.Overrides) > 0) {
		return CapturePolicy{}, fmt.Errorf("choose a new run to set a context capture policy")
	}
	payload, err := mapPayload(p)
	if err != nil {
		return CapturePolicy{}, err
	}
	_, err = (provenance.ObjectStore{DB: s.DB, Paths: s.Paths, Tx: tx}).PutExternalObject(provenance.ExternalObjectInput{
		RunID: run, Type: "context_capture_policy", SourceID: "context-capture/v1", Payload: payload,
	})
	return p, err
}

func omittedContent(body *string, media, reason, scope string) ContentRef {
	c := ContentRef{State: "omitted", Reason: reason, MediaType: media}
	if body != nil {
		sum := sha256.Sum256([]byte(*body))
		c.Bytes, c.SHA256, c.DigestScope = Number(int64(len(*body))), hex.EncodeToString(sum[:]), scope
	}
	return c
}

func addCaptureOmission(report *Coverage, category string) {
	for i := range report.Omissions {
		if report.Omissions[i].Category == category {
			report.Omissions[i].Records++
			return
		}
	}
	report.Omissions = append(report.Omissions, CaptureOmission{Category: category,
		Reason: "capture_policy", Records: 1})
}

func (p CapturePolicy) omitBody(r Record) bool {
	return (r.Kind == "tool_result" && !p.ToolResults) ||
		((r.Kind == "configuration" || r.Kind == "approval") && !p.Configuration)
}

// coreSessionBody retains lifecycle/refusal and explicit child identity only.
// Large source-state snapshots and configuration do not become a second archive.
func coreSessionBody(src Source, r Record) *string {
	if r.Body == nil {
		return nil
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(*r.Body), &value) != nil {
		return nil
	}
	keys := []string{}
	if src.Channel == "hooks" {
		keys = []string{"hook_event_name", "session_id", "agent_id", "parent_agent_id", "agent_type",
			"agentId", "parentAgentId", "agentType", "tool_use_id", "tool_name", "ts", "_ts", "timestamp",
			"last_assistant_message"}
	} else if r.ToolName == "spawn_agent" && r.Status == "started" {
		keys = []string{"session_id", "agent_id", "parent_session_id"}
	}
	if len(keys) == 0 {
		return nil
	}
	compact := map[string]json.RawMessage{}
	for _, key := range keys {
		if raw, ok := value[key]; ok {
			compact[key] = raw
		}
	}
	raw, err := json.Marshal(compact)
	if err != nil {
		return nil
	}
	body := string(raw)
	return &body
}

// coreIntentRecord is an explicit derived projection, not a replacement source
// record. It keeps the fields consumed by the existing Claude intent lens and
// excludes tool results, source configuration and unrelated transcript metadata.
func coreIntentRecord(src Source, raw *string) (*string, error) {
	if src.Harness != "claude" || src.Channel == "hooks" || raw == nil {
		return nil, nil
	}
	var top row
	if json.Unmarshal([]byte(*raw), &top) != nil {
		return nil, fmt.Errorf("invalid source record for intent projection")
	}
	typ := text(top, "type")
	if typ != "user" && typ != "assistant" {
		return nil, nil
	}
	message := obj(top["message"])
	content := message["content"]
	if typ == "user" {
		var prompt string
		if json.Unmarshal(content, &prompt) != nil || strings.TrimSpace(prompt) == "" {
			return nil, nil
		}
	} else {
		var blocks []row
		if json.Unmarshal(content, &blocks) != nil || blocks == nil {
			return nil, fmt.Errorf("invalid assistant content for intent projection")
		}
		selected := []row{}
		for _, block := range blocks {
			var keys []string
			switch text(block, "type") {
			case "thinking":
				keys = []string{"type", "thinking"}
			case "text":
				keys = []string{"type", "text"}
			case "tool_use":
				keys = []string{"type", "id", "name", "input"}
			default:
				continue
			}
			part := row{}
			for _, key := range keys {
				if v, ok := block[key]; ok {
					part[key] = v
				}
			}
			selected = append(selected, part)
		}
		if len(selected) == 0 {
			return nil, nil
		}
		content, _ = json.Marshal(selected)
	}
	msg := row{"content": content}
	for _, key := range []string{"role", "model", "stop_reason"} {
		if v, ok := message[key]; ok {
			msg[key] = v
		}
	}
	result := row{"projection": quoted("claude-model-calls/v1"), "type": quoted(typ), "message": whole(msg)}
	for _, key := range []string{"timestamp", "sessionId", "agentId"} {
		if v, ok := top[key]; ok {
			result[key] = v
		}
	}
	body := string(whole(result))
	return &body, nil
}
