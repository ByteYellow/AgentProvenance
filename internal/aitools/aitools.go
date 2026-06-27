// Package aitools exposes AgentProvenance's read surface (and the inline policy
// gate) as AI-callable tools. It is the single source the provider adapters
// (Anthropic tool-use, OpenAI function-calling, generic/MCP) are generated from,
// plus a dispatcher that executes a tool against the local store / policy engine.
//
// Trust boundary (see docs/ai-access.md): these tools let a model QUERY the
// verifiable graph and pre-flight a proposed action; they never let the model
// fabricate system events or signatures. The gate's verdict is computed by the
// trusted policy engine, not the model.
package aitools

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

// Tool is one AI-callable operation.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Run         func(db *sql.DB, input map[string]any) (any, error)
}

// Catalog is the canonical AI tool set. Read tools query the verifiable graph;
// evaluate_action is the inline pre-flight gate.
func Catalog() []Tool {
	return []Tool{
		{
			Name:        "verify_run",
			Description: "Verify a run's evidence chain (object hashes, parent links, policy->risk->response->signal integrity). Returns status ok|failed with any issues.",
			InputSchema: objSchema(map[string]any{"run": strProp("run id to verify")}, "run"),
			Run: func(db *sql.DB, in map[string]any) (any, error) {
				return provenance.Verify(db, strArg(in, "run"))
			},
		},
		{
			Name:        "get_signals",
			Description: "List the unified signals (behavior/cost/quality/security) attached to a run's causality graph.",
			InputSchema: objSchema(map[string]any{"run": strProp("run id")}, "run"),
			Run: func(db *sql.DB, in map[string]any) (any, error) {
				return signals.Export(db, strArg(in, "run"))
			},
		},
		{
			Name:        "list_risks",
			Description: "List the security risk signals (metadata-IP, private-CIDR, secret-path, etc.) raised for a run, with recommended actions.",
			InputSchema: objSchema(map[string]any{"run": strProp("run id")}, "run"),
			Run: func(db *sql.DB, in map[string]any) (any, error) {
				return securitymodel.BuildRiskSignalsReport(db, strArg(in, "run"))
			},
		},
		{
			Name:        "list_events",
			Description: "List runtime telemetry events for a run (paged), optionally filtered by event type.",
			InputSchema: objSchema(map[string]any{
				"run":   strProp("run id"),
				"type":  strProp("optional event_type filter, e.g. execve, metadata_ip"),
				"limit": map[string]any{"type": "integer", "description": "max events (default 50)"},
			}, "run"),
			Run: func(db *sql.DB, in map[string]any) (any, error) {
				return telemetry.ListEventsPage(db, telemetry.ListOptions{
					Filter: telemetry.Filter{RunID: strArg(in, "run"), Type: strArg(in, "type")},
					Limit:  intArg(in, "limit", 50),
				})
			},
		},
		{
			Name:        "get_timeline",
			Description: "Get the merged application-context + runtime-telemetry timeline for a run.",
			InputSchema: objSchema(map[string]any{
				"run":  strProp("run id"),
				"view": map[string]any{"type": "string", "enum": []string{"table", "causality"}, "description": "timeline view"},
			}, "run"),
			Run: func(db *sql.DB, in map[string]any) (any, error) {
				return provenance.BuildTimeline(db, provenance.TimelineOptions{RunID: strArg(in, "run"), View: strArg(in, "view")})
			},
		},
		{
			Name:        "evaluate_action",
			Description: "Pre-flight gate: evaluate a PROPOSED agent action against the security policy WITHOUT executing it. Returns a verdict (allow|deny|quarantine|kill) computed by the trusted engine. Call before running a tool/command/connection.",
			InputSchema: objSchema(map[string]any{
				"event_type": strProp("one of: execve, network_connect, file_write, file_open"),
				"command":    strProp("the command line for execve actions"),
				"args": map[string]any{
					"type":        "array",
					"description": "structured argv for execve actions; preferred when the caller already has tokenized arguments",
					"items":       map[string]any{"type": "string"},
				},
				"dst_ip": strProp("destination IP for network_connect actions"),
				"path":   strProp("file path for file actions"),
			}, "event_type"),
			Run: func(_ *sql.DB, in map[string]any) (any, error) {
				return evaluateAction(in), nil
			},
		},
	}
}

// evaluateAction runs a proposed action through the default policy engine with
// no side effects (no DB write) -- the inline gate.
func evaluateAction(in map[string]any) map[string]any {
	ev := securitymodel.Event{
		Source:    "ai_gate",
		EventType: strArg(in, "event_type"),
		DstIP:     strArg(in, "dst_ip"),
		Path:      strArg(in, "path"),
		Args:      strSliceArg(in, "args"),
	}
	if cmd := strArg(in, "command"); cmd != "" && len(ev.Args) == 0 {
		ev.Args = strings.Fields(cmd)
	}
	d := securitymodel.DefaultEngine().Evaluate(ev)
	return map[string]any{
		"schema_version": "agentprovenance.ai_gate/v1",
		"decision":       d.Decision,
		"reason":         d.Reason,
		"rule_id":        d.RuleID,
		"allow":          d.Decision == "allow",
	}
}

// Dispatch executes a named tool with the given input.
func Dispatch(db *sql.DB, name string, input map[string]any) (any, error) {
	for _, t := range Catalog() {
		if t.Name == name {
			return t.Run(db, input)
		}
	}
	return nil, fmt.Errorf("unknown ai tool %q", name)
}

// AnthropicTools renders the catalog as Anthropic tool-use definitions.
func AnthropicTools() []map[string]any {
	out := make([]map[string]any, 0, len(Catalog()))
	for _, t := range Catalog() {
		out = append(out, map[string]any{
			"name":         t.Name,
			"description":  t.Description,
			"input_schema": t.InputSchema,
		})
	}
	return out
}

// OpenAITools renders the catalog as OpenAI function-calling definitions.
func OpenAITools() []map[string]any {
	out := make([]map[string]any, 0, len(Catalog()))
	for _, t := range Catalog() {
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  t.InputSchema,
			},
		})
	}
	return out
}

// GenericTools renders a provider-neutral catalog.
func GenericTools() []map[string]any {
	out := make([]map[string]any, 0, len(Catalog()))
	for _, t := range Catalog() {
		out = append(out, map[string]any{
			"name":         t.Name,
			"description":  t.Description,
			"input_schema": t.InputSchema,
		})
	}
	return out
}

func objSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func strArg(in map[string]any, key string) string {
	s, _ := in[key].(string)
	return strings.TrimSpace(s)
}

func intArg(in map[string]any, key string, def int) int {
	switch v := in[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return def
	}
}

func strSliceArg(in map[string]any, key string) []string {
	items, ok := in[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
