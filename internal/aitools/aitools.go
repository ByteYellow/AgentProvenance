// Package aitools exposes AgentProvenance's read surface, the inline policy
// gate, and the context-write surface as AI-callable tools. It is the single
// source the provider adapters (Anthropic tool-use, OpenAI function-calling,
// generic/MCP) are generated from, plus a dispatcher that executes a tool
// against the local store / policy engine.
//
// Trust boundary (see docs/ai-access.md §0): these tools let a model QUERY the
// verifiable graph, pre-flight a proposed action, and ASSERT its own app-side
// context (bind_scope / record_tool_call). They never let the model fabricate
// system events or signatures: context-write rows are recorded as ai_asserted
// and execute nothing, and the gate's verdict is computed by the trusted policy
// engine, not the model. Tool.Writes marks the mutating context-write tools.
package aitools

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/ids"
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
	// Writes is true for tools that mutate the local store (the context-write
	// surface). Read tools and the no-side-effect gate leave it false. Adapters
	// use this to advertise read-only-ness (e.g. the MCP readOnlyHint).
	Writes bool
	Run    func(db *sql.DB, input map[string]any) (any, error)
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
		{
			Name:        "bind_scope",
			Description: "Register a ToolCallScope binding: assert that this run+tool_call ran as the given OS process/container/cgroup so independent system telemetry can later be correlated to it (zero-instrumentation). This is APP-ASSERTED context only -- the binding is recorded with source ai_asserted and cannot fabricate system events or signatures; it merely provides a join key the trusted correlation engine may use when real kernel events arrive.",
			InputSchema: objSchema(map[string]any{
				"run":          strProp("run id this scope belongs to"),
				"tool_call":    strProp("tool_call id to bind"),
				"process_id":   strProp("optional AgentProvenance process id for this scope"),
				"container_id": strProp("optional runtime-observable container id"),
				"cgroup_id":    strProp("optional runtime-observable cgroup id"),
				"pid":          intProp("optional OS process id"),
				"root_pid":     intProp("optional root OS process id for the scope"),
				"started_at":   strProp("optional RFC3339 start; defaults to now"),
				"ended_at":     strProp("optional RFC3339 end; empty leaves the scope open"),
			}, "run", "tool_call"),
			Writes: true,
			Run:    bindScope,
		},
		{
			Name:        "record_tool_call",
			Description: "Record an APP-ASSERTED tool call: anchor that this run invoked the named tool/command, returning a tool_call id you can then bind_scope to a process. This does NOT execute anything and does NOT create system evidence; the row is stored with status/policy_decision 'asserted' so consumers can tell it apart from a gate-decided or kernel-observed call.",
			InputSchema: objSchema(map[string]any{
				"run":       strProp("run id this tool call belongs to"),
				"command":   strProp("the tool name / command line the agent is asserting it invoked"),
				"tool_call": strProp("optional tool_call id to use; generated when omitted"),
			}, "run", "command"),
			Writes: true,
			Run:    recordToolCall,
		},
	}
}

// assertedStatus marks rows written by the context-write tools as agent
// assertions, distinct from 'running'/'completed' (gate/recorder lifecycle) and
// from any kernel-observed state. policy_decision is set to the same value so a
// consumer never mistakes an asserted call for one the trusted gate allowed.
const assertedStatus = "asserted"

// recordToolCall inserts a minimal, parent-less tool_calls anchor. It executes
// nothing (vs. the `record` recorder, which spawns the command) and writes no
// telemetry events -- so it stays strictly inside the app-context trust boundary.
// verify_run/get_timeline tolerate the empty rollout/attempt/session links.
func recordToolCall(db *sql.DB, in map[string]any) (any, error) {
	runID := strArg(in, "run")
	command := strArg(in, "command")
	if runID == "" || command == "" {
		return nil, fmt.Errorf("record_tool_call requires run and command")
	}
	toolCallID := strArg(in, "tool_call")
	if toolCallID == "" {
		toolCallID = ids.New("tool")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(command))
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, command, args_hash, status, policy_decision, created_at, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		toolCallID, runID, command, hex.EncodeToString(sum[:]), assertedStatus, assertedStatus, now, now); err != nil {
		return nil, err
	}
	return map[string]any{
		"schema_version": "agentprovenance.ai_record_tool_call/v1",
		"tool_call":      toolCallID,
		"run":            runID,
		"status":         assertedStatus,
	}, nil
}

// aiBindingSource is the binding_source forced on every bind_scope write. It is
// NOT caller-controllable: an agent-asserted scope must never masquerade as the
// trusted control plane (RecordBinding's default) -- this label is the only
// audit trail that the attribution was agent-asserted. See docs/ai-access.md §0.
const aiBindingSource = "ai_asserted"

// bindScope records an app-asserted ToolCallScope binding. The model supplies
// the observable identifiers (pid/container/cgroup) that let real kernel events
// resolve to this tool call, but it cannot set the binding_source or confidence:
// the join only yields independent (kernel_correlated) evidence when a genuine
// system event matches, never from this assertion alone.
func bindScope(db *sql.DB, in map[string]any) (any, error) {
	runID := strArg(in, "run")
	toolCallID := strArg(in, "tool_call")
	if runID == "" || toolCallID == "" {
		return nil, fmt.Errorf("bind_scope requires run and tool_call")
	}
	id, err := correlation.RecordBinding(db, correlation.Binding{
		RunID:         runID,
		ToolCallID:    toolCallID,
		ProcessID:     strArg(in, "process_id"),
		ContainerID:   strArg(in, "container_id"),
		CgroupID:      strArg(in, "cgroup_id"),
		PID:           int64Arg(in, "pid"),
		RootPID:       int64Arg(in, "root_pid"),
		StartedAt:     strArg(in, "started_at"),
		EndedAt:       strArg(in, "ended_at"),
		BindingSource: aiBindingSource, // forced; overrides any caller value
		// Confidence left zero -> RecordBinding caps ai_asserted binds at 0.5
		// (defaultBindingConfidence), so a scope the model merely CLAIMED reads
		// as honestly less certain than a kernel-verified match, even if it later
		// resolves by pid. The matching method's confidence still applies (min).
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"schema_version": "agentprovenance.ai_bind/v1",
		"binding_id":     id,
		"binding_source": aiBindingSource,
		"run":            runID,
		"tool_call":      toolCallID,
	}, nil
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

func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
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

func int64Arg(in map[string]any, key string) int64 {
	switch v := in[key].(type) {
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	default:
		return 0
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
