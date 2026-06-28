// Package mcpserver exposes AgentProvenance's AI tool surface over the Model
// Context Protocol (MCP, spec revision 2025-06-18) as a stdio JSON-RPC 2.0
// server. It is a thin transport over internal/aitools: the tool catalog and
// dispatcher are the single source of truth, so an MCP client (Claude Desktop,
// the mcp inspector, etc.) sees exactly the same read surface + inline policy
// gate as the `agentprov ai` CLI and the provider adapters.
//
// Trust boundary is inherited from aitools (see docs/ai-access.md): tools let a
// model QUERY the verifiable graph and pre-flight a proposed action; the gate
// verdict is computed by the trusted engine, never fabricated by the model.
//
// Wire framing is newline-delimited JSON (one JSON-RPC message per line). Only
// JSON-RPC is written to the output stream -- callers must keep diagnostics on
// stderr so the stdout channel stays clean for the client.
package mcpserver

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/aitools"
)

// ProtocolVersion is the MCP spec revision this server implements. During the
// initialize handshake we echo the client's requested version when it sends one
// (maximizing client compatibility) and fall back to this otherwise.
const ProtocolVersion = "2025-06-18"

const (
	serverName    = "agentprovenance"
	serverVersion = "0.2.0"
)

// JSON-RPC 2.0 standard error codes.
const (
	codeParse          = -32700
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

const instructions = "Query the verifiable AgentProvenance graph (verify_run, get_signals, " +
	"list_risks, list_events, get_timeline) and pre-flight a PROPOSED agent action through the " +
	"trusted policy gate (evaluate_action) before executing it. The gate verdict is computed by " +
	"the engine, not the model; these tools cannot fabricate system events or signatures."

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve runs the MCP stdio loop: it reads newline-delimited JSON-RPC messages
// from r and writes responses to w until r reaches EOF (a clean shutdown). It
// returns a non-nil error only on an unrecoverable transport failure.
func Serve(db *sql.DB, r io.Reader, w io.Writer) error {
	br := bufio.NewReaderSize(r, 1<<20)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for {
		line, readErr := br.ReadBytes('\n')
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			if err := handleLine(db, trimmed, enc); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func handleLine(db *sql.DB, line []byte, enc *json.Encoder) error {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		// Per JSON-RPC, a parse error is answered with a null id.
		return enc.Encode(rpcResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: codeParse, Message: "parse error"},
		})
	}
	resp, respond := dispatch(db, req)
	if !respond {
		return nil
	}
	return enc.Encode(resp)
}

// dispatch routes one request. The bool is false for notifications (id absent or
// null), which must not produce a response.
func dispatch(db *sql.DB, req rpcRequest) (rpcResponse, bool) {
	if isNotification(req.ID) {
		return rpcResponse{}, false
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = initializeResult(req.Params)
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": toolDefs()}
	case "tools/call":
		result, rerr := callTool(db, req.Params)
		if rerr != nil {
			resp.Error = rerr
		} else {
			resp.Result = result
		}
	default:
		resp.Error = &rpcError{Code: codeMethodNotFound, Message: fmt.Sprintf("method not found: %s", req.Method)}
	}
	return resp, true
}

func isNotification(id json.RawMessage) bool {
	s := strings.TrimSpace(string(id))
	return s == "" || s == "null"
}

func initializeResult(params json.RawMessage) map[string]any {
	version := ProtocolVersion
	if len(params) > 0 {
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
			version = p.ProtocolVersion
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		"instructions":    instructions,
	}
}

// toolDefs renders aitools.Catalog() as MCP tool definitions. MCP uses the
// camelCase inputSchema key (vs. the provider adapters' input_schema).
func toolDefs() []map[string]any {
	cat := aitools.Catalog()
	out := make([]map[string]any, 0, len(cat))
	for _, t := range cat {
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
			// readOnlyHint surfaces the trust boundary to clients: the read
			// surface + gate touch nothing; the context-write tools assert
			// app-side context (see docs/ai-access.md §0).
			"annotations": map[string]any{"readOnlyHint": !t.Writes},
		})
	}
	return out
}

func callTool(db *sql.DB, params json.RawMessage) (map[string]any, *rpcError) {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{Code: codeInvalidParams, Message: fmt.Sprintf("invalid params: %v", err)}
		}
	}
	if p.Name == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "missing tool name"}
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}
	result, err := aitools.Dispatch(db, p.Name, p.Arguments)
	if err != nil {
		// An unknown tool is a protocol error (the method does not exist); a tool
		// that ran but failed is reported in-band with isError per the MCP spec.
		if strings.HasPrefix(err.Error(), "unknown ai tool") {
			return nil, &rpcError{Code: codeMethodNotFound, Message: err.Error()}
		}
		return toolResult(map[string]any{"error": err.Error()}, true), nil
	}
	return toolResult(result, false), nil
}

// toolResult wraps a dispatch payload as an MCP CallToolResult: the serialized
// JSON always goes in a text content block, and object payloads are additionally
// surfaced as structuredContent (per the spec's backwards-compat guidance).
func toolResult(payload any, isError bool) map[string]any {
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte(fmt.Sprintf("%q", err.Error()))
	}
	var indented bytes.Buffer
	if json.Indent(&indented, raw, "", "  ") != nil {
		indented.Write(raw)
	}
	res := map[string]any{
		"content": []map[string]any{{"type": "text", "text": indented.String()}},
		"isError": isError,
	}
	if obj := asObject(raw); obj != nil {
		res["structuredContent"] = obj
	}
	return res
}

func asObject(raw []byte) map[string]any {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '{' {
		return nil
	}
	var obj map[string]any
	if json.Unmarshal(t, &obj) != nil {
		return nil
	}
	return obj
}
