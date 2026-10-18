package dashboard

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
)

const searchSourceLimit = 50

// Search sources describe existing readers; they never copy or index a body.
// The same bounded browser scanner consumes this catalog online and offline.
type SearchSource struct {
	ID             string                  `json:"id"`
	Category       string                  `json:"category"`
	Kind           string                  `json:"kind"`
	Label          string                  `json:"label"`
	Node           string                  `json:"node,omitempty"`
	GraphNode      string                  `json:"graph_node,omitempty"`
	SourceID       string                  `json:"source_id,omitempty"`
	Harness        string                  `json:"harness,omitempty"`
	SessionID      string                  `json:"session_id,omitempty"`
	AgentID        string                  `json:"agent_id,omitempty"`
	ToolCallID     string                  `json:"tool_call_id,omitempty"`
	RecordedAt     string                  `json:"recorded_at,omitempty"`
	ExecutionScope string                  `json:"execution_scope,omitempty"`
	Entry          *agentcontext.Entry     `json:"entry,omitempty"`
	Content        agentcontext.ContentRef `json:"content"`
}

type SearchSources struct {
	SchemaVersion string         `json:"schema_version"`
	RunID         string         `json:"run_id"`
	Harness       string         `json:"harness,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	Sources       []SearchSource `json:"sources"`
	HasMore       bool           `json:"has_more"`
	NextCursor    string         `json:"next_cursor,omitempty"`
}

type SearchSourceOptions struct {
	RunID, Harness, SessionID, Cursor string
}

type searchCursor struct {
	Query string `json:"query"`
	Stage int    `json:"stage"`
	After string `json:"after"`
}

func (s Server) searchSources(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := s.SearchSources(r.Context(), SearchSourceOptions{RunID: q.Get("run"), Harness: q.Get("harness"),
		SessionID: q.Get("session"), Cursor: q.Get("cursor")})
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, agentcontext.ErrInvalidArgument) {
			code = http.StatusBadRequest
		} else if errors.Is(err, sql.ErrNoRows) {
			code = http.StatusNotFound
		}
		httpError(w, err.Error(), code)
		return
	}
	writeJSON(w, page)
}

func (s Server) SearchSources(ctx context.Context, opts SearchSourceOptions) (SearchSources, error) {
	result := SearchSources{SchemaVersion: "agentprovenance.search_sources/v1", RunID: opts.RunID,
		Harness: opts.Harness, SessionID: opts.SessionID, Sources: []SearchSource{}}
	invalid := func() (SearchSources, error) {
		return result, fmt.Errorf("%w: invalid search scope or cursor", agentcontext.ErrInvalidArgument)
	}
	if opts.RunID == "" || len(opts.RunID) > 512 || len(opts.Harness) > 128 || len(opts.SessionID) > 512 || (opts.Harness == "") != (opts.SessionID == "") {
		return invalid()
	}
	key, _ := json.Marshal([]string{opts.RunID, opts.Harness, opts.SessionID})
	sum := sha256.Sum256(key)
	cursor := searchCursor{Query: hex.EncodeToString(sum[:])}
	if opts.Cursor != "" {
		if len(opts.Cursor) > 16384 {
			return invalid()
		}
		raw, err := base64.RawURLEncoding.DecodeString(opts.Cursor)
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Query != hex.EncodeToString(sum[:]) || cursor.Stage < 0 || cursor.Stage > 3 || len(cursor.After) > 8192 {
			return invalid()
		}
	}
	service := agentcontext.Service{DB: s.DB}
	tools, events, nodes := "[]", "[]", "[]"
	if opts.SessionID != "" {
		scope, err := service.SessionGraphScope(ctx, opts.RunID, opts.Harness, opts.SessionID)
		if err != nil {
			return result, err
		}
		b, _ := json.Marshal(scope.ToolIDs)
		tools = string(b)
		b, _ = json.Marshal(scope.EventIDs)
		events = string(b)
		ids := append([]string{}, scope.ToolIDs...)
		for _, id := range scope.EventIDs {
			ids = append(ids, "runtime_event/"+id)
		}
		b, _ = json.Marshal(ids)
		nodes = string(b)
	}
	more := false
	if cursor.Stage == 0 {
		page, err := service.Entries(ctx, agentcontext.PageOptions{RunID: opts.RunID, Harness: opts.Harness,
			SessionID: opts.SessionID, Cursor: cursor.After, Limit: searchSourceLimit})
		if err != nil {
			return result, err
		}
		for _, entry := range page.Entries {
			category := "messages"
			switch entry.Kind {
			case "tool_call", "tool_result":
				category = "tools"
			case "configuration", "approval", "session":
				category = "configuration"
			}
			label := entry.Kind
			if entry.ToolName != "" {
				label += " · " + entry.ToolName
			} else if entry.Role != "" {
				label += " · " + entry.Role
			}
			result.Sources = append(result.Sources, SearchSource{ID: "entry/" + entry.ID, Category: category, Kind: entry.Kind,
				Label: label, Entry: &entry, Content: entry.Content, SourceID: entry.Source.ID, Harness: entry.Source.Harness,
				SessionID: entry.Source.SessionID, AgentID: entry.AgentID, ToolCallID: entry.ToolCallID,
				RecordedAt: entry.RecordedAt, ExecutionScope: entry.ExecutionScope})
		}
		cursor.After, more = page.NextCursor, page.HasMore
	} else {
		var query string
		args := []any{opts.RunID, cursor.After}
		switch cursor.Stage {
		case 1:
			query = `SELECT o.hash, o.object_type, o.source_id, o.created_at,
			 EXISTS(SELECT 1 FROM graph_edges g WHERE g.run_id=o.run_id AND (g.from_id=o.hash OR g.to_id=o.hash))
			 FROM provenance_objects o WHERE o.run_id=? AND o.hash>? AND o.object_type IN ('artifact','llm_message')`
			if opts.SessionID != "" {
				// Only direct saved object relationships qualify. Sharing a path,
				// process or agent must not pull another session's body into scope.
				query += ` AND EXISTS(SELECT 1 FROM graph_edges g WHERE g.run_id=o.run_id AND
				 ((g.from_id=o.hash AND g.to_id IN (SELECT value FROM json_each(?))) OR
				  (g.to_id=o.hash AND g.from_id IN (SELECT value FROM json_each(?)))))`
				args = append(args, nodes, nodes)
			}
			query += ` ORDER BY o.hash LIMIT ?`
		case 2:
			query = `SELECT id, 'tool_call', id, created_at, 1 FROM tool_calls WHERE run_id=? AND id>?`
			if opts.SessionID != "" {
				query += ` AND id IN (SELECT value FROM json_each(?))`
				args = append(args, tools)
			}
			query += ` ORDER BY id LIMIT ?`
		case 3:
			query = `SELECT id, event_type, source, created_at, 1 FROM events WHERE run_id=? AND id>?`
			if opts.SessionID != "" {
				query += ` AND id IN (SELECT value FROM json_each(?))`
				args = append(args, events)
			}
			query += ` ORDER BY id LIMIT ?`
		}
		args = append(args, searchSourceLimit+1)
		rows, err := s.DB.QueryContext(ctx, query, args...)
		if err != nil {
			return result, err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			var id, kind, source, recorded string
			var graph bool
			if err := rows.Scan(&id, &kind, &source, &recorded, &graph); err != nil {
				return result, err
			}
			count++
			if count > searchSourceLimit {
				more = true
				break
			}
			cursor.After = id
			item := SearchSource{ID: fmt.Sprintf("%d/%s", cursor.Stage, id), Kind: kind, SourceID: source,
				RecordedAt: recorded, Node: id, Content: agentcontext.ContentRef{State: "reader"}}
			switch cursor.Stage {
			case 1:
				item.Category, item.Label = "files", source
				if kind == "llm_message" || strings.HasPrefix(source, "agent_message/") {
					item.Category = "messages"
				}
			case 2:
				item.Category, item.Label, item.ToolCallID = "tools", "tool_call", id
			case 3:
				item.Category, item.Label, item.Node = "runtime", kind, "runtime_event/"+id
			}
			if graph {
				item.GraphNode = item.Node
			}
			result.Sources = append(result.Sources, item)
		}
		if err := rows.Err(); err != nil {
			return result, err
		}
	}
	if !more {
		cursor.Stage++
		cursor.After = ""
	}
	result.HasMore = cursor.Stage <= 3
	if result.HasMore {
		data, _ := json.Marshal(cursor)
		result.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	return result, ctx.Err()
}
