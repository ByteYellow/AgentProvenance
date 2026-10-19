package hooksbridge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// HarvestContextIntent preserves the existing Claude model-call lens without
// reopening live transcripts or importing activity before a resume boundary.
func HarvestContextIntent(ctx context.Context, db *sql.DB, paths store.Paths, runID string) (int, error) {
	type transcript struct {
		agent     string
		body      strings.Builder
		refs      []string
		seen      map[string]bool
		toolNodes map[string]string
		derived   bool
	}
	groups := map[string]*transcript{}
	svc, objects := agentcontext.Service{DB: db, Paths: paths}, provenance.ObjectStore{DB: db, Paths: paths}
	cursor, count, budget := "", 0, int64(64<<20)
	for {
		page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: runID, Cursor: cursor, Limit: 200})
		if err != nil {
			return 0, err
		}
		for _, e := range page.Entries {
			count++
			if count > agentcontext.MaxRecords {
				return 0, fmt.Errorf("context intent projection record limit exceeded")
			}
			if e.ExecutionScope == agentcontext.PriorContext || e.Source.Harness != "claude" || e.Source.Channel == "hooks" {
				continue
			}
			g := groups[e.Source.ID]
			if g == nil {
				if len(groups) >= 256 {
					return 0, fmt.Errorf("context intent projection source limit exceeded")
				}
				agent := e.AgentID
				if agent == "" {
					agent = mainAgentID
				}
				g = &transcript{agent: agent, seen: map[string]bool{}, toolNodes: map[string]string{}}
				groups[e.Source.ID] = g
			}
			if e.Kind == "tool_call" && e.ToolCallID != "" && e.Status != "completion_only" {
				node := agentcontext.ToolNodeID(e)
				if previous := g.toolNodes[e.ToolCallID]; previous != "" && previous != node {
					return 0, fmt.Errorf("context intent projection has conflicting tool identities")
				}
				g.toolNodes[e.ToolCallID] = node
			}
			g.refs = append(g.refs, e.ObjectHash)
			content := e.RawContent
			if content.State == "omitted" && content.Reason == "capture_policy" {
				if e.IntentContent == nil {
					continue
				}
				content = *e.IntentContent
				g.derived = true
			}
			if g.seen[content.Ref] {
				continue
			}
			if content.State != "stored" {
				return 0, fmt.Errorf("context intent projection requires preserved source records")
			}
			body, err := contextBody(db, runID, content, &budget)
			if err != nil {
				return 0, err
			}
			if e.IntentContent != nil && content.Ref == e.IntentContent.Ref {
				var header struct {
					Projection string `json:"projection"`
				}
				if json.Unmarshal([]byte(body), &header) != nil || header.Projection != "claude-model-calls/v1" {
					return 0, fmt.Errorf("unsupported retained intent projection")
				}
			}
			g.seen[content.Ref] = true
			g.body.WriteString(body)
			g.body.WriteByte('\n')
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	if len(groups) == 0 {
		return 0, nil
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	inputs := make([]provenance.TranscriptStream, 0, len(keys))
	for _, key := range keys {
		g := groups[key]
		projection := "claude-model-calls/v1"
		if g.derived {
			projection = "claude-model-calls/core-v1"
		}
		ref, err := objects.PutExternalObject(provenance.ExternalObjectInput{
			RunID: runID, Type: "agent_context_projection", SourceID: "context-intent/" + key, Parents: g.refs,
			Payload: map[string]any{"source_id": key, "parser_version": agentcontext.ParserVersion,
				"projection": projection, "source_record_count": len(g.seen)},
		})
		if err != nil {
			return 0, err
		}
		inputs = append(inputs, provenance.TranscriptStream{AgentID: g.agent, Reader: strings.NewReader(g.body.String()), SourceRef: ref.Hash, ToolNodes: g.toolNodes})
	}
	return provenance.HarvestTranscriptStreams(objects, db, runID, inputs)
}
