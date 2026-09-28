package hooksbridge

import (
	"context"
	"database/sql"
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
		agent string
		body  strings.Builder
		refs  []string
		seen  map[string]bool
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
			if e.Source.Harness != "claude" || e.Source.Channel == "hooks" {
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
				g = &transcript{agent: agent, seen: map[string]bool{}}
				groups[e.Source.ID] = g
			}
			g.refs = append(g.refs, e.ObjectHash)
			if g.seen[e.RawContent.Ref] {
				continue
			}
			if e.RawContent.State != "stored" {
				return 0, fmt.Errorf("context intent projection requires preserved source records")
			}
			body, err := contextBody(db, runID, e.RawContent, &budget)
			if err != nil {
				return 0, err
			}
			g.seen[e.RawContent.Ref] = true
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
		ref, err := objects.PutExternalObject(provenance.ExternalObjectInput{
			RunID: runID, Type: "agent_context_projection", SourceID: "context-intent/" + key, Parents: g.refs,
			Payload: map[string]any{"source_id": key, "parser_version": agentcontext.ParserVersion,
				"projection": "claude-model-calls/v1", "source_record_count": len(g.seen)},
		})
		if err != nil {
			return 0, err
		}
		inputs = append(inputs, provenance.TranscriptStream{AgentID: g.agent, Reader: strings.NewReader(g.body.String()), SourceRef: ref.Hash})
	}
	return provenance.HarvestTranscriptStreams(objects, db, runID, inputs)
}
