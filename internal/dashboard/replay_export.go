package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type ReplayPages struct {
	Offsets []int64          `json:"offsets"`
	Pages   []staticdata.Ref `json:"pages"`
}
type ReplayRun struct {
	Audit     *replayAuditIndex                    `json:"audit,omitempty"`
	Compare   map[string]staticdata.Ref            `json:"compare,omitempty"`
	Search    map[string]map[string]staticdata.Ref `json:"search,omitempty"`
	Sessions  map[string]replaySession             `json:"sessions,omitempty"`
	API       map[string]staticdata.Ref            `json:"api"`
	Lenses    staticdata.Ref                       `json:"lenses"`
	Events    staticdata.Ref                       `json:"events"`
	Timeline  staticdata.Ref                       `json:"timeline"`
	Context   staticdata.Ref                       `json:"context"`
	Artifacts staticdata.Ref                       `json:"artifacts"`
	EventRefs map[string][]string                  `json:"event_refs"`
	Filters   map[string]eventQuery                `json:"filters"`
}
type replaySession struct {
	Lenses         staticdata.Ref                `json:"lenses"`
	EventIDs       []string                      `json:"event_ids"`
	Relations      map[string]staticdata.Ref     `json:"relations,omitempty"`
	Audit          *provenance.SessionAuditScope `json:"audit,omitempty"`
	AuditRelations *staticdata.Ref               `json:"audit_relations,omitempty"`
}

func writeReplayLenses(w *staticdata.Writer, lenses provenance.ReplayLenses) (staticdata.Ref, error) {
	index := struct {
		Nodes      staticdata.Ref            `json:"nodes"`
		Present    []string                  `json:"present"`
		FocusNodes staticdata.Ref            `json:"focus_nodes"`
		Views      map[string]staticdata.Ref `json:"views"`
	}{Present: lenses.Present, Views: map[string]staticdata.Ref{}}
	var err error
	if index.Nodes, err = w.JSON(lenses.Nodes); err != nil {
		return staticdata.Ref{}, err
	}
	if index.FocusNodes, err = w.JSON(lenses.FocusNodes); err != nil {
		return staticdata.Ref{}, err
	}
	for key, view := range lenses.Views {
		if index.Views[key], err = w.JSON(view); err != nil {
			return staticdata.Ref{}, err
		}
	}
	return w.JSON(index)
}

type replayContext struct {
	Entries     []agentcontext.Entry               `json:"entries"`
	Latest      []string                           `json:"latest"`
	Nodes       map[string][]string                `json:"nodes"`
	Links       map[string]agentcontext.EntryLinks `json:"links"`
	Content     map[string]ReplayPages             `json:"content"`
	Comparisons map[string]staticdata.Ref          `json:"comparisons"`
}

// ExportReplay exports only the supplied run from an isolated, verified demo
// database. It uses the same readers as the local dashboard, including redaction,
// content limits and absence diagnostics. It never opens a workspace file.
func (s Server) ExportReplay(ctx context.Context, run string, w *staticdata.Writer) (ReplayRun, error) {
	return s.ExportReplaySet(ctx, run, w, []string{run})
}

// ExportReplaySet includes relationship discovery within an explicit export
// catalog, without following those links to copy additional runs.
func (s Server) ExportReplaySet(ctx context.Context, run string, w *staticdata.Writer, visibleRuns []string) (ReplayRun, error) {
	if visibleRuns == nil {
		visibleRuns = []string{run}
	}
	result := ReplayRun{API: map[string]staticdata.Ref{}, EventRefs: map[string][]string{}, Filters: map[string]eventQuery{}}
	contextService := agentcontext.Service{DB: s.DB}
	// Read the same frozen, selected database as every exported index. The
	// overview's bounded display is not an authoritative session catalog.
	sessions, err := contextService.EnumerateSessions(ctx, agentcontext.SessionEnumerationOptions{RunID: run})
	if err != nil {
		return result, err
	}
	if s.replayProjection != nil && s.replayProjection.plan.Selection.Scope == "session" {
		selection := s.replayProjection.plan.Selection
		selected := sessions[:0]
		for _, session := range sessions {
			if session.Harness == selection.Harness && session.SessionID == selection.SessionID {
				selected = append(selected, session)
			}
		}
		sessions = selected
	}
	var auditErr error
	result.Audit, auditErr = s.exportReplayAudit(ctx, run, w)
	if auditErr != nil {
		return result, auditErr
	}
	h := s.Handler()
	get := func(route string, query url.Values) (json.RawMessage, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := httptest.NewRequest(http.MethodGet, route+"?"+query.Encode(), nil).WithContext(ctx)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, r)
		if response.Code != 200 {
			return nil, fmt.Errorf("export %s: HTTP %d %s", route, response.Code, response.Body.String())
		}
		if s.replayProjection != nil && route == "/api/context/overview" {
			var overview agentcontext.Overview
			if err := json.Unmarshal(response.Body.Bytes(), &overview); err != nil {
				return nil, err
			}
			overview.RuntimeCoverage.Capture = s.replayProjection.capture
			return json.Marshal(overview)
		}
		return json.RawMessage(response.Body.Bytes()), nil
	}
	q := url.Values{"run": {run}}
	for _, endpoint := range []string{"overview", "egress", "outbound", "processes", "context/overview", "frameworks"} {
		raw, err := get("/api/"+endpoint, q)
		if err != nil {
			return result, err
		}
		ref, err := w.JSON(raw)
		if err != nil {
			return result, err
		}
		result.API[endpoint] = ref
	}
	raw, err := get("/api/frameworks", q)
	if err != nil {
		return result, err
	}
	var frameworks []struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(raw, &frameworks); err != nil {
		return result, err
	}
	for _, f := range frameworks {
		raw, err := get("/api/compliance", url.Values{"run": {run}, "framework": {f.ID}})
		if err != nil {
			return result, err
		}
		ref, err := w.JSON(raw)
		if err != nil {
			return result, err
		}
		result.API["compliance/"+f.ID] = ref
	}
	lenses, err := provenance.BuildReplayLenses(s.DB, run)
	if err != nil {
		return result, err
	}
	if s.replayProjection != nil {
		s.replayProjection.lenses(&lenses)
	}
	// Load one lens at a time in the browser instead of retaining all 36 views.
	result.Lenses, err = writeReplayLenses(w, lenses)
	if err != nil {
		return result, err
	}
	result.Sessions = map[string]replaySession{}
	for _, src := range sessions {
		keyBytes, _ := json.Marshal([]string{src.Harness, src.SessionID})
		key := string(keyBytes)
		if err := ctx.Err(); err != nil {
			return result, err
		}
		scope, err := s.sessionGraphScope(ctx, run, src.Harness, src.SessionID)
		if err != nil {
			return result, err
		}
		views, err := provenance.BuildSessionReplayLenses(s.DB, run, scope)
		if err != nil {
			return result, err
		}
		if s.replayProjection != nil {
			s.replayProjection.lenses(&views)
		}
		ref, err := writeReplayLenses(w, views)
		if err != nil {
			return result, err
		}
		relations := map[string]staticdata.Ref{}
		cursor := ""
		for {
			page, err := contextService.SessionRelations(ctx, agentcontext.SessionRelationOptions{RunID: run, Harness: src.Harness,
				SessionID: src.SessionID, Limit: 50, Cursor: cursor, VisibleRuns: visibleRuns})
			if err != nil {
				return result, err
			}
			if page.Limited {
				return result, fmt.Errorf("replay session relations resource limit exceeded: %s", key)
			}
			relations[cursor], err = w.JSON(page)
			if err != nil {
				return result, err
			}
			if !page.HasMore {
				break
			}
			if page.NextCursor == "" || page.NextCursor == cursor || relations[page.NextCursor].Path != "" {
				return result, fmt.Errorf("invalid replay session relations continuation: %s", key)
			}
			cursor = page.NextCursor
		}
		saved := replaySession{Lenses: ref, EventIDs: scope.EventIDs, Relations: relations, Audit: scope.Audit}
		if scope.Audit != nil {
			audits, err := w.JSON(scope.AuditEvents)
			if err != nil {
				return result, err
			}
			saved.AuditRelations = &audits
		}
		result.Sessions[key] = saved
	}
	timeline, err := telemetry.ListEventsFiltered(s.DB, telemetry.Filter{RunID: run})
	if err != nil {
		return result, err
	}
	result.Timeline, err = w.JSON(timeline)
	if err != nil {
		return result, err
	}
	events, eventCount, err := s.queryEventsPage(run, eventQuery{}, 1000000, 0)
	if err != nil {
		return result, err
	}
	if eventCount != len(events) {
		return result, fmt.Errorf("public replay exceeds the event export limit")
	}
	result.Events, err = w.JSON(events)
	if err != nil {
		return result, err
	}
	nodes := map[string]bool{}
	for id := range lenses.Nodes {
		nodes[id] = true
	}
	// Precompute the server's event group rules; the browser only evaluates the
	// exported predicates and unions explicitly resolved event references.
	groups := map[string]bool{"": true}
	for _, n := range lenses.Nodes {
		groups[n.Subtype] = true
		for _, k := range []string{"group", "category", "rule_id", "event_type"} {
			if v, ok := n.Data[k].(string); ok {
				groups[v] = true
			}
		}
	}
	for _, view := range lenses.Views {
		lens := view.Manifest.Lens
		for group := range groups {
			var filter eventQuery
			applyLensGroupFilter(&filter, lens, group)
			result.Filters[lens+"/"+group] = filter
		}
	}
	for id := range nodes {
		if strings.HasPrefix(id, "runtime_process/") {
			result.EventRefs[id] = []string{}
			continue
		}
		ids, err := s.resolveEventRefs(run, []string{id})
		if err != nil {
			return result, err
		}
		if len(ids) > 0 {
			sort.Strings(ids)
			result.EventRefs[id] = ids
		}
	}
	// Load process references in one pass; observation-local identities can be
	// numerous, so resolving them one node at a time would add an N+1 query loop.
	processRefs, err := s.DB.QueryContext(ctx, `SELECT DISTINCT from_id, source_event_id FROM graph_edges
		WHERE run_id=? AND edge_type='runtime_process_event' AND from_id LIKE 'runtime_process/%'
		ORDER BY from_id, source_event_id`, run)
	if err != nil {
		return result, err
	}
	for processRefs.Next() {
		var node, id string
		if err := processRefs.Scan(&node, &id); err != nil {
			processRefs.Close()
			return result, err
		}
		if nodes[node] && id != "" {
			result.EventRefs[node] = append(result.EventRefs[node], id)
		}
	}
	err = processRefs.Err()
	processRefs.Close()
	if err != nil {
		return result, err
	}
	service := agentcontext.Service{DB: s.DB}
	contextData := replayContext{Entries: []agentcontext.Entry{}, Latest: []string{}, Nodes: map[string][]string{}, Links: map[string]agentcontext.EntryLinks{}, Content: map[string]ReplayPages{}, Comparisons: map[string]staticdata.Ref{}}
	for _, revisions := range []bool{false, true} {
		cursor := ""
		for {
			page, err := service.Entries(ctx, agentcontext.PageOptions{RunID: run, IncludeRevisions: revisions, Cursor: cursor, Limit: 200})
			if err != nil {
				return result, err
			}
			if revisions {
				if len(contextData.Entries)+len(page.Entries) > replaySelectionLimit {
					return result, fmt.Errorf("replay context resource limit exceeded: more than %d entries", replaySelectionLimit)
				}
				if s.replayProjection != nil {
					for i, entry := range page.Entries {
						page.Entries[i] = s.replayProjection.entry(entry)
					}
				}
				contextData.Entries = append(contextData.Entries, page.Entries...)
			} else {
				for _, e := range page.Entries {
					contextData.Latest = append(contextData.Latest, e.ID)
				}
			}
			if !page.HasMore {
				break
			}
			cursor = page.NextCursor
		}
	}
	comparisons, err := replayComparisonGroups(ctx, contextData.Entries)
	if err != nil {
		return result, err
	}
	// Node -> entry navigation follows exactly the stored relations used by Entries.
	rows, err := s.DB.QueryContext(ctx, `SELECT e.id,e.object_hash,c.to_id,g.to_id FROM agent_context_entries e
 LEFT JOIN graph_edges c ON c.run_id=e.run_id AND c.from_id=e.object_hash AND c.edge_type IN ('context_tool_call','context_tool_result')
 LEFT JOIN graph_edges g ON g.run_id=c.run_id AND g.from_id=c.to_id AND g.edge_type IN ('agent_syscall','runtime_tool_call_event','runtime_tool_call_process') WHERE e.run_id=?`, run)
	if err != nil {
		return result, err
	}
	var recordRows [][4]string
	for rows.Next() {
		var id, hash string
		var tool, runtime *string
		if err = rows.Scan(&id, &hash, &tool, &runtime); err != nil {
			rows.Close()
			return result, err
		}
		r := [4]string{id, hash, "", ""}
		if tool != nil {
			r[2] = *tool
		}
		if runtime != nil {
			r[3] = *runtime
		}
		recordRows = append(recordRows, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	for _, r := range recordRows {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		for _, node := range r[1:] {
			if node == "" {
				continue
			}
			list := contextData.Nodes[node]
			found := false
			for _, id := range list {
				found = found || id == r[0]
			}
			if !found {
				contextData.Nodes[node] = append(list, r[0])
			}
			nodes[node] = true
		}
	}
	pages := func(route string, query url.Values) (ReplayPages, error) {
		out := ReplayPages{Offsets: []int64{}, Pages: []staticdata.Ref{}}
		offset := int64(0)
		for {
			query.Set("offset", strconv.FormatInt(offset, 10))
			query.Set("limit", "65536")
			raw, err := get(route, query)
			if err != nil {
				return out, err
			}
			var p struct {
				Next     int64             `json:"next_offset"`
				More     bool              `json:"has_more"`
				Versions []artifactVersion `json:"versions"`
			}
			if err = json.Unmarshal(raw, &p); err != nil {
				return out, err
			}
			ref, err := w.JSON(raw)
			if err != nil {
				return out, err
			}
			out.Offsets = append(out.Offsets, offset)
			out.Pages = append(out.Pages, ref)
			for _, v := range p.Versions {
				nodes[v.Ref] = true
			}
			if !p.More {
				break
			}
			if p.Next <= offset || p.Next > 32<<20 {
				return out, fmt.Errorf("invalid saved-content continuation")
			}
			offset = p.Next
		}
		return out, nil
	}
	for _, entry := range contextData.Entries {
		links, err := service.Links(ctx, run, entry.ID)
		if err != nil {
			return result, err
		}
		contextData.Links[entry.ID] = links
		for _, body := range entry.ContentReferences() {
			if body.State != "stored" || body.Ref == "" {
				continue
			}
			if _, ok := contextData.Content[body.Ref]; ok {
				continue
			}
			p, err := pages("/api/context/content", url.Values{"run": {run}, "ref": {body.Ref}})
			if err != nil {
				return result, err
			}
			contextData.Content[body.Ref] = p
		}
		k := replayComparisonKind(entry)
		if k != "task" && k != "configuration" && k != "approval" {
			continue
		}
		for _, right := range comparisons[k] {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			comparison := agentcontext.SnapshotComparison{SchemaVersion: agentcontext.SchemaVersion, Scope: "recorded_values",
				Status: "unknown", Left: entry, Right: right, Changes: []agentcontext.SnapshotChange{}, Reason: "excluded"}
			var err error
			if entry.Content.State != "excluded" && right.Content.State != "excluded" {
				comparison, err = service.CompareSnapshots(ctx, run, entry.ID, "", right.ID)
			}
			if err != nil {
				return result, err
			}
			if s.replayProjection != nil {
				comparison.Left = s.replayProjection.entry(comparison.Left)
				comparison.Right = s.replayProjection.entry(comparison.Right)
				if comparison.Left.Content.State == "excluded" || comparison.Right.Content.State == "excluded" {
					comparison.Status, comparison.Reason = "unknown", "excluded"
					comparison.Changes = nil
				}
			}
			ref, err := w.JSON(comparison)
			if err != nil {
				return result, err
			}
			contextData.Comparisons[entry.ID+"/"+right.ID] = ref
		}
	}
	result.Context, err = w.JSON(contextData)
	if err != nil {
		return result, err
	}
	result.Search = map[string]map[string]staticdata.Ref{}
	searchScopes := []SearchSourceOptions{{RunID: run}}
	for key := range result.Sessions {
		var identity []string
		if err := json.Unmarshal([]byte(key), &identity); err != nil || len(identity) != 2 {
			return result, fmt.Errorf("invalid replay session identity")
		}
		searchScopes = append(searchScopes, SearchSourceOptions{RunID: run, Harness: identity[0], SessionID: identity[1]})
	}
	for _, scope := range searchScopes {
		key, _ := json.Marshal([]string{scope.Harness, scope.SessionID})
		catalog := map[string]staticdata.Ref{}
		for {
			page, err := s.SearchSources(ctx, scope)
			if err != nil {
				return result, err
			}
			catalog[scope.Cursor], err = w.JSON(page)
			if err != nil {
				return result, err
			}
			for _, source := range page.Sources {
				if source.Node != "" {
					nodes[source.Node] = true
				}
			}
			if !page.HasMore {
				break
			}
			if page.NextCursor == "" || page.NextCursor == scope.Cursor || catalog[page.NextCursor].Path != "" {
				return result, fmt.Errorf("invalid replay search continuation: %s", key)
			}
			scope.Cursor = page.NextCursor
		}
		result.Search[string(key)] = catalog
	}
	result.Compare = map[string]staticdata.Ref{}
	for cursor := ""; ; {
		page, err := s.ComparisonRecords(ctx, run, cursor)
		if err != nil {
			return result, err
		}
		result.Compare[cursor], err = w.JSON(page)
		if err != nil {
			return result, err
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	artifacts := map[string]ReplayPages{}
	done := map[string]bool{}
	for {
		pending := []string{}
		for node := range nodes {
			if !done[node] {
				pending = append(pending, node)
			}
		}
		if len(pending) == 0 {
			break
		}
		sort.Strings(pending)
		for _, node := range pending {
			done[node] = true
			for _, lang := range []string{"en", "zh-CN"} {
				for _, mode := range []string{"body", "raw"} {
					p, err := pages("/api/artifact", url.Values{"run": {run}, "node": {node}, "mode": {mode}, "view_lang": {lang}})
					if err != nil {
						return result, fmt.Errorf("artifact %s: %w", node, err)
					}
					artifacts[lang+"/"+mode+"/"+node] = p
				}
			}
		}
	}
	result.Artifacts, err = w.JSON(artifacts)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, reconcileReplaySessions(sessions, result)
}

func replayComparisonKind(e agentcontext.Entry) string {
	if e.Kind == "message" && e.Role == "user" {
		return "task"
	}
	return e.Kind
}

// Bound the generated pairs, not just the input records or final ZIP bytes.
// This check precedes all pair materialization, including excluded bodies.
func replayComparisonGroups(ctx context.Context, entries []agentcontext.Entry) (map[string][]agentcontext.Entry, error) {
	groups := map[string][]agentcontext.Entry{}
	pairs := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		kind := replayComparisonKind(entry)
		if kind != "task" && kind != "configuration" && kind != "approval" {
			continue
		}
		pairs += 2*len(groups[kind]) + 1
		if pairs > replaySelectionLimit {
			return nil, fmt.Errorf("replay comparison resource limit exceeded: more than %d pairs", replaySelectionLimit)
		}
		groups[kind] = append(groups[kind], entry)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}

// Reconcile independent enumeration against every required per-session index
// before publishing. A successful ZIP must not silently omit a scope.
func reconcileReplaySessions(expected []agentcontext.SessionIdentity, replay ReplayRun) error {
	if len(replay.Sessions) != len(expected) || len(replay.Search) != len(expected)+1 || replay.Search[`["",""]`][""].Path == "" {
		return fmt.Errorf("replay session index count mismatch: expected %d, sessions %d, search scopes %d", len(expected), len(replay.Sessions), len(replay.Search))
	}
	for _, identity := range expected {
		encoded, _ := json.Marshal([]string{identity.Harness, identity.SessionID})
		key := string(encoded)
		session, ok := replay.Sessions[key]
		if !ok || session.Lenses.Path == "" || session.EventIDs == nil || session.Relations[""].Path == "" || replay.Search[key][""].Path == "" || (session.Audit != nil && (session.AuditRelations == nil || session.AuditRelations.Path == "")) {
			return fmt.Errorf("replay session indexes incomplete: %s", key)
		}
	}
	return nil
}
