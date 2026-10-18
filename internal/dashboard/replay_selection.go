package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
)

const replaySelectionLimit = 1000000

// ReplaySelection defines a sharing copy, without changing the saved evidence.
// Record IDs use the existing search catalog, including entry/<id>.
type ReplaySelection struct {
	RunID             string   `json:"run_id"`
	Scope             string   `json:"scope"`
	Harness           string   `json:"harness,omitempty"`
	SessionID         string   `json:"session_id,omitempty"`
	ExcludeRecords    []string `json:"exclude_records,omitempty"`
	ExcludeCategories []string `json:"exclude_categories,omitempty"`
}

type replayRecordDecision struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Node          string `json:"node,omitempty"`
	Indexed       bool   `json:"indexed"`
	Included      bool   `json:"included"`
	Reason        string `json:"reason,omitempty"`
	RelatedRecord string `json:"related_record,omitempty"`
}

type replaySelectionWarning struct {
	Code          string   `json:"code"`
	ContentSHA256 string   `json:"content_sha256"`
	Included      []string `json:"included_records"`
	Excluded      []string `json:"excluded_records"`
	IncludedCount int      `json:"included_count"`
	ExcludedCount int      `json:"excluded_count"`
}

// The preview uses this bounded summary instead of loading the complete record
// manifest into the browser. Detailed membership remains in record-selection.json.
type ReplaySelectionSummary struct {
	Selection    ReplaySelection          `json:"selection"`
	Included     int                      `json:"included_records"`
	Excluded     int                      `json:"excluded_records"`
	Reasons      map[string]int           `json:"exclusion_reasons"`
	Warnings     []replaySelectionWarning `json:"warnings,omitempty"`
	WarningCount int                      `json:"warning_count"`
}

func (p *replaySelectionPlan) summary() ReplaySelectionSummary {
	s := ReplaySelectionSummary{Selection: p.Selection, Reasons: map[string]int{}, Warnings: p.Warnings, WarningCount: p.WarningCount}
	for _, record := range p.Records {
		if record.Included {
			s.Included++
		} else {
			s.Excluded++
			s.Reasons[record.Reason]++
		}
	}
	return s
}

type replaySelectionPlan struct {
	Selection ReplaySelection
	Records   []replayRecordDecision
	Entries   map[string]agentcontext.Entry
	// Every alias of an omitted record is denied, including its CAS envelope.
	DeniedNodes map[string]string
	// A source line may contain multiple normalized entries. Its raw reader is
	// withheld if even one entry is outside the selection; normalized siblings
	// remain independently readable.
	WithheldContent map[string]string
	Warnings        []replaySelectionWarning
	WarningCount    int
	SHA256          string
}

func (selection ReplaySelection) normalized() (ReplaySelection, error) {
	invalid := func(message string) (ReplaySelection, error) {
		return ReplaySelection{}, fmt.Errorf("%w: %s", agentcontext.ErrInvalidArgument, message)
	}
	if selection.RunID == "" || len(selection.RunID) > 512 || len(selection.Harness) > 128 || len(selection.SessionID) > 512 {
		return invalid("invalid replay identity")
	}
	switch selection.Scope {
	case "whole_run":
		if selection.Harness != "" || selection.SessionID != "" {
			return invalid("whole-run selection must not contain a session filter")
		}
	case "session":
		if selection.Harness == "" || selection.SessionID == "" {
			return invalid("session selection requires harness and session")
		}
	default:
		return invalid("unknown replay scope")
	}
	if len(selection.ExcludeRecords) > 4096 || len(selection.ExcludeCategories) > 5 {
		return invalid("replay exclusion list exceeds its limit")
	}
	for _, id := range selection.ExcludeRecords {
		if id == "" || len(id) > 1024 {
			return invalid("invalid replay record identifier")
		}
	}
	for _, category := range selection.ExcludeCategories {
		if !slices.Contains([]string{"messages", "tools", "configuration", "files", "runtime"}, category) {
			return invalid("unknown replay record category")
		}
	}
	selection.ExcludeRecords = sortedReplayStrings(selection.ExcludeRecords)
	selection.ExcludeCategories = sortedReplayStrings(selection.ExcludeCategories)
	return selection, nil
}

func sortedReplayStrings(values []string) []string {
	values = slices.Clone(values)
	sort.Strings(values)
	return slices.Compact(values)
}

func replayEntryKey(entry agentcontext.Entry) string {
	key, _ := json.Marshal([]string{entry.Source.ID, entry.SourceKey, entry.Kind})
	return string(key)
}

func replayEntryCategory(entry agentcontext.Entry) string {
	switch entry.Kind {
	case "tool_call", "tool_result":
		return "tools"
	case "configuration", "approval", "session":
		return "configuration"
	default:
		return "messages"
	}
}

// resolveReplaySelection must run against the export's private frozen database.
// It resolves only saved relationships, without reading workspace files or
// widening membership through a shared PID, path, cgroup or parent session.
func (s Server) resolveReplaySelection(ctx context.Context, input ReplaySelection) (*replaySelectionPlan, error) {
	selection, err := input.normalized()
	if err != nil {
		return nil, err
	}
	p := &replaySelectionPlan{Selection: selection, Entries: map[string]agentcontext.Entry{},
		DeniedNodes: map[string]string{}, WithheldContent: map[string]string{}, Warnings: []replaySelectionWarning{}}
	var exists bool
	if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE run_id=?)
		OR EXISTS(SELECT 1 FROM tool_calls WHERE run_id=?)
		OR EXISTS(SELECT 1 FROM provenance_objects WHERE run_id=?)
		OR EXISTS(SELECT 1 FROM agent_context_reports WHERE run_id=?)
		OR EXISTS(SELECT 1 FROM agent_context_entries WHERE run_id=?)`,
		selection.RunID, selection.RunID, selection.RunID, selection.RunID, selection.RunID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, sql.ErrNoRows
	}
	records := map[string]replayRecordDecision{}
	eligible := map[string]bool{}
	sourceIDs := map[string]bool{}
	service := agentcontext.Service{DB: s.DB}
	if selection.Scope == "session" {
		scope, err := s.sessionGraphScope(ctx, selection.RunID, selection.Harness, selection.SessionID)
		if err != nil {
			return nil, err
		}
		for _, id := range scope.SourceIDs {
			sourceIDs[id] = true
		}
		nodes := slices.Clone(scope.ToolIDs)
		for _, id := range scope.ToolIDs {
			eligible["2/"+id] = true
		}
		for _, id := range scope.EventIDs {
			eligible["3/"+id] = true
			nodes = append(nodes, "runtime_event/"+id)
		}
		encoded, err := json.Marshal(nodes)
		if err != nil {
			return nil, err
		}
		// Resolve the session once, not again for every search-catalog page.
		rows, err := s.DB.QueryContext(ctx, `SELECT o.hash FROM provenance_objects o
			WHERE o.run_id=? AND o.object_type IN ('artifact','llm_message') AND `+savedObjectScopePredicate,
			selection.RunID, string(encoded), string(encoded))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				rows.Close()
				return nil, err
			}
			eligible["1/"+hash] = true
			if len(eligible) > replaySelectionLimit {
				rows.Close()
				return nil, fmt.Errorf("replay record selection exceeds %d records", replaySelectionLimit)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	for _, revisions := range []bool{false, true} {
		// Read immutable context metadata through its normal verifier. Other
		// source catalogs below need only IDs, not bodies or per-row lookups.
		cursor := ""
		for {
			page, err := service.Entries(ctx, agentcontext.PageOptions{RunID: selection.RunID, IncludeRevisions: revisions, Cursor: cursor, Limit: 200})
			if err != nil {
				return nil, err
			}
			for _, entry := range page.Entries {
				id := "entry/" + entry.ID
				p.Entries[entry.ID] = entry
				if _, exists := records[id]; !exists {
					records[id] = replayRecordDecision{ID: id, Node: entry.ObjectHash, Category: replayEntryCategory(entry), Indexed: !revisions}
				}
				if selection.Scope == "session" {
					eligible[id] = sourceIDs[entry.Source.ID] && entry.Source.Harness == selection.Harness && entry.Source.SessionID == selection.SessionID
				}
			}
			if len(records) > replaySelectionLimit {
				return nil, fmt.Errorf("replay record selection exceeds %d records", replaySelectionLimit)
			}
			if !page.HasMore {
				break
			}
			cursor = page.NextCursor
		}
	}
	for _, source := range []struct{ prefix, nodePrefix, category, query string }{
		{"1/", "", "files", `SELECT hash,object_type,source_id FROM provenance_objects WHERE run_id=? AND object_type IN ('artifact','llm_message') ORDER BY hash LIMIT ?`},
		{"2/", "", "tools", `SELECT id,'','' FROM tool_calls WHERE run_id=? ORDER BY id LIMIT ?`},
		{"3/", "runtime_event/", "runtime", `SELECT id,'','' FROM events WHERE run_id=? ORDER BY id LIMIT ?`},
	} {
		rows, err := s.DB.QueryContext(ctx, source.query, selection.RunID, replaySelectionLimit-len(records)+1)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, kind, origin string
			if err := rows.Scan(&id, &kind, &origin); err != nil {
				rows.Close()
				return nil, err
			}
			category := source.category
			if kind == "llm_message" || strings.HasPrefix(origin, "agent_message/") {
				category = "messages"
			}
			records[source.prefix+id] = replayRecordDecision{ID: source.prefix + id, Node: source.nodePrefix + id, Category: category, Indexed: true}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if len(records) > replaySelectionLimit {
			return nil, fmt.Errorf("replay record selection exceeds %d records", replaySelectionLimit)
		}
	}
	inScope := func(id string) bool { return selection.Scope == "whole_run" || eligible[id] }
	exclusions := map[string]bool{}
	for _, id := range selection.ExcludeRecords {
		if _, exists := records[id]; !exists || !inScope(id) {
			return nil, fmt.Errorf("%w: excluded record is absent or outside the selected scope: %s", agentcontext.ErrInvalidArgument, id)
		}
		exclusions[id] = true
	}

	groups := newReplayRecordGroups()
	byKey, byObject := map[string]string{}, map[string]string{}
	for id, entry := range p.Entries {
		record := "entry/" + id
		key := replayEntryKey(entry)
		if previous := byKey[key]; previous != "" {
			groups.join(previous, record)
		}
		byKey[key], byObject[entry.ObjectHash] = record, record
	}
	// A saved context call/result and its projected tool record are multiple
	// readers of one invocation. Excluding one omits the linked readers too;
	// runtime effects remain independent records and never join this group.
	rows, err := s.DB.QueryContext(ctx, `SELECT g.from_id,g.to_id FROM graph_edges g
		JOIN tool_calls t ON t.run_id=g.run_id AND t.id=g.to_id
		WHERE g.run_id=? AND g.edge_type IN ('context_tool_call','context_tool_result')
		ORDER BY g.from_id,g.to_id`, selection.RunID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var hash, tool string
		if err := rows.Scan(&hash, &tool); err != nil {
			rows.Close()
			return nil, err
		}
		if entryID := byObject[hash]; entryID != "" && p.Entries[strings.TrimPrefix(entryID, "entry/")].ExecutionScope != agentcontext.PriorContext {
			groups.join(entryID, "2/"+tool)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	seeds := map[string]string{}
	for _, id := range ids {
		r := records[id]
		switch {
		case !inScope(id):
			r.Reason = "outside_scope"
		case exclusions[id]:
			r.Reason = "excluded_record"
		case slices.Contains(selection.ExcludeCategories, r.Category):
			r.Reason = "excluded_category"
		default:
			r.Included = true
		}
		if !r.Included && r.Reason != "outside_scope" && seeds[groups.root(id)] == "" {
			seeds[groups.root(id)] = id
		}
		records[id] = r
	}
	p.Records = make([]replayRecordDecision, 0, len(records))
	for _, id := range ids {
		r := records[id]
		if seed := seeds[groups.root(id)]; r.Included && seed != "" {
			r.Included, r.Reason, r.RelatedRecord = false, "linked_record_excluded", seed
		}
		if !r.Included && r.Node != "" {
			p.DeniedNodes[r.Node] = r.Reason
		}
		p.Records = append(p.Records, r)
		records[id] = r
	}
	if err := p.addObjectAliases(ctx, s); err != nil {
		return nil, err
	}
	p.resolveContentBoundaries(records)
	fingerprint, err := json.Marshal(struct {
		Selection       ReplaySelection
		Records         []replayRecordDecision
		DeniedNodes     map[string]string
		WithheldContent map[string]string
	}{p.Selection, p.Records, p.DeniedNodes, p.WithheldContent})
	if err != nil {
		return nil, err
	}
	p.SHA256 = replayDigest(fingerprint)
	return p, ctx.Err()
}

func (p *replaySelectionPlan) addObjectAliases(ctx context.Context, s Server) error {
	if len(p.DeniedNodes) == 0 {
		return ctx.Err()
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT hash,object_type,source_id FROM provenance_objects
		WHERE run_id=? AND object_type IN ('event','tool_call','agent_context') ORDER BY hash`, p.Selection.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var hash, kind, source string
		if err := rows.Scan(&hash, &kind, &source); err != nil {
			return err
		}
		node := source
		if kind == "event" {
			node = "runtime_event/" + source
		} else if kind == "agent_context" {
			if entry, ok := p.Entries[source]; ok {
				node = entry.ObjectHash
			}
		}
		if reason := p.DeniedNodes[node]; reason != "" {
			p.DeniedNodes[hash] = reason
		}
	}
	return rows.Err()
}

func (p *replaySelectionPlan) resolveContentBoundaries(records map[string]replayRecordDecision) {
	type copies struct{ included, excluded []string }
	byContent := map[string]*copies{}
	type rawLine struct {
		source   string
		sequence int64
	}
	withheldLines := map[rawLine]bool{}
	retainedBodies := map[string]bool{}
	for id, entry := range p.Entries {
		if !records["entry/"+id].Included {
			withheldLines[rawLine{entry.Source.ID, entry.Sequence}] = true
		} else if entry.Content.State == "stored" {
			retainedBodies[entry.Content.Ref] = true
		}
	}
	for id, entry := range p.Entries {
		r := records["entry/"+id]
		if !r.Included && entry.Content.State == "stored" && entry.Content.Ref != "" && !retainedBodies[entry.Content.Ref] {
			p.WithheldContent[entry.Content.Ref] = "record_excluded"
		}
		if withheldLines[rawLine{entry.Source.ID, entry.Sequence}] && entry.RawContent.State == "stored" && entry.RawContent.Ref != "" {
			p.WithheldContent[entry.RawContent.Ref] = "shared_raw_record_excluded"
		}
		if withheldLines[rawLine{entry.Source.ID, entry.Sequence}] && entry.IntentContent != nil && entry.IntentContent.Ref != "" {
			p.WithheldContent[entry.IntentContent.Ref] = "shared_intent_record_excluded"
		}
		if entry.Content.State != "stored" || entry.Content.SHA256 == "" {
			continue
		}
		c := byContent[entry.Content.SHA256]
		if c == nil {
			c = &copies{}
			byContent[entry.Content.SHA256] = c
		}
		if r.Included {
			c.included = append(c.included, r.ID)
		} else {
			c.excluded = append(c.excluded, r.ID)
		}
	}
	for ref, reason := range p.WithheldContent {
		p.DeniedNodes[ref] = reason
	}
	keys := make([]string, 0, len(byContent))
	for hash := range byContent {
		keys = append(keys, hash)
	}
	sort.Strings(keys)
	for _, hash := range keys {
		c := byContent[hash]
		if len(c.included) == 0 || len(c.excluded) == 0 {
			continue
		}
		p.WarningCount++
		if len(p.Warnings) == 100 {
			continue
		}
		sort.Strings(c.included)
		sort.Strings(c.excluded)
		p.Warnings = append(p.Warnings, replaySelectionWarning{Code: "same_content_in_retained_record", ContentSHA256: hash,
			Included: c.included[:min(len(c.included), 10)], Excluded: c.excluded[:min(len(c.excluded), 10)],
			IncludedCount: len(c.included), ExcludedCount: len(c.excluded)})
	}
}

// Union by size bounds chained alias/revision lookups even for long histories.
type replayRecordGroups struct {
	parent map[string]string
	size   map[string]int
}

func newReplayRecordGroups() *replayRecordGroups {
	return &replayRecordGroups{parent: map[string]string{}, size: map[string]int{}}
}

func (g *replayRecordGroups) root(id string) string {
	if g.parent[id] == "" {
		return id
	}
	root := id
	for g.parent[root] != root {
		root = g.parent[root]
	}
	for id != root {
		next := g.parent[id]
		g.parent[id], id = root, next
	}
	return root
}

func (g *replayRecordGroups) join(a, b string) {
	a, b = g.root(a), g.root(b)
	if a == b {
		return
	}
	for _, id := range []string{a, b} {
		if g.parent[id] == "" {
			g.parent[id], g.size[id] = id, 1
		}
	}
	if g.size[a] < g.size[b] {
		a, b = b, a
	}
	g.parent[b] = a
	g.size[a] += g.size[b]
}
