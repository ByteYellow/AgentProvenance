package agentcontext

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

type SessionRef struct {
	RunID     string   `json:"run_id,omitempty"`
	RunIDs    []string `json:"run_ids,omitempty"`
	Harness   string   `json:"harness"`
	SessionID string   `json:"session_id"`
	Available bool     `json:"available"`
}

type SessionRelationEvidence struct {
	RunID      string `json:"run_id"`
	SourceID   string `json:"source_id"`
	ObjectHash string `json:"object_hash"`
	EntryID    string `json:"entry_id,omitempty"`
	RecordedAt string `json:"recorded_at,omitempty"`
	Basis      string `json:"basis"`
}

type SessionRelation struct {
	ID       string                    `json:"id"`
	Kind     string                    `json:"kind"`
	From     SessionRef                `json:"from"`
	To       SessionRef                `json:"to"`
	Evidence []SessionRelationEvidence `json:"evidence"`
	Issues   []string                  `json:"issues,omitempty"`
}

type SessionRelationsPage struct {
	SchemaVersion string            `json:"schema_version"`
	Subject       SessionRef        `json:"subject"`
	Relations     []SessionRelation `json:"relations"`
	HasMore       bool              `json:"has_more"`
	NextCursor    string            `json:"next_cursor,omitempty"`
	Limit         int               `json:"limit"`
	Limited       bool              `json:"limited"`
	Issues        []string          `json:"issues"`
}

type SessionRelationOptions struct {
	RunID, Harness, SessionID, Cursor string
	Limit                             int
	// Nil queries the local store. A non-nil set confines discovery to the
	// explicitly exported runs; private occurrences never enter a public replay.
	VisibleRuns []string
}

func nativeSession(src Source) bool {
	return src.Harness != "" && src.Harness != "unknown" && src.Harness != "launch" && src.SessionID != "" &&
		src.Channel != "processing" && src.Channel != "discovery" && src.Channel != "runtime_correlation"
}

// SessionRelations is a read projection over immutable source records. It never
// changes run membership or treats shared resources as a session relationship.
func (s Service) SessionRelations(ctx context.Context, opts SessionRelationOptions) (SessionRelationsPage, error) {
	result := SessionRelationsPage{SchemaVersion: SchemaVersion,
		Subject:   SessionRef{RunID: opts.RunID, Harness: opts.Harness, SessionID: opts.SessionID, Available: true},
		Relations: []SessionRelation{}, Issues: []string{}}
	if opts.RunID == "" || opts.Harness == "" || opts.SessionID == "" || len(opts.RunID) > 512 || len(opts.Harness) > 128 || len(opts.SessionID) > 512 {
		return result, fmt.Errorf("%w: run, harness and native session are required", ErrInvalidArgument)
	}
	if opts.Limit == 0 {
		opts.Limit = 50
	}
	if opts.Limit < 1 || opts.Limit > 200 {
		return result, fmt.Errorf("%w: limit must be between 1 and 200", ErrInvalidArgument)
	}
	result.Limit = opts.Limit
	visibility := ""
	args := []any{opts.Harness}
	if opts.VisibleRuns != nil {
		runs, _ := json.Marshal(opts.VisibleRuns)
		visibility = ` AND r.run_id IN (SELECT value FROM json_each(?))`
		args = append(args, string(runs))
	}
	// Prefer the requested identity before the discovery ceiling. A bounded
	// catalog scan also finds parent claims in sources with zero saved entries.
	args = append(args, opts.SessionID, opts.RunID)
	rows, err := s.DB.QueryContext(ctx, `SELECT r.run_id,r.source_id,r.session_id,r.object_hash FROM agent_context_reports r
		WHERE r.harness=?`+visibility+` AND NOT EXISTS (SELECT 1 FROM agent_context_reports n
		 WHERE n.run_id=r.run_id AND n.source_id=r.source_id AND (n.created_at,n.id)>(r.created_at,r.id))
		ORDER BY (r.session_id=?) DESC,(r.run_id=?) DESC,r.run_id,r.source_id LIMIT 1025`, args...)
	if err != nil {
		return result, err
	}
	type sourceRef struct{ run, source, session, hash string }
	refs := []sourceRef{}
	for rows.Next() {
		var ref sourceRef
		if err := rows.Scan(&ref.run, &ref.source, &ref.session, &ref.hash); err != nil {
			rows.Close()
			return result, err
		}
		refs = append(refs, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if len(refs) > 1024 {
		refs = refs[:1024]
		result.Limited = true
		result.Issues = append(result.Issues, "session_source_discovery_limit")
	}
	known := map[string]map[string][]Coverage{}
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		var c Coverage
		if err := provenance.ReadObjectPayload(s.DB, ref.run, ref.hash, &c); err != nil {
			return result, err
		}
		if c.SchemaVersion != SchemaVersion || c.RunID != ref.run || c.Source.ID != ref.source || c.Source.SessionID != ref.session || c.Source.Harness != opts.Harness {
			return result, fmt.Errorf("session report identity mismatch")
		}
		if !nativeSession(c.Source) {
			continue
		}
		c.ObjectHash = ref.hash
		if known[ref.session] == nil {
			known[ref.session] = map[string][]Coverage{}
		}
		known[ref.session][ref.run] = append(known[ref.session][ref.run], c)
	}
	if len(known[opts.SessionID][opts.RunID]) == 0 {
		return result, sql.ErrNoRows
	}
	relations := map[string]*SessionRelation{}
	add := func(kind string, from, to SessionRef, evidence []SessionRelationEvidence, issues ...string) {
		id := "session-relation-" + digest([]any{kind, from, to})
		r := relations[id]
		if r == nil {
			r = &SessionRelation{ID: id, Kind: kind, From: from, To: to, Evidence: []SessionRelationEvidence{}}
			relations[id] = r
		}
		for _, ev := range evidence {
			found := false
			for _, old := range r.Evidence {
				found = found || old == ev
			}
			if !found {
				r.Evidence = append(r.Evidence, ev)
			}
		}
		for _, issue := range issues {
			if issue != "" && !slices.Contains(r.Issues, issue) {
				r.Issues = append(r.Issues, issue)
			}
		}
	}
	refFor := func(run, session string) SessionRef {
		return SessionRef{RunID: run, Harness: opts.Harness, SessionID: session, Available: len(known[session][run]) > 0}
	}
	targets := func(session, preferredRun string) []SessionRef {
		// A same-run occurrence is the local relationship endpoint. If it has
		// not been collected here, expose every known occurrence, not the newest.
		if len(known[session][preferredRun]) > 0 {
			return []SessionRef{refFor(preferredRun, session)}
		}
		out := []SessionRef{}
		for run := range known[session] {
			out = append(out, refFor(run, session))
		}
		sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
		if len(out) > 1 {
			runs := make([]string, 0, len(out))
			for _, ref := range out {
				runs = append(runs, ref.RunID)
			}
			return []SessionRef{{Harness: opts.Harness, SessionID: session, RunIDs: runs, Available: true}}
		}
		if len(out) == 0 {
			out = append(out, SessionRef{Harness: opts.Harness, SessionID: session})
		}
		return out
	}
	evidenceFor := func(c Coverage) SessionRelationEvidence {
		return SessionRelationEvidence{RunID: c.RunID, SourceID: c.Source.ID, ObjectHash: c.ObjectHash, RecordedAt: c.ObservedAt, Basis: "source_parent_session_id"}
	}
	for run, reports := range known[opts.SessionID] {
		if run == opts.RunID {
			continue
		}
		evidence := []SessionRelationEvidence{}
		for _, c := range append(append([]Coverage{}, known[opts.SessionID][opts.RunID]...), reports...) {
			ev := evidenceFor(c)
			ev.Basis = "same_harness_native_session_id"
			evidence = append(evidence, ev)
		}
		add("same_session", result.Subject, refFor(run, opts.SessionID), evidence)
	}
	// Preserve conflicting parent claims rather than selecting a single parent.
	parentSets := map[string]map[string]bool{}
	for child, runs := range known {
		for _, reports := range runs {
			for _, c := range reports {
				if parent := c.Source.ParentSessionID; parent != "" {
					if parentSets[child] == nil {
						parentSets[child] = map[string]bool{}
					}
					parentSets[child][parent] = true
				}
			}
		}
	}
	for child, runs := range known {
		for run, reports := range runs {
			for _, c := range reports {
				parent := c.Source.ParentSessionID
				if parent == "" || (child != opts.SessionID && parent != opts.SessionID) {
					continue
				}
				issues := []string{}
				if parent == child {
					issues = append(issues, "self_parent")
				} else if parentCycle(child, parent, parentSets) {
					issues = append(issues, "parent_cycle")
				}
				if len(parentSets[child]) > 1 {
					issues = append(issues, "conflicting_parents")
				}
				for _, p := range targets(parent, run) {
					add("parent", p, refFor(run, child), []SessionRelationEvidence{evidenceFor(c)}, issues...)
				}
			}
		}
	}
	// Only typed native envelopes carry session relations. Arbitrary prose,
	// shell arguments, Agent display names and prior transcript context do not.
	if err := s.sessionActionRelations(ctx, opts, known, targets, refFor, add, &result); err != nil {
		return result, err
	}
	for _, relation := range relations {
		sort.Slice(relation.Evidence, func(i, j int) bool {
			a, b := relation.Evidence[i], relation.Evidence[j]
			return a.RunID+"/"+a.ObjectHash < b.RunID+"/"+b.ObjectHash
		})
		sort.Strings(relation.Issues)
		result.Relations = append(result.Relations, *relation)
	}
	sort.Slice(result.Relations, func(i, j int) bool { return result.Relations[i].ID < result.Relations[j].ID })
	// Bind pagination to the evidence snapshot. A concurrent import asks the
	// reader to restart instead of silently skipping or repeating relationships.
	fingerprint := digest([]any{result.Subject, opts.VisibleRuns, result.Relations, result.Issues})
	offset := 0
	if opts.Cursor != "" {
		var cursor struct {
			Query  string `json:"query"`
			Offset int    `json:"offset"`
		}
		raw, err := base64.RawURLEncoding.DecodeString(opts.Cursor)
		if len(opts.Cursor) > 8192 || err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Query != fingerprint || cursor.Offset < 0 || cursor.Offset > len(result.Relations) {
			return result, fmt.Errorf("%w: session relation cursor no longer matches the evidence", ErrInvalidArgument)
		}
		offset = cursor.Offset
	}
	end := min(offset+opts.Limit, len(result.Relations))
	result.HasMore = end < len(result.Relations)
	if result.HasMore {
		raw, _ := json.Marshal(map[string]any{"query": fingerprint, "offset": end})
		result.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	result.Relations = result.Relations[offset:end]
	return result, nil
}

func parentCycle(child, parent string, parents map[string]map[string]bool) bool {
	seen, queue := map[string]bool{}, []string{parent}
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if next == child {
			return true
		}
		if seen[next] {
			continue
		}
		seen[next] = true
		for p := range parents[next] {
			queue = append(queue, p)
		}
	}
	return false
}

func (s Service) sessionActionRelations(ctx context.Context, opts SessionRelationOptions, known map[string]map[string][]Coverage,
	targets func(string, string) []SessionRef, refFor func(string, string) SessionRef,
	add func(string, SessionRef, SessionRef, []SessionRelationEvidence, ...string), result *SessionRelationsPage) error {
	sources := []string{}
	for _, runs := range known {
		for _, reports := range runs {
			for _, c := range reports {
				sources = append(sources, c.RunID+"/"+c.Source.ID)
			}
		}
	}
	encoded, _ := json.Marshal(sources)
	rows, err := s.DB.QueryContext(ctx, `SELECT e.run_id,e.id,e.source_id,e.session_id,e.object_hash FROM agent_context_entries e
		WHERE e.run_id || '/' || e.source_id IN (SELECT value FROM json_each(?)) AND `+latestEntry+`
		AND ((e.kind='session' AND e.tool_name='spawn_agent' AND e.status='started')
		 OR (e.kind='configuration' AND e.status='session_metadata')
		 OR (e.kind='tool_call' AND e.tool_name IN ('send_input','functions.send_input')))
		ORDER BY (e.session_id=?) DESC,e.run_id,e.id LIMIT 2049`, string(encoded), opts.SessionID)
	if err != nil {
		return err
	}
	type recordRef struct{ run, id, source, session, hash string }
	refs := []recordRef{}
	for rows.Next() {
		var ref recordRef
		if err := rows.Scan(&ref.run, &ref.id, &ref.source, &ref.session, &ref.hash); err != nil {
			rows.Close()
			return err
		}
		refs = append(refs, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(refs) > 2048 {
		refs = refs[:2048]
		result.Limited = true
		result.Issues = append(result.Issues, "session_action_discovery_limit")
	}
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return err
		}
		var e Entry
		if err := provenance.ReadObjectPayload(s.DB, ref.run, ref.hash, &e); err != nil {
			return err
		}
		if e.SchemaVersion != SchemaVersion || e.RunID != ref.run || e.ID != ref.id || e.Source.ID != ref.source || e.Source.SessionID != ref.session || e.Source.Harness != opts.Harness || len(known[e.Source.SessionID][ref.run]) == 0 {
			return fmt.Errorf("session relation entry identity mismatch")
		}
		if e.Source.Harness != "codex" || e.ExecutionScope == PriorContext {
			continue
		}
		var body map[string]json.RawMessage
		if e.Kind == "configuration" && e.Status == "session_metadata" && e.SessionMetadata != nil {
			// Reconstruct only the native relation fields for the shared projection.
			// The body may be omitted, oversized or unavailable; it is not needed.
			body = row{"id": quoted(e.Source.SessionID), "forked_from_id": quoted(e.SessionMetadata.ForkedFromID)}
		} else {
			if e.Content.State != "stored" {
				if e.Kind == "configuration" && e.Status == "session_metadata" && !slices.Contains(result.Issues, "session_relation_metadata_unavailable") {
					result.Issues = append(result.Issues, "session_relation_metadata_unavailable")
				}
				continue
			}
			page, err := provenance.ReadTextContentPage(s.DB, ref.run, e.Content.Ref, 0, 64<<10)
			if err != nil {
				return err
			}
			if page.HasMore {
				result.Limited = true
				if !slices.Contains(result.Issues, "session_relation_body_limit") {
					result.Issues = append(result.Issues, "session_relation_body_limit")
				}
				continue
			}
			if json.Unmarshal([]byte(page.Content), &body) != nil {
				continue
			}
		}
		value := func(key string) string {
			var v string
			_ = json.Unmarshal(body[key], &v)
			if len(v) > 512 || strings.TrimSpace(v) != v {
				return ""
			}
			return v
		}
		from, to, kind, basis := e.Source.SessionID, "", "", ""
		switch {
		case e.Kind == "session" && e.ToolName == "spawn_agent" && e.Status == "started" && value("parent_session_id") == from:
			to, kind, basis = value("session_id"), "delegation", "native_spawn_result"
		case e.Kind == "configuration" && e.Status == "session_metadata" && value("id") == from:
			from, to, kind, basis = value("forked_from_id"), from, "fork", "native_fork_metadata"
		case e.Kind == "tool_call" && (e.ToolName == "send_input" || e.ToolName == "functions.send_input"):
			to, kind, basis = value("id"), "message_request", "native_send_input_call"
		}
		if from == "" || to == "" || from == to || (from != opts.SessionID && to != opts.SessionID) {
			continue
		}
		ev := SessionRelationEvidence{RunID: e.RunID, SourceID: e.Source.ID, ObjectHash: ref.hash, EntryID: e.ID, RecordedAt: e.RecordedAt, Basis: basis}
		if from == e.Source.SessionID {
			for _, target := range targets(to, ref.run) {
				add(kind, refFor(ref.run, from), target, []SessionRelationEvidence{ev})
			}
		} else {
			for _, parent := range targets(from, ref.run) {
				add(kind, parent, refFor(ref.run, to), []SessionRelationEvidence{ev})
			}
		}
	}
	return nil
}
