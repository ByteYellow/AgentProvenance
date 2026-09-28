package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

type contextIndexFields struct {
	ParentSession string `json:"parent_session_id"`
	Agent         string `json:"agent_id"`
	Key           string `json:"source_key"`
	Sequence      int64  `json:"sequence"`
	Kind          string `json:"kind"`
	Role          string `json:"role"`
	Call          string `json:"tool_call_id"`
	Tool          string `json:"tool_name"`
	Status        string `json:"status"`
	Recorded      string `json:"recorded_at"`
	Ref           string `json:"content_ref"`
	Version       string `json:"parser_version"`
	Harness       string `json:"harness"`
	Observed      string `json:"observed_at"`
}

// Context indexes are projections of signed objects. Verify both the projection
// and every declared body reference, including raw records and full text tails.
func verifyAgentContext(db *sql.DB, runID string, add issueAdder) error {
	for _, table := range []string{"agent_context_entries", "agent_context_reports"} {
		extra := `json_object('parent_session_id',parent_session_id,'agent_id',agent_id,
			'source_key',source_key,'sequence',source_sequence,'kind',kind,'role',role,
			'tool_call_id',tool_call_id,'tool_name',tool_name,'status',status,
			'recorded_at',recorded_at,'content_ref',content_ref,'parser_version',parser_version)`
		if table == "agent_context_reports" {
			extra = `json_object('harness',harness,'status',status,'observed_at',created_at)`
		}
		cursor := ""
		for {
			rows, err := db.Query(`SELECT id, source_id, session_id, object_hash, `+extra+` FROM `+table+` WHERE run_id=? AND id>? ORDER BY id LIMIT 128`, runID, cursor)
			if err != nil {
				return err
			}
			type index struct{ id, source, session, hash, fields string }
			batch := []index{}
			for rows.Next() {
				var v index
				if err := rows.Scan(&v.id, &v.source, &v.session, &v.hash, &v.fields); err != nil {
					rows.Close()
					return err
				}
				batch = append(batch, v)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				break
			}
			checked := map[string]bool{}
			for _, v := range batch {
				var payload struct {
					contextIndexFields
					Schema string `json:"schema_version"`
					ID     string `json:"id"`
					RunID  string `json:"run_id"`
					Source struct {
						ID      string `json:"id"`
						Session string `json:"session_id"`
						Parent  string `json:"parent_session_id"`
						Version string `json:"parser_version"`
						Harness string `json:"harness"`
					} `json:"source"`
					Content    json.RawMessage `json:"content"`
					RawContent json.RawMessage `json:"raw_content"`
				}
				if err := ReadObjectPayload(db, runID, v.hash, &payload); err != nil {
					add("error", "context_object_invalid", v.id, "context object cannot be verified: %v", err)
					continue
				}
				if payload.Schema != "agentprovenance.agent_context/v1" || payload.ID != v.id || payload.RunID != runID || payload.Source.ID != v.source || payload.Source.Session != v.session {
					add("error", "context_index_mismatch", v.id, "context index does not match its evidence object")
				}
				var indexed contextIndexFields
				if err := json.Unmarshal([]byte(v.fields), &indexed); err != nil {
					return err
				}
				actual := payload.contextIndexFields
				if table == "agent_context_entries" {
					actual.ParentSession, actual.Version = payload.Source.Parent, payload.Source.Version
					var body struct {
						Ref string `json:"ref"`
					}
					if err := json.Unmarshal(payload.Content, &body); err != nil {
						add("error", "context_content_invalid", v.id, "context content reference cannot be parsed")
					} else {
						actual.Ref = body.Ref
					}
				} else {
					actual.Harness = payload.Source.Harness
				}
				if actual != indexed {
					add("error", "context_index_mismatch", v.id, "context query fields do not match the evidence object")
				}
				if table != "agent_context_entries" {
					continue
				}
				for _, raw := range []json.RawMessage{payload.Content, payload.RawContent} {
					var ref struct {
						Ref    string `json:"ref"`
						State  string `json:"state"`
						Bytes  *int64 `json:"bytes"`
						SHA256 string `json:"sha256"`
					}
					if json.Unmarshal(raw, &ref) != nil {
						add("error", "context_content_invalid", v.id, "context content reference is invalid")
						continue
					}
					if ref.State != "stored" {
						continue
					}
					page, err := ReadTextContentPage(db, runID, ref.Ref, 0, 4)
					if err == nil && (ref.Bytes == nil || *ref.Bytes != page.TotalBytes || ref.SHA256 != page.SHA256) {
						err = fmt.Errorf("content metadata does not match manifest")
					}
					if err == nil && !checked[ref.Ref] {
						err = VerifyTextContent(db, runID, ref.Ref)
					}
					if err != nil {
						add("error", "context_content_invalid", v.id, "context content cannot be verified: %v", err)
					} else {
						checked[ref.Ref] = true
					}
				}
			}
			cursor = batch[len(batch)-1].id
		}
	}
	return nil
}
