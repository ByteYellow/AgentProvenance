package intent

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

// Contract kinds.
const (
	ContractToolCall      = "tool_call"
	ContractPeerMessage   = "peer_message"
	ContractRefusal       = "refusal"
	ContractModelResponse = "model_response"
)

// assertedConfidence caps how much a hook-derived (model-asserted) contract may
// vouch for itself. The runtime effect it is diffed against is kernel-witnessed
// (confidence ~1.0); the intent side is only what the model CLAIMED, so a
// mismatch's confidence is bounded by this. Mirrors the ai_asserted 0.5 cap the
// correlation layer already uses.
const assertedConfidence = 0.5

// IntentContract is what one agent action declares it should and must-not do.
type IntentContract struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	ScopeAgent   string   `json:"scope_agent"`
	ToolCallID   string   `json:"tool_call_id,omitempty"`
	Operation    string   `json:"operation"`
	Target       string   `json:"target"`
	Profile      Profile  `json:"-"`
	Source       string   `json:"source"`
	Confidence   float64  `json:"confidence"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	ObservedAt   string   `json:"observed_at,omitempty"`
	// A persistent policy is explicitly supplied metadata, never inferred from
	// message wording. Its validity interval is local to this run and agent.
	ScopeKind  string `json:"scope_kind,omitempty"`
	ScopeStart string `json:"scope_start,omitempty"`
	ScopeEnd   string `json:"scope_end,omitempty"`
	// Negative marks a refusal: the agent declared it would NOT do the proposed
	// action, so the baseline sensitive effects become a hard forbid for it.
	Negative bool `json:"negative,omitempty"`
}

// ExtractContracts builds every IntentContract for a run from the captured
// intent surfaces: each agent tool call (via its profile), each peer message
// (governing the recipient), and each refusal (a negative contract).
func ExtractContracts(db *sql.DB, runID string, profiles map[string]Profile) ([]IntentContract, error) {
	return extractContracts(db, runID, profiles)
}

type intentQueryer interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func extractContracts(db intentQueryer, runID string, profiles map[string]Profile) ([]IntentContract, error) {
	var out []IntentContract

	rows, err := db.Query(`SELECT id, agent_id, command, status FROM tool_calls
		WHERE run_id = ? AND agent_id != '' AND command != '' ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, agentID, command, status string
		if err := rows.Scan(&id, &agentID, &command, &status); err != nil {
			rows.Close()
			return nil, err
		}
		if status == "refused" || strings.HasPrefix(id, "refusal-") {
			// A refusal is a negative contract: the agent said it would not act,
			// so any baseline-sensitive effect later attributed to it is a bypass.
			out = append(out, IntentContract{
				ID:           "contract/" + id,
				Kind:         ContractRefusal,
				ScopeAgent:   agentID,
				ToolCallID:   id,
				Operation:    "refusal",
				Target:       strings.TrimPrefix(command, "[llm refusal] "),
				Profile:      Profile{Operation: "refusal"},
				Source:       "refusal " + id,
				Confidence:   assertedConfidence,
				EvidenceRefs: []string{id},
				Negative:     true,
			})
			continue
		}
		op := inferOperation(command)
		out = append(out, IntentContract{
			ID:           "contract/" + id,
			Kind:         ContractToolCall,
			ScopeAgent:   agentID,
			ToolCallID:   id,
			Operation:    op,
			Target:       command,
			Profile:      profileFor(profiles, op),
			Source:       "tool_call " + id,
			Confidence:   assertedConfidence,
			EvidenceRefs: []string{id},
		})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}

	msgs, err := extractMessageContracts(db, runID, profiles)
	if err != nil {
		return nil, err
	}
	out = append(out, msgs...)
	modelContracts, err := extractModelResponseContracts(db, runID)
	if err != nil {
		return nil, err
	}
	out = append(out, modelContracts...)
	return out, nil
}

func extractModelResponseContracts(db intentQueryer, runID string) ([]IntentContract, error) {
	var rootAgent string
	if err := db.QueryRow(`SELECT id FROM agents WHERE run_id = ? AND parent_agent_id = '' ORDER BY created_at,id LIMIT 1`, runID).Scan(&rootAgent); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	var rootToolCall string
	if err := db.QueryRow(`SELECT id FROM tool_calls WHERE run_id = ? ORDER BY started_at,id LIMIT 1`, runID).Scan(&rootToolCall); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	rows, err := db.Query(`SELECT source_id, path, hash FROM provenance_objects
		WHERE run_id = ? AND object_type = 'llm_message' AND source_id LIKE 'endpoint/resp-%' ORDER BY source_id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntentContract
	for rows.Next() {
		var sourceID, path, hash string
		if err := rows.Scan(&sourceID, &path, &hash); err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read model response %s: %w", sourceID, err)
		}
		if fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != hash {
			return nil, fmt.Errorf("model response %s: object hash mismatch", sourceID)
		}
		var obj struct {
			Schema  string `json:"schema"`
			RunID   string `json:"run_id"`
			Payload *struct {
				Semantics struct {
					DeclaredToolCall bool   `json:"declared_tool_call"`
					IntentRole       string `json:"intent_role"`
				} `json:"semantics"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("decode model response %s: %w", sourceID, err)
		}
		if obj.Payload == nil || obj.RunID != runID || obj.Schema != "agentprov.provenance.object.v1" {
			return nil, fmt.Errorf("model response %s: invalid object envelope", sourceID)
		}
		if obj.Payload.Semantics.DeclaredToolCall || obj.Payload.Semantics.IntentRole != "primary" {
			continue
		}
		seq := strings.TrimPrefix(sourceID, "endpoint/resp-")
		out = append(out, IntentContract{
			ID: "contract/endpoint-response-" + seq, Kind: ContractModelResponse,
			ScopeAgent: rootAgent, ToolCallID: rootToolCall, Operation: "text_response",
			Target:  "model returned text without declaring a tool call",
			Profile: Profile{Operation: "text_response"}, Source: sourceID, Confidence: assertedConfidence,
		})
	}
	return out, rows.Err()
}

// Messages retain recipient scope and their content-addressed source. Only
// explicit recipient-side bindings can narrow them to a particular operation.
func extractMessageContracts(db intentQueryer, runID string, profiles map[string]Profile) ([]IntentContract, error) {
	rows, err := db.Query(`SELECT from_id, to_id, created_at FROM graph_edges
		WHERE run_id = ? AND edge_type = 'agent_message'`, runID)
	if err != nil {
		return nil, err
	}
	recipientOf := map[string]map[string]string{} // object -> recipient -> capture time
	for rows.Next() {
		var from, to, at string
		if err := rows.Scan(&from, &to, &at); err != nil {
			rows.Close()
			return nil, err
		}
		if strings.HasPrefix(from, "sha256:") && strings.HasPrefix(to, "agent/") {
			if recipientOf[from] == nil {
				recipientOf[from] = map[string]string{}
			}
			prior, ok := recipientOf[from][to]
			if !ok || earlierMessageTime(at, prior) {
				recipientOf[from][to] = at
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}

	var out []IntentContract
	hashes := make([]string, 0, len(recipientOf))
	for hash := range recipientOf {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	for _, hash := range hashes {
		msg, err := readMessage(db, runID, hash)
		if err != nil {
			return nil, fmt.Errorf("read peer message %s: %w", hash, err)
		}
		if msg.Body == "" {
			continue
		}
		var recipients []string
		for recipient := range recipientOf[hash] {
			recipients = append(recipients, recipient)
		}
		sort.Strings(recipients)
		for _, recipient := range recipients {
			op := inferOperation(msg.Body)
			recipientAgent := strings.TrimPrefix(recipient, "agent/")
			c := IntentContract{
				ID:           fmt.Sprintf("contract/message/%x", sha256.Sum256([]byte(hash+"/"+recipient))),
				Kind:         ContractPeerMessage,
				ScopeAgent:   recipientAgent,
				Operation:    op,
				Target:       msg.Body,
				Profile:      profileFor(profiles, op),
				Source:       hash,
				Confidence:   assertedConfidence,
				EvidenceRefs: []string{hash},
				ObservedAt:   recipientOf[hash][recipient],
			}
			// Explicit metadata is scoped to this recipient. A sender's SendMessage
			// call ID is not the recipient's subsequent execution identity.
			if msg.Scope.AgentID == recipientAgent {
				switch msg.Scope.Kind {
				case "tool_call":
					var agent string
					err := db.QueryRow(`SELECT agent_id FROM tool_calls WHERE run_id=? AND id=?`, runID, msg.Scope.ToolCallID).Scan(&agent)
					if err != nil && err != sql.ErrNoRows {
						return nil, err
					}
					if err == nil && agent == recipientAgent {
						c.ToolCallID = msg.Scope.ToolCallID
					}
				case "agent_policy":
					c.ScopeKind, c.ScopeStart, c.ScopeEnd = "agent_policy", msg.Scope.Start, msg.Scope.End
				}
			}
			out = append(out, c)
		}
	}
	return out, nil
}

type peerMessage struct {
	Body       string `json:"body"`
	Content    string `json:"content"`
	ContentRef string `json:"content_ref"`
	Scope      struct {
		Kind       string `json:"kind"`
		AgentID    string `json:"agent_id"`
		ToolCallID string `json:"tool_call_id"`
		Start      string `json:"valid_from"`
		End        string `json:"valid_until"`
	} `json:"intent_scope"`
}

func earlierMessageTime(a, b string) bool {
	ta, ea := time.Parse(time.RFC3339Nano, a)
	tb, eb := time.Parse(time.RFC3339Nano, b)
	return ea == nil && (eb != nil || ta.Before(tb))
}

func readMessage(db intentQueryer, runID, hash string) (peerMessage, error) {
	var path string
	if err := db.QueryRow(`SELECT path FROM provenance_objects WHERE run_id = ? AND hash = ?`, runID, hash).Scan(&path); err != nil {
		return peerMessage{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return peerMessage{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return peerMessage{}, fmt.Errorf("message object is not a readable regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil {
		return peerMessage{}, err
	}
	if len(raw) > 8<<20 {
		return peerMessage{}, fmt.Errorf("legacy message object exceeds read limit")
	}
	if fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != hash {
		return peerMessage{}, fmt.Errorf("message object hash mismatch")
	}
	var obj struct {
		RunID   string      `json:"run_id"`
		Payload peerMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return peerMessage{}, err
	}
	if obj.RunID != runID {
		return peerMessage{}, fmt.Errorf("message object run mismatch")
	}
	if obj.Payload.ContentRef != "" {
		var body strings.Builder
		for offset := int64(0); ; {
			page, err := provenance.ReadTextContentPage(db, runID, obj.Payload.ContentRef, offset, provenance.MaxContentPageBytes)
			if err != nil {
				return peerMessage{}, err
			}
			body.WriteString(page.Content)
			if !page.HasMore {
				if fmt.Sprintf("%x", sha256.Sum256([]byte(body.String()))) != page.SHA256 {
					return peerMessage{}, fmt.Errorf("message content digest mismatch")
				}
				obj.Payload.Body = body.String()
				return obj.Payload, nil
			}
			if page.NextOffset <= offset {
				return peerMessage{}, fmt.Errorf("message page did not advance")
			}
			offset = page.NextOffset
		}
	}
	if obj.Payload.Body == "" {
		obj.Payload.Body = obj.Payload.Content
	}
	return obj.Payload, nil
}
