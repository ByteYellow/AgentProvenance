package provenance

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AgentTranscript is a sub-agent's own session transcript, located via the hook
// log's agent_transcript_path. The command a sub-agent decided to run lives here,
// not in the main session transcript -- so without harvesting these, a command
// decided by a delegate never becomes an llm_call and can never carry an
// llm_caused edge (the multi-agent half of the demo llm_caused=0 gap).
type AgentTranscript struct {
	AgentID string
	Path    string
}

// TranscriptStream is an already selected, immutable source range. SourceRef
// binds this derived model-call view to the preserved records it was built from.
type TranscriptStream struct {
	AgentID   string
	Reader    io.Reader
	SourceRef string
	// ToolNodes maps native IDs to graph IDs from this stream's stored context.
	// A non-nil map disables fallback to unscoped native IDs.
	ToolNodes map[string]string
}

func HarvestTranscriptStreams(objects ObjectStore, db *sql.DB, runID string, inputs []TranscriptStream) (int, error) {
	if runID == "" || len(inputs) > 256 {
		return 0, fmt.Errorf("invalid transcript stream scope")
	}
	parsed := make([][]transcriptTurn, len(inputs))
	budget := int64(64 << 20)
	seen := map[string]bool{}
	for i, input := range inputs {
		if input.Reader == nil || seen[input.AgentID] {
			return 0, fmt.Errorf("invalid or duplicate transcript stream")
		}
		seen[input.AgentID] = true
		r := &io.LimitedReader{R: input.Reader, N: budget + 1}
		turns, err := parseTranscript(r)
		budget = r.N - 1
		if err != nil || budget < 0 {
			return 0, fmt.Errorf("transcript stream exceeds limits or cannot be parsed")
		}
		parsed[i] = turns
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	objects.Tx = tx
	var decisions []llmDecision
	for i, input := range inputs {
		nodePrefix, _ := transcriptNamespace(input.AgentID)
		for j, turn := range parsed[i] {
			at, _ := time.Parse(time.RFC3339Nano, turn.Timestamp)
			for k, command := range turn.ShellCommands {
				toolID := turn.ShellToolIDs[k]
				if input.ToolNodes != nil {
					toolID = input.ToolNodes[toolID]
				}
				decisions = append(decisions, llmDecision{
					node: fmt.Sprintf("llm_call/%s-%d", nodePrefix, j), command: command,
					at: at, transcript: true, toolID: toolID,
					agentID: turn.AgentID, sessionID: turn.SessionID,
				})
			}
		}
	}
	actions, err := readLLMActions(tx, runID, true)
	if err != nil {
		return 0, err
	}
	matches, err := matchLLMDecisions(decisions, actions)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM provenance_objects WHERE run_id=? AND source_id LIKE 'transcript/%'`, runID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM graph_edges WHERE run_id=? AND from_id LIKE 'llm_call/tr-%'`, runID); err != nil {
		return 0, err
	}
	total, now := 0, time.Now().UTC().Format(time.RFC3339Nano)
	for i, input := range inputs {
		n, err := harvestTranscriptTurns(objects, tx, runID, input.AgentID, now, input.SourceRef, parsed[i])
		if err != nil {
			return 0, err
		}
		total += n
	}
	for i, d := range decisions {
		if action, ok := matches[i]; ok {
			if err := insertLLMEdge(tx, runID, d.node, action, edgeLLMCaused, "", now); err != nil {
				return 0, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

// HarvestTranscriptsFromHookLog harvests every transcript a run's hook log points
// at -- each distinct main session transcript_path AND each sub-agent
// agent_transcript_path -- into the llm_call graph. Unlike the launch path (one
// main + its sub-agents), a hook log can span several main sessions (e.g. the
// double-attempt demo's recon + team runs in one run graph); each is namespaced
// distinctly so none collide or get dropped. This is the reusable entry point for
// pipelines that seal a run outside `launch`.
func HarvestTranscriptsFromHookLog(store ObjectStore, db *sql.DB, runID, hookLogPath string) (int, error) {
	mains, subs, err := transcriptsFromHookLog(hookLogPath)
	if err != nil {
		return 0, err
	}
	entries := make([]AgentTranscript, 0, len(mains)+len(subs))
	for _, m := range mains {
		// Namespace a main by its session file stem so multiple mains stay distinct.
		entries = append(entries, AgentTranscript{AgentID: "session-" + fileStem(m), Path: m})
	}
	entries = append(entries, subs...)
	// mainPath "" -> no empty-namespace main; every transcript is namespaced.
	return HarvestTranscriptSet(store, db, runID, "", entries)
}

// transcriptsFromHookLog reads a hook JSONL log and returns the distinct main
// session transcript paths and the distinct sub-agent transcripts (with agent id).
func transcriptsFromHookLog(path string) (mains []string, subs []AgentTranscript, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("harvest transcripts: open hook log %s: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	seenMain, seenSub := map[string]bool{}, map[string]bool{}
	for sc.Scan() {
		var ev struct {
			TranscriptPath      string `json:"transcript_path"`
			AgentID             string `json:"agent_id"`
			AgentTranscriptPath string `json:"agent_transcript_path"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		if ev.TranscriptPath != "" && !seenMain[ev.TranscriptPath] {
			seenMain[ev.TranscriptPath] = true
			mains = append(mains, ev.TranscriptPath)
		}
		if ev.AgentTranscriptPath != "" && !seenSub[ev.AgentTranscriptPath] {
			seenSub[ev.AgentTranscriptPath] = true
			subs = append(subs, AgentTranscript{AgentID: ev.AgentID, Path: ev.AgentTranscriptPath})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	// A sub-agent path must never also be treated as a main.
	filtered := mains[:0]
	for _, m := range mains {
		if !seenSub[m] {
			filtered = append(filtered, m)
		}
	}
	return filtered, subs, nil
}

// fileStem returns a file's base name without its extension, for use as a
// transcript namespace token.
func fileStem(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// HarvestTranscriptSet harvests the main session transcript and every sub-agent
// transcript into the shared llm_call graph. Sub-agent turns are namespaced by
// agent id so they neither collide with the main turns nor with each other, and
// so a missing/unreadable sub-agent file is skipped rather than aborting the run.
// All readable inputs are parsed and matched together before atomic replacement.
func HarvestTranscriptSet(store ObjectStore, db *sql.DB, runID, mainPath string, subs []AgentTranscript) (int, error) {
	if runID == "" || len(subs) > 255 {
		return 0, fmt.Errorf("invalid transcript file scope")
	}
	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	var inputs []TranscriptStream
	entries := append([]AgentTranscript{{Path: mainPath}}, subs...)
	for i, entry := range entries {
		if entry.Path == "" || (i > 0 && entry.Path == mainPath) {
			continue
		}
		f, err := os.Open(entry.Path)
		if err != nil {
			if i > 0 && os.IsNotExist(err) {
				continue
			}
			return 0, fmt.Errorf("harvest transcript: open %s: %w", entry.Path, err)
		}
		files = append(files, f)
		inputs = append(inputs, TranscriptStream{AgentID: entry.AgentID, Reader: f})
	}
	return HarvestTranscriptStreams(store, db, runID, inputs)
}

func harvestTranscriptTurns(store ObjectStore, writer llmEdgeWriter, runID, agentID, now, sourceRef string, turns []transcriptTurn) (int, error) {
	nodePrefix, srcPrefix := transcriptNamespace(agentID)
	var parents []string
	if sourceRef != "" {
		parents = []string{sourceRef}
	}
	n := 0
	for i, t := range turns {
		reqContent, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"content": t.Prompt}}})
		reqObj, err := store.PutExternalObject(ExternalObjectInput{
			Type: "llm_message", SourceID: fmt.Sprintf("%s/req-%d", srcPrefix, i), RunID: runID,
			Parents: parents,
			Payload: map[string]any{
				"direction": "request", "model": t.Model, "content": string(reqContent),
				"semantics": map[string]any{"model": t.Model, "message_count": 1, "agent_id": agentID},
			},
		})
		if err != nil {
			return n, fmt.Errorf("harvest transcript: request object: %w", err)
		}
		respContent, _ := json.Marshal(map[string]any{"content": t.ContentBlocks, "thinking": t.Thinking, "text": t.Text})
		respObj, err := store.PutExternalObject(ExternalObjectInput{
			Type: "llm_message", SourceID: fmt.Sprintf("%s/resp-%d", srcPrefix, i), RunID: runID,
			Parents: parents,
			Payload: map[string]any{
				"direction": "response", "model": t.Model, "content": string(respContent),
				"semantics": map[string]any{
					"model": t.Model, "tool_calls": t.DecidedTools, "stop_reason": t.StopReason, "agent_id": agentID,
					"timestamp": t.Timestamp, "session_id": t.SessionID, "source_agent_id": t.AgentID, "shell_tool_ids": t.ShellToolIDs,
				},
			},
		})
		if err != nil {
			return n, fmt.Errorf("harvest transcript: response object: %w", err)
		}

		llmNode := fmt.Sprintf("llm_call/%s-%d", nodePrefix, i)
		if err := insertLLMEdge(writer, runID, llmNode, reqObj.Hash, edgeLLMRequest, "", now); err != nil {
			return n, err
		}
		if err := insertLLMEdge(writer, runID, llmNode, respObj.Hash, edgeLLMResponse, "", now); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// transcriptNamespace returns the llm_call node prefix and object source_id
// prefix for a transcript. The empty agentID (main session) keeps the original
// "tr" / "transcript" naming; sub-agents nest under it so the run's existing
// cleanup DELETEs (llm_call/tr-%, source_id LIKE 'transcript/%') still cover them.
func transcriptNamespace(agentID string) (nodePrefix, srcPrefix string) {
	if agentID == "" {
		return "tr", "transcript"
	}
	a := safeGraphID(agentID)
	return "tr-" + a, "transcript/" + a
}

// transcriptTurn is one prompt→assistant exchange distilled from the transcript.
type transcriptTurn struct {
	Prompt        string   // the user prompt that led to this turn
	Model         string   // model that produced the response
	Thinking      string   // the model's reasoning blocks (the "why"/plan)
	Text          string   // the model's visible answer text
	ContentBlocks []any    // raw assistant content blocks (for the response object)
	DecidedTools  []string // readable decided tool calls ("Bash: cat x", "Read: y")
	ShellCommands []string // just the shell commands, for syscall command-match
	ShellToolIDs  []string // tool_use ids, aligned with ShellCommands
	Timestamp     string
	SessionID     string
	AgentID       string
	StopReason    string
}

// transcriptLine is the tolerant projection of one transcript JSONL row.
type transcriptLine struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	SessionID string `json:"sessionId"`
	AgentID   string `json:"agentId"`
	Message   struct {
		Role       string          `json:"role"`
		Model      string          `json:"model"`
		StopReason string          `json:"stop_reason"`
		Content    json.RawMessage `json:"content"` // string (user) OR array (assistant/tool_result)
	} `json:"message"`
}

// parseTranscript walks the JSONL, pairing each assistant message with the most
// recent real user prompt (a string content, not a tool-result array).
func parseTranscript(r io.Reader) ([]transcriptTurn, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var turns []transcriptTurn
	lastPrompt := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var tl transcriptLine
		if json.Unmarshal([]byte(line), &tl) != nil {
			continue
		}
		switch tl.Type {
		case "user":
			// A user prompt is a plain string; a tool_result is an array -- only the
			// former is a real prompt that starts a turn.
			var s string
			if json.Unmarshal(tl.Message.Content, &s) == nil && strings.TrimSpace(s) != "" {
				lastPrompt = s
			}
		case "assistant":
			var blocks []any
			if json.Unmarshal(tl.Message.Content, &blocks) != nil {
				continue
			}
			turn := transcriptTurn{
				Prompt: lastPrompt, Model: tl.Message.Model, StopReason: tl.Message.StopReason,
				Timestamp: tl.Timestamp, SessionID: tl.SessionID, AgentID: tl.AgentID,
				ContentBlocks: blocks,
			}
			collectAssistantBlocks(blocks, &turn)
			// Skip empty assistant turns (pure whitespace, no reasoning/answer/action).
			if turn.Thinking == "" && turn.Text == "" && len(turn.DecidedTools) == 0 {
				continue
			}
			turns = append(turns, turn)
		}
	}
	return turns, sc.Err()
}

// collectAssistantBlocks pulls the reasoning, decided tools, and shell commands
// out of an assistant message's content blocks.
func collectAssistantBlocks(blocks []any, turn *transcriptTurn) {
	var thinking, text []string
	for _, b := range blocks {
		m, ok := b.(map[string]any)
		if !ok {
			continue
		}
		switch m["type"] {
		case "thinking":
			if s, _ := m["thinking"].(string); s != "" {
				thinking = append(thinking, s)
			}
		case "text":
			if s, _ := m["text"].(string); s != "" {
				text = append(text, s)
			}
		case "tool_use":
			name, _ := m["name"].(string)
			input, _ := m["input"].(map[string]any)
			label, shell := describeToolUse(name, input)
			if label != "" {
				turn.DecidedTools = append(turn.DecidedTools, label)
			}
			if shell != "" {
				turn.ShellCommands = append(turn.ShellCommands, shell)
				id, _ := m["id"].(string)
				turn.ShellToolIDs = append(turn.ShellToolIDs, id)
			}
		}
	}
	turn.Thinking = strings.Join(thinking, "\n")
	turn.Text = strings.Join(text, "\n")
}

// describeToolUse renders a readable label for a decided tool call and, when it
// is a shell command, the raw command for syscall matching.
func describeToolUse(name string, input map[string]any) (label, shell string) {
	str := func(k string) string { s, _ := input[k].(string); return s }
	switch name {
	case "Bash":
		cmd := str("command")
		return "Bash: " + cmd, cmd
	case "Read":
		return "Read: " + str("file_path"), ""
	case "Write", "Edit":
		return name + ": " + str("file_path"), ""
	case "SendMessage":
		return "SendMessage → " + firstNonEmpty(str("recipient"), str("to")), ""
	default:
		if name == "" {
			return "", ""
		}
		return name, ""
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
