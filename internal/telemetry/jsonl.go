package telemetry

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

type JSONLIngestOptions struct {
	Format     string
	Path       string
	RunID      string
	SessionID  string
	AttemptID  string
	ToolCallID string
	ProcessID  string
	SnapshotID string
	RolloutID  string
}

type FalcoIngestOptions struct {
	Path       string
	RunID      string
	SessionID  string
	AttemptID  string
	ToolCallID string
	ProcessID  string
	SnapshotID string
	RolloutID  string
}

type JSONLIngestResult struct {
	BatchID        string   `json:"batch_id,omitempty"`
	Format         string   `json:"format"`
	Path           string   `json:"path"`
	FileSHA256     string   `json:"file_sha256,omitempty"`
	Read           int      `json:"read"`
	Ingested       int      `json:"ingested"`
	Skipped        int      `json:"skipped"`
	Failed         int      `json:"failed"`
	EventIDs       []string `json:"event_ids,omitempty"`
	EventIDsSHA256 string   `json:"event_ids_sha256,omitempty"`
	Errors         []string `json:"errors,omitempty"`
}

func IngestJSONL(db *sql.DB, opts JSONLIngestOptions) (JSONLIngestResult, error) {
	if strings.TrimSpace(opts.Path) == "" {
		return JSONLIngestResult{}, fmt.Errorf("jsonl path is required")
	}
	opts.Format = strings.TrimSpace(opts.Format)
	if opts.Format == "" {
		opts.Format = "auto"
	}
	fileHash, err := hashFile(opts.Path)
	if err != nil {
		return JSONLIngestResult{}, err
	}
	file, err := os.Open(opts.Path)
	if err != nil {
		return JSONLIngestResult{}, err
	}
	defer file.Close()
	result := JSONLIngestResult{Format: opts.Format, Path: opts.Path, FileSHA256: fileHash}
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		result.Read++
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("line %d: invalid JSON: %v", lineNo, err))
			continue
		}
		event, ok, err := mapJSONLEvent(opts, raw, lineNo)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("line %d: %v", lineNo, err))
			continue
		}
		if !ok {
			result.Skipped++
			continue
		}
		id, err := IngestFiltered(db, event)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("line %d: ingest failed: %v", lineNo, err))
			continue
		}
		result.Ingested++
		result.EventIDs = append(result.EventIDs, id)
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	result.EventIDsSHA256 = hashStrings(result.EventIDs)
	if err := persistJSONLBatch(db, opts, &result); err != nil {
		return result, err
	}
	return result, nil
}

func IngestFalco(db *sql.DB, opts FalcoIngestOptions, input io.Reader) (JSONLIngestResult, error) {
	if input == nil {
		return JSONLIngestResult{}, fmt.Errorf("falco input reader is required")
	}
	path := strings.TrimSpace(opts.Path)
	if path == "" {
		path = "stdin"
	}
	jsonlOpts := JSONLIngestOptions{
		Format:     "falco",
		Path:       path,
		RunID:      opts.RunID,
		SessionID:  opts.SessionID,
		AttemptID:  opts.AttemptID,
		ToolCallID: opts.ToolCallID,
		ProcessID:  opts.ProcessID,
		SnapshotID: opts.SnapshotID,
		RolloutID:  opts.RolloutID,
	}
	hasher := sha256.New()
	result := JSONLIngestResult{Format: "falco", Path: path}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		rawLine := scanner.Bytes()
		_, _ = hasher.Write(rawLine)
		_, _ = hasher.Write([]byte{'\n'})
		line := strings.TrimSpace(string(rawLine))
		if line == "" {
			continue
		}
		result.Read++
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("line %d: invalid JSON: %v", lineNo, err))
			continue
		}
		event, ok, err := mapJSONLEvent(jsonlOpts, raw, lineNo)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("line %d: %v", lineNo, err))
			continue
		}
		if !ok {
			result.Skipped++
			continue
		}
		id, err := IngestFiltered(db, event)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("line %d: ingest failed: %v", lineNo, err))
			continue
		}
		result.Ingested++
		result.EventIDs = append(result.EventIDs, id)
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	result.FileSHA256 = hex.EncodeToString(hasher.Sum(nil))
	result.EventIDsSHA256 = hashStrings(result.EventIDs)
	if err := persistJSONLBatch(db, jsonlOpts, &result); err != nil {
		return result, err
	}
	return result, nil
}

func persistJSONLBatch(db *sql.DB, opts JSONLIngestOptions, result *JSONLIngestResult) error {
	if result == nil {
		return nil
	}
	batchID := ids.New("telbatch")
	eventIDsJSON, err := json.Marshal(result.EventIDs)
	if err != nil {
		return err
	}
	runID := strings.TrimSpace(opts.RunID)
	if runID == "" {
		inferred, err := inferSingleRunID(db, result.EventIDs)
		if err != nil {
			return err
		}
		runID = inferred
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO telemetry_batches
		(id, run_id, format, path, file_sha256, read_count, ingested_count, skipped_count, failed_count, event_ids_json, event_ids_sha256, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		batchID, runID, result.Format, result.Path, result.FileSHA256, result.Read, result.Ingested, result.Skipped, result.Failed, string(eventIDsJSON), result.EventIDsSHA256, now); err != nil {
		return err
	}
	result.BatchID = batchID
	return nil
}

func inferSingleRunID(db *sql.DB, eventIDs []string) (string, error) {
	if len(eventIDs) == 0 {
		return "", nil
	}
	runIDs := map[string]struct{}{}
	for _, eventID := range eventIDs {
		var runID string
		if err := db.QueryRow(`SELECT COALESCE(run_id, '') FROM events WHERE id = ?`, eventID).Scan(&runID); err != nil {
			return "", err
		}
		if strings.TrimSpace(runID) != "" {
			runIDs[runID] = struct{}{}
		}
	}
	if len(runIDs) != 1 {
		return "", nil
	}
	for runID := range runIDs {
		return runID, nil
	}
	return "", nil
}

func mapJSONLEvent(opts JSONLIngestOptions, raw map[string]any, lineNo int) (IngestEvent, bool, error) {
	format := opts.Format
	if format == "auto" {
		format = detectFormat(raw)
	}
	var event IngestEvent
	var ok bool
	var err error
	switch format {
	case "tetragon":
		event, ok, err = mapTetragon(raw)
	case "falco":
		event, ok, err = mapFalco(raw)
	case "loongcollector":
		event, ok, err = mapLoongCollector(raw)
	default:
		return IngestEvent{}, false, fmt.Errorf("unsupported telemetry jsonl format %q", opts.Format)
	}
	if err != nil || !ok {
		return event, ok, err
	}
	event.RunID = firstNonEmpty(event.RunID, opts.RunID)
	event.RolloutID = firstNonEmpty(event.RolloutID, opts.RolloutID)
	event.AttemptID = firstNonEmpty(event.AttemptID, opts.AttemptID)
	event.SessionID = firstNonEmpty(event.SessionID, opts.SessionID)
	event.ToolCallID = firstNonEmpty(event.ToolCallID, opts.ToolCallID)
	event.ProcessID = firstNonEmpty(event.ProcessID, opts.ProcessID)
	event.SnapshotID = firstNonEmpty(event.SnapshotID, opts.SnapshotID)
	if event.RawEventID == "" {
		event.RawEventID = fmt.Sprintf("%s:%d", format, lineNo)
	}
	return event, true, nil
}

func detectFormat(raw map[string]any) string {
	if _, ok := raw["process_exec"]; ok {
		return "tetragon"
	}
	if _, ok := raw["process_exit"]; ok {
		return "tetragon"
	}
	if _, ok := raw["output_fields"]; ok {
		return "falco"
	}
	if stringAt(raw, "source") == "loongcollector" || stringAt(raw, "__tag__:__path__") != "" {
		return "loongcollector"
	}
	return "loongcollector"
}

func mapTetragon(raw map[string]any) (IngestEvent, bool, error) {
	event := baseMappedEvent(raw, "tetragon_jsonl")
	if exec, ok := nestedMap(raw, "process_exec"); ok {
		proc, _ := nestedMap(exec, "process")
		event.EventType = "execve"
		event.PID = firstInt(event.PID, intAt(proc, "pid"))
		event.PPID = firstInt(event.PPID, intAt(proc, "parent_exec_id"))
		event.ContainerID = firstNonEmpty(event.ContainerID, stringAt(proc, "docker"))
		argv := tetragonArgv(proc)
		event.Payload = mustJSON(map[string]any{"argv": argv})
		return event, true, nil
	}
	if exit, ok := nestedMap(raw, "process_exit"); ok {
		proc, _ := nestedMap(exit, "process")
		event.EventType = "process_exit"
		event.PID = firstInt(event.PID, intAt(proc, "pid"))
		event.Payload = mustJSON(map[string]any{"exit_code": intAt(exit, "status")})
		return event, true, nil
	}
	return event, false, nil
}

func tetragonArgv(proc map[string]any) []string {
	binary := stringAt(proc, "binary")
	args := splitCommand(stringAt(proc, "arguments"))
	if binary != "" {
		return append([]string{binary}, args...)
	}
	if len(args) > 0 {
		return args
	}
	return []string{"unknown"}
}

func mapFalco(raw map[string]any) (IngestEvent, bool, error) {
	fields, ok := nestedMap(raw, "output_fields")
	if !ok {
		return IngestEvent{}, false, nil
	}
	event := baseMappedEvent(raw, "falco_jsonl")
	event.PID = firstInt(event.PID, intAt(fields, "proc.pid"))
	event.PPID = firstInt(event.PPID, intAt(fields, "proc.ppid"))
	event.ContainerID = firstNonEmpty(event.ContainerID, stringAt(fields, "container.id"))
	event.CgroupID = firstNonEmpty(event.CgroupID, stringAt(fields, "container.cgroup"), stringAt(fields, "proc.cgroup"))
	evtType := strings.ToLower(firstNonEmpty(stringAt(fields, "evt.type"), stringAt(raw, "evt.type")))
	switch evtType {
	case "execve", "execveat", "spawned_process":
		event.EventType = "execve"
		argv := splitCommand(firstNonEmpty(stringAt(fields, "proc.cmdline"), stringAt(fields, "proc.exepath")))
		if len(argv) == 0 {
			argv = []string{"unknown"}
		}
		event.Payload = mustJSON(map[string]any{
			"argv":       argv,
			"command":    strings.Join(argv, " "),
			"rule":       firstNonEmpty(stringAt(raw, "rule"), stringAt(raw, "output")),
			"priority":   stringAt(raw, "priority"),
			"falco_time": stringAt(raw, "time"),
		})
	case "open", "openat", "openat2", "creat":
		path := firstNonEmpty(stringAt(fields, "fd.name"), stringAt(fields, "evt.arg.path"), stringAt(fields, "evt.arg.name"))
		flags := firstNonEmpty(stringAt(fields, "evt.arg.flags"), stringAt(fields, "evt.args"))
		if secretPath(path) {
			event.EventType = "secret_path"
		} else if writeOpenFlags(flags) {
			event.EventType = "file_write"
		} else {
			event.EventType = "file_open"
		}
		event.Payload = mustJSON(map[string]any{
			"path":       path,
			"flags":      flags,
			"rule":       firstNonEmpty(stringAt(raw, "rule"), stringAt(raw, "output")),
			"priority":   stringAt(raw, "priority"),
			"falco_time": stringAt(raw, "time"),
		})
	case "connect":
		event.EventType = "network_connect"
		dst := firstNonEmpty(stringAt(fields, "fd.rip"), stringAt(fields, "fd.name"), stringAt(fields, "fd.sip"))
		host, port := splitFalcoDestination(dst)
		if host == "169.254.169.254" {
			event.EventType = "metadata_ip"
		} else if privateIP(host) {
			event.EventType = "private_cidr"
		}
		event.Payload = mustJSON(map[string]any{
			"dst":        dst,
			"dst_ip":     host,
			"host":       host,
			"port":       port,
			"rule":       firstNonEmpty(stringAt(raw, "rule"), stringAt(raw, "output")),
			"priority":   stringAt(raw, "priority"),
			"falco_time": stringAt(raw, "time"),
		})
	default:
		return IngestEvent{}, false, nil
	}
	return event, true, nil
}

func splitFalcoDestination(dst string) (string, string) {
	dst = strings.TrimSpace(dst)
	if dst == "" {
		return "", ""
	}
	if host, port, err := net.SplitHostPort(dst); err == nil {
		return strings.Trim(host, "[]"), port
	}
	if idx := strings.LastIndex(dst, ":"); idx > -1 && strings.Count(dst, ":") == 1 {
		return dst[:idx], dst[idx+1:]
	}
	return strings.Trim(dst, "[]"), ""
}

func privateIP(raw string) bool {
	ip := net.ParseIP(strings.Trim(raw, "[]"))
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback())
}

func secretPath(path string) bool {
	path = strings.ToLower(path)
	for _, pattern := range []string{".env", "id_rsa", "secret", "credentials"} {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

func writeOpenFlags(flags string) bool {
	flags = strings.ToLower(flags)
	for _, pattern := range []string{"o_wronly", "o_rdwr", "o_creat", "o_trunc", "write"} {
		if strings.Contains(flags, pattern) {
			return true
		}
	}
	return false
}

func mapLoongCollector(raw map[string]any) (IngestEvent, bool, error) {
	event := baseMappedEvent(raw, "loongcollector_jsonl")
	rawType := strings.ToLower(firstNonEmpty(stringAt(raw, "event_type"), stringAt(raw, "type"), stringAt(raw, "event.name")))
	switch rawType {
	case "execve", "exec", "process_exec":
		event.EventType = "execve"
		argv := stringArrayAt(raw, "argv")
		if len(argv) == 0 {
			argv = splitCommand(stringAt(raw, "command"))
		}
		if len(argv) == 0 {
			argv = []string{"unknown"}
		}
		event.Payload = mustJSON(map[string]any{"argv": argv})
	case "process_exit", "exit":
		event.EventType = "process_exit"
		event.Payload = mustJSON(map[string]any{"exit_code": intAt(raw, "exit_code")})
	case "file_open", "file_write":
		event.EventType = rawType
		event.Payload = mustJSON(map[string]any{"path": firstNonEmpty(stringAt(raw, "path"), stringAt(raw, "file"))})
	case "network_connect", "connect":
		event.EventType = "network_connect"
		event.Payload = mustJSON(map[string]any{"dst": firstNonEmpty(stringAt(raw, "dst"), stringAt(raw, "dst_ip"), stringAt(raw, "host"))})
	default:
		return IngestEvent{}, false, nil
	}
	return event, true, nil
}

func baseMappedEvent(raw map[string]any, source string) IngestEvent {
	return IngestEvent{
		RawEventID:  firstNonEmpty(stringAt(raw, "id"), stringAt(raw, "uuid"), stringAt(raw, "event_id")),
		ContainerID: firstNonEmpty(stringAt(raw, "container_id"), stringAt(raw, "container.id")),
		CgroupID:    firstNonEmpty(stringAt(raw, "cgroup_id"), stringAt(raw, "cgroup.id")),
		PID:         intAt(raw, "pid"),
		TGID:        intAt(raw, "tgid"),
		PPID:        intAt(raw, "ppid"),
		Timestamp:   firstNonEmpty(stringAt(raw, "time"), stringAt(raw, "timestamp")),
		Source:      source,
	}
}

func nestedMap(raw map[string]any, key string) (map[string]any, bool) {
	value, ok := raw[key].(map[string]any)
	return value, ok
}

func stringAt(raw map[string]any, key string) string {
	value, ok := raw[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return ""
	}
}

func intAt(raw map[string]any, key string) int64 {
	value, ok := raw[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return n
	default:
		return 0
	}
}

func stringArrayAt(raw map[string]any, key string) []string {
	value, ok := raw[key]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if ok && strings.TrimSpace(text) != "" {
			out = append(out, text)
		}
	}
	return out
}

func splitCommand(command string) []string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstInt(values ...int64) int64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func mustJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashStrings(values []string) string {
	h := sha256.New()
	for _, value := range values {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
