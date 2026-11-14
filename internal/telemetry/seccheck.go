package telemetry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/redact"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const SecCheckSchema = "agentprovenance.seccheck/v1"
const secCheckSource = "gvisor_seccheck"

// SecCheckContext stores only identity and clock fields. Credentials and exec
// environment are deliberately excluded from this projection before spooling.
type SecCheckContext struct {
	TimeNS        int64 `json:"time_ns"`
	ThreadID      int32 `json:"thread_id"`
	ThreadStartNS int64 `json:"thread_start_ns"`
	GroupID       int32 `json:"group_id"`
	GroupStartNS  int64 `json:"group_start_ns"`
	ParentGroupID int32 `json:"parent_group_id"`
}

type SecCheckEvidence struct {
	SchemaVersion        string                `json:"schema_version"`
	RuntimeRelease       string                `json:"runtime_release"`
	Registration         seccheck.Registration `json:"registration"`
	ConnectionID         string                `json:"connection_id"`
	Sequence             uint64                `json:"sequence"`
	ReceivedAt           time.Time             `json:"received_at"`
	ProtocolVersion      uint32                `json:"protocol_version"`
	PeerPID              int32                 `json:"transport_peer_pid"`
	Kind                 string                `json:"kind"`
	Reason               string                `json:"reason,omitempty"`
	Context              *SecCheckContext      `json:"context,omitempty"`
	PacketSHA256         string                `json:"packet_sha256,omitempty"`
	PacketBytes          int                   `json:"packet_bytes,omitempty"`
	Header               *seccheck.Header      `json:"header,omitempty"`
	DroppedDelta         *uint64               `json:"dropped_delta,omitempty"`
	DropCounterDecreased bool                  `json:"drop_counter_decreased,omitempty"`
	IdentityGaps         []string              `json:"identity_gaps,omitempty"`
}

func (e SecCheckEvidence) identity() (seccheck.Identity, error) {
	var c *wire.ContextData
	if e.Context != nil {
		c = &wire.ContextData{ContainerId: e.Registration.ContainerID, TimeNs: e.Context.TimeNS,
			ThreadId: e.Context.ThreadID, ThreadStartTimeNs: e.Context.ThreadStartNS,
			ThreadGroupId: e.Context.GroupID, ThreadGroupStartTimeNs: e.Context.GroupStartNS,
			ParentThreadGroupId: e.Context.ParentGroupID}
	}
	return seccheck.IdentityFor(e.Registration, c)
}

func readSecCheckEvidence(payload string) (SecCheckEvidence, error) {
	// Decode raw objects so nanosecond birth times never pass through float64.
	for i := 0; i < 8; i++ {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(payload), &fields); err != nil {
			return SecCheckEvidence{}, err
		}
		if inner, ok := fields["payload"]; ok {
			payload = string(inner)
			continue
		}
		var e SecCheckEvidence
		if err := json.Unmarshal(fields["sentry"], &e); err != nil {
			return e, err
		}
		if e.SchemaVersion != SecCheckSchema || e.ConnectionID == "" || len(e.ConnectionID) > 256 || e.ReceivedAt.IsZero() {
			return e, fmt.Errorf("invalid SecCheck evidence envelope")
		}
		return e, e.Registration.Validate()
	}
	return SecCheckEvidence{}, fmt.Errorf("SecCheck payload nesting exceeds limit")
}

// ValidateSecCheckStoredEvent checks the registration evidence instead of
// requiring a host execution_context_binding for a Sentry observation.
func ValidateSecCheckStoredEvent(event EventRecord) error {
	e, err := readSecCheckEvidence(event.Payload)
	if err != nil {
		return err
	}
	id, err := e.identity()
	if err != nil {
		return err
	}
	if event.Source != secCheckSource || event.RunID == "" || event.CorrelationMethod != "runtime_scope" || event.SessionID != "" || event.ToolCallID != "" || event.ProcessID != "" || event.CgroupID != "" || event.ContainerID != id.Scope {
		return fmt.Errorf("SecCheck registration does not match stored execution scope")
	}
	if event.PID != int64(id.ThreadID) || event.TGID != int64(id.ThreadGroupID) || event.PPID != int64(id.ParentThreadGroupID) {
		return fmt.Errorf("SecCheck stored process identity differs from source")
	}
	raw, _ := json.Marshal([]any{id.Scope, e.ConnectionID, e.Sequence})
	if event.RawEventID != fmt.Sprintf("seccheck:%x", sha256.Sum256(raw)) {
		return fmt.Errorf("SecCheck source observation identity differs")
	}
	at := e.ReceivedAt.UTC()
	if e.Context != nil && e.Context.TimeNS > 0 {
		at = time.Unix(0, e.Context.TimeNS).UTC()
	}
	if event.CreatedAt != at.Format(time.RFC3339Nano) {
		return fmt.Errorf("SecCheck capture time differs from source")
	}
	if e.Kind != "event" && e.Kind != "stream" {
		return fmt.Errorf("invalid SecCheck observation kind")
	}
	if e.Kind == "event" && (e.Header == nil || e.ProtocolVersion != seccheck.ProtocolVersion || len(e.PacketSHA256) != 64) {
		return fmt.Errorf("SecCheck event lacks protocol evidence")
	}
	if e.Kind == "stream" && e.Reason == "" {
		return fmt.Errorf("SecCheck stream diagnostic lacks a reason")
	}
	return nil
}

// MapSecCheckRecord receives the Run from the local registration, never from
// the runtime packet. It preserves entry/return stages as separate observations.
func MapSecCheckRecord(runID string, rec seccheck.Record) (IngestEvent, error) {
	if strings.TrimSpace(runID) != runID || runID == "" || len(runID) > 1024 || strings.ContainsAny(runID, "\x00\r\n") || rec.ConnectionID == "" || len(rec.ConnectionID) > 256 || rec.ReceivedAt.IsZero() {
		return IngestEvent{}, fmt.Errorf("SecCheck requires a Run, connection and receive time")
	}
	var c *wire.ContextData
	if rec.Packet != nil {
		c = rec.Packet.Context
	}
	id, err := seccheck.IdentityFor(rec.Registration, c)
	if err != nil {
		return IngestEvent{}, err
	}
	e := SecCheckEvidence{SchemaVersion: SecCheckSchema, RuntimeRelease: seccheck.RuntimeRelease,
		Registration: rec.Registration, ConnectionID: rec.ConnectionID, Sequence: rec.Sequence,
		ReceivedAt: rec.ReceivedAt.UTC(), ProtocolVersion: rec.ProtocolVersion, PeerPID: rec.PeerPID,
		Kind: rec.Kind, Reason: rec.Reason, DroppedDelta: rec.DroppedDelta,
		DropCounterDecreased: rec.DropCounterDecreased, IdentityGaps: id.Gaps}
	body := map[string]any{"observation_stage": "collector", "operation": "collection", "pid": 0}
	event := IngestEvent{RunID: runID, Source: secCheckSource, EventType: "runtime_collection",
		ContainerID: id.Scope, Timestamp: rec.ReceivedAt.UTC().Format(time.RFC3339Nano)}
	if rec.Packet != nil {
		e.PacketSHA256, e.PacketBytes, e.Header = rec.Packet.SHA256, rec.Packet.Size, &rec.Packet.Header
	}
	if c != nil {
		e.Context = &SecCheckContext{TimeNS: c.TimeNs, ThreadID: c.ThreadId, ThreadStartNS: c.ThreadStartTimeNs,
			GroupID: c.ThreadGroupId, GroupStartNS: c.ThreadGroupStartTimeNs, ParentGroupID: c.ParentThreadGroupId}
		event.PID, event.TGID, event.PPID = int64(c.ThreadId), int64(c.ThreadGroupId), int64(c.ParentThreadGroupId)
		if c.TimeNs > 0 {
			event.Timestamp = time.Unix(0, c.TimeNs).UTC().Format(time.RFC3339Nano)
		}
		body["pid"], body["comm"], body["cwd"] = event.PID, c.ProcessName, c.Cwd
	}
	if rec.Kind == "event" {
		if rec.Packet == nil || rec.Packet.Message == nil || rec.ProtocolVersion != seccheck.ProtocolVersion {
			return IngestEvent{}, fmt.Errorf("SecCheck event lacks a supported packet")
		}
		body["observation_stage"] = "sentry_checkpoint"
		switch m := rec.Packet.Message.(type) {
		case *wire.Start:
			if m.Id != rec.Registration.ContainerID {
				return IngestEvent{}, fmt.Errorf("SecCheck container start does not match registration")
			}
			event.EventType, body["operation"] = "process_observed", "container_start"
			body["argv"] = m.Args
		case *wire.CloneInfo:
			event.EventType, body["operation"] = "process_observed", "clone"
			body["created_thread_id"], body["created_thread_group_id"] = m.CreatedThreadId, m.CreatedThreadGroupId
			body["created_thread_start_ns"], body["clone_flags"] = m.CreatedThreadStartTimeNs, m.Flags
		case *wire.ExecveInfo:
			event.EventType, body["operation"] = "execve", "execve"
			body["argv"], body["command"], body["binary_path"] = m.Argv, m.BinaryPath, m.BinaryPath
		case *wire.TaskExit:
			event.EventType, body["operation"], body["exit_scope"] = "thread_exit", "task_exit", "thread"
			secCheckWaitStatus(body, m.ExitStatus)
		case *wire.ExitNotifyParentInfo:
			event.EventType, body["operation"], body["exit_scope"] = "process_exit", "group_exit", "thread_group"
			secCheckWaitStatus(body, m.ExitStatus)
		case *wire.Open:
			event.EventType, body["operation"] = "file_open", "file_open"
			body["path"], body["dirfd"], body["dirfd_path"], body["flags"] = m.Pathname, m.Fd, m.FdPath, m.Flags
			body["path_basis"] = "syscall_argument"
			secCheckResult(body, m.Exit, m.Sysno)
		case *wire.Connect:
			event.EventType, body["operation"] = "network_connect", "network_connect"
			body["fd"], body["address_hex"] = m.Fd, fmt.Sprintf("%x", m.Address)
			if dst, port := secCheckAddress(m.Address); dst != "" {
				body["dst_ip"], body["dst_port"] = dst, port
			} else {
				// Keep an uninterpreted address as an observation, not an IP.
				event.EventType = "runtime_observation"
				body["address_status"] = "unsupported_or_incomplete"
			}
			secCheckResult(body, m.Exit, m.Sysno)
		case *wire.Execve:
			event.EventType, body["operation"] = "runtime_observation", "execve"
			body["argv"], body["path"] = m.Argv, m.Pathname
			secCheckResult(body, m.Exit, m.Sysno)
		case *wire.Clone:
			event.EventType, body["operation"] = "runtime_observation", "clone"
			body["clone_flags"] = m.Flags
			secCheckResult(body, m.Exit, m.Sysno)
		case *wire.Fork:
			event.EventType, body["operation"] = "runtime_observation", "fork"
			secCheckResult(body, m.Exit, m.Sysno)
		default:
			return IngestEvent{}, fmt.Errorf("unsupported SecCheck projection %T", m)
		}
		if body["observation_stage"] == "result" {
			// Match the existing sensor contract: return evidence is separate
			// from an attempted file/network operation, including failures.
			event.EventType = "syscall_result"
		}
	} else if rec.Kind != "stream" || rec.Reason == "" {
		return IngestEvent{}, fmt.Errorf("invalid SecCheck record kind")
	}
	body["sentry"] = e
	raw, err := json.Marshal(body)
	if err != nil {
		return IngestEvent{}, err
	}
	event.Payload = redact.RedactString(string(raw))
	identity, _ := json.Marshal([]any{id.Scope, rec.ConnectionID, rec.Sequence})
	event.RawEventID = fmt.Sprintf("seccheck:%x", sha256.Sum256(identity))
	if err := ValidateRawPayload(event.EventType, event.Payload); err != nil {
		return IngestEvent{}, err
	}
	return event, nil
}

func secCheckResult(body map[string]any, exit *wire.Exit, sysno uint64) {
	body["syscall_number"], body["observation_stage"], body["syscall_outcome"] = sysno, "attempt", "unknown"
	if exit == nil {
		return
	}
	body["observation_stage"], body["syscall_result"], body["errno"] = "result", exit.Result, exit.Errorno
	outcome := "success"
	if exit.Errorno != 0 || exit.Result < 0 {
		outcome = "failure"
	}
	// Linux errno values in the pinned little-endian amd64/arm64 protocol.
	if body["operation"] == "network_connect" && (exit.Errorno == 115 || exit.Errorno == 114) {
		outcome = "pending"
	}
	body["syscall_outcome"] = outcome
}

func secCheckWaitStatus(body map[string]any, status int32) {
	body["wait_status"] = status
	if status&0x7f == 0 {
		body["exit_code"] = (status >> 8) & 0xff
	} else if signal := status & 0x7f; signal > 0 && signal <= 64 {
		body["exit_signal"] = signal
	}
}

func secCheckAddress(address []byte) (string, uint16) {
	if len(address) < 4 {
		return "", 0
	}
	port := binary.BigEndian.Uint16(address[2:4])
	switch binary.LittleEndian.Uint16(address[:2]) {
	case 2:
		if len(address) >= 16 {
			return net.IP(address[4:8]).String(), port
		}
	case 10:
		if len(address) >= 28 {
			return net.IP(address[8:24]).String(), port
		}
	}
	return "", 0
}

// SecCheckStream shares the native spool engine, but not host scope counters,
// correlation, locks or kernel capability claims. One stream serves many
// registered per-sandbox sockets; it is the sole SecCheck owner of this store.
type SecCheckStream struct{ stream *NativeStream }

func NewSecCheckStream(db *sql.DB, paths store.Paths, opts NativeStreamOptions) (*SecCheckStream, error) {
	if opts.PolicyEnabled || opts.Ingest.DropUncorrelated {
		return nil, fmt.Errorf("SecCheck scope capture does not support host policy or host-binding filters")
	}
	n, err := newRuntimeStream(db, paths, opts, secCheckSource)
	if err != nil {
		return nil, err
	}
	return &SecCheckStream{stream: n}, nil
}

func (s *SecCheckStream) Sink(runID string, registration seccheck.Registration) seccheck.Sink {
	return func(ctx context.Context, rec seccheck.Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if rec.Registration != registration {
			return fmt.Errorf("SecCheck record differs from receiver registration")
		}
		event, err := MapSecCheckRecord(runID, rec)
		if err != nil {
			return err
		}
		s.stream.mu.Lock()
		defer s.stream.mu.Unlock()
		if s.stream.closed {
			return os.ErrClosed
		}
		s.stream.counters["read"]++
		return s.stream.appendEvent(event)
	}
}

func (s *SecCheckStream) Run(ctx context.Context, report func(error)) error {
	return s.stream.Run(ctx, report)
}
func (s *SecCheckStream) Flush() error                    { return s.stream.Flush() }
func (s *SecCheckStream) Drain(ctx context.Context) error { return s.stream.Drain(ctx) }
func (s *SecCheckStream) Close() error                    { return s.stream.Close() }
func (s *SecCheckStream) Status(ctx context.Context) (NativeStreamStatus, error) {
	return readStreamStatus(ctx, s.stream.service.DB, secCheckSource)
}

func ingestSecCheckEvent(db sqlStore, event IngestEvent) (string, bool, error) {
	if event.Source != secCheckSource || !strings.HasPrefix(event.RawEventID, "seccheck:") {
		return "", false, fmt.Errorf("invalid SecCheck spool row")
	}
	if _, err := readSecCheckEvidence(event.Payload); err != nil {
		return "", false, err
	}
	id := fmt.Sprintf("evt-seccheck-%x", sha256.Sum256([]byte(event.RawEventID)))
	var oldRun, oldPayload, oldType, oldTime string
	err := db.QueryRow(`SELECT run_id,payload,event_type,created_at FROM events WHERE id=? AND source=?`, id, secCheckSource).Scan(&oldRun, &oldPayload, &oldType, &oldTime)
	if err == nil {
		payload := event.Payload
		if event.PID > 0 {
			payload, err = stampProcessGraphForSource(payload, event.Source)
		}
		if err != nil || oldRun != event.RunID || oldPayload != payload || oldType != event.EventType || oldTime != event.Timestamp {
			return "", false, fmt.Errorf("conflicting SecCheck observation identity")
		}
		return id, true, nil
	}
	if err != sql.ErrNoRows {
		return "", false, err
	}
	id, err = ingestFilteredWithID(db, event, id)
	return id, false, err
}

func sentryProcessGraph(event EventRecord, fallback RuntimeProcessIdentity) RuntimeProcessIdentity {
	e, err := readSecCheckEvidence(event.Payload)
	if err != nil {
		return fallback
	}
	id, err := e.identity()
	if err != nil || e.Context == nil || int64(id.ThreadID) != event.PID || int64(id.ThreadGroupID) != event.TGID || int64(id.ParentThreadGroupID) != event.PPID {
		return fallback
	}
	node := func(instance string, pid int64) RuntimeProcessNode {
		return RuntimeProcessNode{ID: "runtime_process/" + instance, PID: pid, InstanceID: instance, Basis: "sentry_process_instance"}
	}
	if id.Task != "" {
		instance := id.Task
		if id.Process != "" && id.ThreadID == id.ThreadGroupID && e.Context.ThreadStartNS == e.Context.GroupStartNS {
			instance = id.Process
		}
		fallback.Process = node(instance, event.PID)
	}
	if id.Process != "" && event.TGID != event.PID {
		fallback.ThreadGroup = node(id.Process, event.TGID)
	}
	return fallback
}

// A path is scoped to its sandbox lifetime; a relative or unresolved argument
// stays local to its observation. Neither is a host workspace artifact.
func SecCheckFileNode(event EventRecord) (string, string) {
	if event.Source != secCheckSource {
		return "", ""
	}
	e, err := readSecCheckEvidence(event.Payload)
	if err != nil {
		return "", ""
	}
	id, err := e.identity()
	if err != nil {
		return "", ""
	}
	body, err := decodePayloadObject(event.Payload)
	if err != nil {
		return "", ""
	}
	p := stringField(unwrapStoredPayload(body), "path")
	if p == "" {
		return "", ""
	}
	if strings.HasPrefix(p, "/") && !hasDotPathSegment(p) {
		return "runtime_file/" + id.Scope + "/" + p, p
	}
	if event.ID != "" {
		return "runtime_file/observation/" + event.ID + "/" + p, p
	}
	return "", ""
}
