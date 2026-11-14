package seccheck

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/buildinfo"
)

const CollectionConfigSchema = "agentprovenance.seccheck_collection/v1"

// CollectionConfig is supplied by the trusted launcher. RuntimeRelease is its
// version assertion; the wire handshake carries a protocol version only.
type CollectionConfig struct {
	SchemaVersion  string   `json:"schema_version"`
	RuntimeRelease string   `json:"runtime_release"`
	Targets        []Target `json:"targets"`
}

type Target struct {
	RunID        string       `json:"run_id"`
	SocketPath   string       `json:"socket_path"`
	Registration Registration `json:"registration"`
}

func ValidateSocketPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) >= 108 || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("SecCheck socket must be a clean absolute path shorter than 108 bytes")
	}
	return nil
}

func (c CollectionConfig) Validate() error {
	if c.SchemaVersion != CollectionConfigSchema || c.RuntimeRelease != RuntimeRelease {
		return fmt.Errorf("SecCheck requires schema %s and runtime %s", CollectionConfigSchema, RuntimeRelease)
	}
	if len(c.Targets) == 0 || len(c.Targets) > 64 {
		return fmt.Errorf("SecCheck configuration requires 1..64 targets")
	}
	sockets, scopes := map[string]bool{}, map[string]bool{}
	for _, target := range c.Targets {
		if target.RunID == "" || len(target.RunID) > 1024 || strings.TrimSpace(target.RunID) != target.RunID || strings.ContainsAny(target.RunID, "\x00\r\n") {
			return fmt.Errorf("invalid SecCheck run ID")
		}
		if err := ValidateSocketPath(target.SocketPath); err != nil {
			return err
		}
		id, err := IdentityFor(target.Registration, nil)
		if err != nil {
			return err
		}
		if sockets[target.SocketPath] || scopes[id.Scope] {
			return fmt.Errorf("SecCheck targets must have distinct socket paths and lifecycle scopes")
		}
		sockets[target.SocketPath], scopes[id.Scope] = true, true
	}
	return nil
}

type TracePoint struct {
	Name           string   `json:"name"`
	ContextFields  []string `json:"context_fields"`
	OptionalFields []string `json:"optional_fields,omitempty"`
}

// TraceConfig produces the supported checkpoint selection, not an assertion
// that a running sandbox enabled every point. Observations establish coverage.
func TraceConfig(socket string) (map[string]any, error) {
	if err := ValidateSocketPath(socket); err != nil {
		return nil, err
	}
	points := make([]TracePoint, 0, len(CheckpointNames()))
	for _, name := range CheckpointNames() {
		p := TracePoint{Name: name, ContextFields: []string{"time", "thread_id", "task_start_time", "group_id", "thread_group_start_time", "container_id", "cwd", "process_name", "parent_thread_group_id", "is_exec_session"}}
		if strings.HasPrefix(name, "syscall/openat/") {
			p.OptionalFields = []string{"fd_path"}
		}
		points = append(points, p)
	}
	return map[string]any{"trace_session": map[string]any{"name": "Default", "points": points, "sinks": []any{map[string]any{"name": "remote", "config": map[string]any{"endpoint": socket}}}}}, nil
}

func CheckpointNames() []string {
	return []string{"container/start", "sentry/clone", "sentry/execve", "sentry/task_exit", "syscall/openat/enter", "syscall/openat/exit", "syscall/connect/enter", "syscall/connect/exit", "syscall/execve/enter", "syscall/execve/exit"}
}

type Capabilities struct {
	Producer           string   `json:"producer"`
	ProducerVersion    string   `json:"producer_version"`
	ProducerCommit     string   `json:"producer_commit"`
	Placement          string   `json:"placement"`
	IdentityDomain     string   `json:"identity_domain"`
	SystemTelemetry    string   `json:"system_telemetry"`
	ModelIntent        string   `json:"model_intent"`
	AppContext         string   `json:"app_context"`
	SupportedPoints    []string `json:"supported_points"`
	EnabledPointsBasis string   `json:"enabled_points_basis"`
	RuntimeBasis       string   `json:"runtime_release_basis"`
	RawPacketsRetained bool     `json:"raw_packets_retained"`
}

func ReceiverCapabilities() Capabilities {
	return Capabilities{Producer: "agentprov", ProducerVersion: buildinfo.Version, ProducerCommit: buildinfo.Commit, Placement: "host_receiver", IdentityDomain: "sentry", SystemTelemetry: "partial", ModelIntent: "none", AppContext: "none", SupportedPoints: CheckpointNames(), EnabledPointsBasis: "observed_records", RuntimeBasis: "trusted_launcher_assertion", RawPacketsRetained: false}
}
