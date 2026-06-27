package telemetry

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

var forbiddenRawPayloadFields = map[string]bool{
	"run_id":       true,
	"rollout_id":   true,
	"attempt_id":   true,
	"session_id":   true,
	"tool_call_id": true,
	"process_id":   true,
	"snapshot_id":  true,
	"correlation":  true,
}

func ValidateRawPayload(eventType, payload string) error {
	raw, err := decodePayloadObject(payload)
	if err != nil {
		return err
	}
	if field := findForbiddenRawPayloadField(raw); field != "" {
		return fmt.Errorf("raw telemetry payload must not contain application/correlation field %q", field)
	}
	return validateEventBody(eventType, raw)
}

func ValidateStoredPayload(eventType, payload string) error {
	raw, err := decodePayloadObject(payload)
	if err != nil {
		return err
	}
	body := unwrapStoredPayload(raw)
	if field := findForbiddenRawPayloadField(body); field != "" {
		return fmt.Errorf("stored telemetry raw body contains application/correlation field %q", field)
	}
	return validateEventBody(eventType, body)
}

func TelemetrySource(source string, correlationMethod string) bool {
	if strings.TrimSpace(correlationMethod) != "" {
		return true
	}
	switch source {
	case "filtered_telemetry", "wrapper_runtime", "tetragon_jsonl", "falco_jsonl", "loongcollector_jsonl", "agentprov_ebpf", "native_runtime", "record_file_diff", "record_process_sample":
		return true
	default:
		return false
	}
}

type EventExplanation struct {
	Receiver              string   `json:"receiver"`
	SourceFormat          string   `json:"source_format"`
	RawEventID            string   `json:"raw_event_id,omitempty"`
	NormalizedEventType   string   `json:"normalized_event_type"`
	SchemaStatus          string   `json:"schema_status"`
	SchemaError           string   `json:"schema_error,omitempty"`
	IdentityKeys          []string `json:"identity_keys,omitempty"`
	CorrelationMethod     string   `json:"correlation_method,omitempty"`
	CorrelationConfidence float64  `json:"correlation_confidence,omitempty"`
	CorrelationStatus     string   `json:"correlation_status"`
}

func ExplainEventRecord(event EventRecord) EventExplanation {
	explanation := EventExplanation{
		Receiver:              receiverName(event.Source),
		SourceFormat:          sourceFormat(event.Source),
		RawEventID:            event.RawEventID,
		NormalizedEventType:   event.EventType,
		SchemaStatus:          "valid",
		IdentityKeys:          eventIdentityKeys(event),
		CorrelationMethod:     event.CorrelationMethod,
		CorrelationConfidence: event.CorrelationConfidence,
		CorrelationStatus:     "provided",
	}
	if strings.TrimSpace(event.CorrelationMethod) == "unresolved" || event.CorrelationConfidence == 0 {
		explanation.CorrelationStatus = "unresolved"
	} else if strings.TrimSpace(event.CorrelationMethod) != "" && event.CorrelationMethod != "provided_context" {
		explanation.CorrelationStatus = "resolved"
	}
	if err := ValidateStoredPayload(event.EventType, event.Payload); err != nil {
		explanation.SchemaStatus = "invalid"
		explanation.SchemaError = err.Error()
	}
	return explanation
}

func receiverName(source string) string {
	switch source {
	case "tetragon_jsonl":
		return "tetragon"
	case "falco_jsonl":
		return "falco"
	case "loongcollector_jsonl":
		return "loongcollector"
	case "agentprov_ebpf":
		return "agentprov_sensor"
	case "wrapper_runtime", "native_runtime", "record_file_diff", "record_process_sample", "filtered_telemetry":
		return source
	default:
		if strings.TrimSpace(source) == "" {
			return "unknown"
		}
		return source
	}
}

func sourceFormat(source string) string {
	switch source {
	case "tetragon_jsonl", "falco_jsonl", "loongcollector_jsonl", "agentprov_ebpf":
		return "jsonl"
	case "wrapper_runtime", "native_runtime", "record_file_diff", "record_process_sample", "filtered_telemetry":
		return "normalized"
	default:
		return "unknown"
	}
}

func eventIdentityKeys(event EventRecord) []string {
	keys := []string{}
	if event.ProcessID != "" {
		keys = append(keys, "process_id")
	}
	if event.ContainerID != "" {
		keys = append(keys, "container_id")
	}
	if event.CgroupID != "" {
		keys = append(keys, "cgroup_id")
	}
	if event.PID != 0 {
		keys = append(keys, "pid")
	}
	if event.TGID != 0 {
		keys = append(keys, "tgid")
	}
	if event.PPID != 0 {
		keys = append(keys, "ppid")
	}
	sort.Strings(keys)
	return keys
}

func decodePayloadObject(payload string) (map[string]any, error) {
	if strings.TrimSpace(payload) == "" {
		payload = "{}"
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		return nil, fmt.Errorf("telemetry payload must be a JSON object: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("telemetry payload must be a JSON object")
	}
	return raw, nil
}

func unwrapStoredPayload(raw map[string]any) map[string]any {
	current := raw
	for {
		if nested, ok := current["payload"].(map[string]any); ok {
			current = nested
			continue
		}
		if nested, ok := current["raw"].(map[string]any); ok {
			current = nested
			continue
		}
		return current
	}
}

func findForbiddenRawPayloadField(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if forbiddenRawPayloadFields[key] {
				return key
			}
			if field := findForbiddenRawPayloadField(nested); field != "" {
				return field
			}
		}
	case []any:
		for _, item := range typed {
			if field := findForbiddenRawPayloadField(item); field != "" {
				return field
			}
		}
	}
	return ""
}

func validateEventBody(eventType string, body map[string]any) error {
	switch eventType {
	case "execve":
		if stringSlice(body["argv"]) == nil && stringField(body, "command") == "" {
			return fmt.Errorf("execve payload requires argv[] or command")
		}
	case "process_exit":
		if _, ok := numberField(body, "exit_code"); !ok {
			return fmt.Errorf("process_exit payload requires numeric exit_code")
		}
	case "process_observed":
		if _, ok := numberField(body, "pid"); !ok {
			return fmt.Errorf("process_observed payload requires numeric pid")
		}
	case "file_open", "file_write", "secret_path":
		if payloadPathFromBody(body) == "" {
			return fmt.Errorf("%s payload requires safe relative path or file", eventType)
		}
	case "network_connect", "metadata_ip", "private_cidr":
		if firstString(body, "dst", "dst_ip", "host") == "" {
			return fmt.Errorf("%s payload requires dst, dst_ip, or host", eventType)
		}
	case "abnormal_process_tree":
		if _, ok := numberField(body, "pid"); !ok && stringField(body, "command") == "" {
			return fmt.Errorf("abnormal_process_tree payload requires pid or command")
		}
	case "policy_verdict":
		if firstString(body, "decision", "verdict") == "" {
			return fmt.Errorf("policy_verdict payload requires decision or verdict")
		}
	case "resource_pressure":
		if firstString(body, "resource", "signal") == "" {
			return fmt.Errorf("resource_pressure payload requires resource or signal")
		}
	}
	return nil
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return nil
		}
		out = append(out, text)
	}
	return out
}

func stringField(body map[string]any, key string) string {
	value, _ := body[key].(string)
	return strings.TrimSpace(value)
}

func firstString(body map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringField(body, key); value != "" {
			return value
		}
	}
	return ""
}

func numberField(body map[string]any, key string) (float64, bool) {
	value, ok := body[key].(float64)
	return value, ok
}

func payloadPathFromBody(body map[string]any) string {
	path := firstString(body, "path", "file")
	path = strings.TrimPrefix(path, "/workspace/")
	path = strings.TrimPrefix(path, "./")
	if path == "" || path == "." || path == ".." || strings.HasPrefix(path, "../") || strings.HasPrefix(path, "/") {
		return ""
	}
	return path
}
