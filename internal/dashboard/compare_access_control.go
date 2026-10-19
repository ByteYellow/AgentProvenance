package dashboard

import (
	"encoding/json"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func accessComparisonKind(kind string) bool {
	switch kind {
	case "access_control", "access_control_config", "access_control_state", "access_control_collection", "syscall_result", "process_exit", "thread_exit":
		return true
	}
	return false
}

// Compare sets of recorded observations, not process pairs or enforcement
// coverage. Volatile identities stay in the evidence reader, outside value
// hashes. Audit actions and runtime outcomes never supply each other's fields.
func comparisonAccessControl(source SearchSource, payload map[string]any) ([]ComparisonRecord, []ComparisonIssue) {
	records := []ComparisonRecord{}
	issues := []ComparisonIssue{}
	issue := func(code string) {
		issues = append(issues, ComparisonIssue{SourceID: source.ID, Dimension: "access_control", Code: code})
	}
	add := func(kind, mechanism, label string, value any, partial bool, identity ...string) {
		key, _ := json.Marshal(append([]string{"access_control", kind, mechanism}, identity...))
		v := comparisonValue(value)
		records = append(records, ComparisonRecord{Dimension: "access_control", Key: string(key), Label: label,
			Operation: kind, EvidenceKind: kind, Mechanism: mechanism, ComparisonScope: "observed_set",
			Value: &v, Partial: partial, Evidence: source})
	}
	fields := func(keys ...string) map[string]any {
		out := map[string]any{}
		for _, key := range keys {
			if v, ok := payload[key]; ok {
				out[key] = v
			}
		}
		return out
	}
	decode := func(value any, target any) bool {
		body, err := json.Marshal(value)
		return err == nil && json.Unmarshal(body, target) == nil
	}
	mechanismValid := func(m string) bool { return m == "apparmor" || m == "seccomp" }
	switch source.Kind {
	case "access_control":
		var audit telemetry.AuditRecord
		if !decode(payload, &audit) || audit.SchemaVersion != telemetry.AuditSchemaVersion || !mechanismValid(audit.Mechanism) ||
			source.SourceID != audit.Mechanism+"_audit" || audit.AuditID == "" || audit.Decision == "" ||
			(audit.EvidenceKind != "audit_decision" && audit.EvidenceKind != "audit_status") {
			issue("invalid_access_control_audit")
			break
		}
		partial := len(audit.Warnings) != 0 || audit.Decision == "unknown"
		operation, target := audit.Operation, audit.Target
		identity := []string{audit.ProfileNamespace, audit.Profile, audit.Label, audit.Class, operation, target}
		if audit.Mechanism == "seccomp" {
			operation, target = audit.SyscallName, ""
			if operation == "" {
				operation = "unknown_syscall"
			}
			identity = []string{audit.Arch, comparisonScalar(payload, "syscall_number"), operation}
			partial = partial || audit.SyscallNumber == nil || audit.ActionCode == nil || audit.SyscallName == ""
		} else if audit.EvidenceKind == "audit_decision" {
			partial = partial || operation == ""
		}
		if partial {
			issue("audit_fields_incomplete")
		}
		value := fields("decision", "profile", "profile_namespace", "label", "class", "operation", "target", "requested_mask", "denied_mask",
			"arch", "abi", "syscall_number", "syscall_name", "action_code", "action_data", "signal", "warnings")
		add(audit.EvidenceKind, audit.Mechanism, strings.TrimSpace(audit.Mechanism+" / "+operation+" "+target), value, partial, identity...)
	case "access_control_state":
		var snapshot accesscontrol.Snapshot
		if source.SourceID != "procfs_access_control" || !decode(payload, &snapshot) || accesscontrol.ValidateSnapshot(snapshot) != nil {
			issue("invalid_access_control_state")
			break
		}
		for _, item := range []struct {
			mechanism string
			state     accesscontrol.State
		}{{"apparmor", snapshot.AppArmor}, {"seccomp", snapshot.Seccomp}} {
			partial := item.state.Status != "observed"
			if partial {
				issue(item.mechanism + "_state_not_observed")
			}
			add("state_snapshot", item.mechanism, item.mechanism+" / recorded task state", item.state, partial)
		}
	case "access_control_config":
		var config struct {
			SchemaVersion string                      `json:"schema_version"`
			EvidenceKind  string                      `json:"evidence_kind"`
			Source        string                      `json:"source"`
			Declarations  []accesscontrol.Declaration `json:"declarations"`
		}
		if source.SourceID != "k8s" || !decode(payload, &config) || config.SchemaVersion != "agentprovenance.access_control_config/v1" ||
			config.EvidenceKind != "configuration_declaration" || config.Source != "k8s_api" || len(config.Declarations) == 0 {
			issue("invalid_access_control_configuration")
			break
		}
		limited := len(config.Declarations) > 64
		if limited {
			issue("access_control_declaration_limit")
			config.Declarations = config.Declarations[:64]
		}
		for _, d := range config.Declarations {
			if !mechanismValid(d.Mechanism) || d.EvidenceKind != "configuration_declaration" || d.Source == "" ||
				(d.Status != "declared" && d.Status != "not_declared") ||
				(d.Status == "not_declared" && (d.ProfileType != "" || d.LocalhostProfile != "" || d.AnnotationValue != nil)) {
				issue("invalid_access_control_declaration")
				continue
			}
			// Compare the observed API fields, not resource revisions or pods
			// presumed equivalent because their names happen to match.
			value := map[string]any{"status": d.Status}
			if d.ProfileType != "" {
				value["profile_type"] = d.ProfileType
			}
			if d.LocalhostProfile != "" {
				value["localhost_profile"] = d.LocalhostProfile
			}
			if d.AnnotationValue != nil {
				value["annotation_value"] = *d.AnnotationValue
			}
			missing := d.Status == "declared" && d.ProfileType == "" && d.AnnotationValue == nil
			if missing {
				issue("declaration_value_not_recorded")
			}
			add("configuration_declaration", d.Mechanism, d.Mechanism+" / "+d.Source, value, limited || missing, d.Source)
		}
	case "access_control_collection":
		var observation telemetry.AuditCollectionObservation
		body, _ := json.Marshal(payload)
		if source.SourceID != "audit_reader" || !decode(payload, &observation) || telemetry.ValidateRawPayload(source.Kind, string(body)) != nil ||
			(observation.Mechanism != "all" && !mechanismValid(observation.Mechanism)) {
			issue("invalid_access_control_collection")
			break
		}
		partial := observation.Status == "failed" || observation.Status == "stopped" || observation.Failed > 0 || observation.IdentityIncomplete > 0 || observation.PendingBytes > 0
		if partial {
			issue("audit_source_collection_incomplete")
		}
		add("collection_status", observation.Mechanism, observation.Mechanism+" / "+observation.SourcePath,
			fields("status", "reason", "coverage_scope", "upstream_loss", "raw_records_retained", "pending_bytes", "read", "ingested", "duplicates", "skipped", "failed", "identity_incomplete"),
			partial, observation.SourcePath)
	case "syscall_result":
		result, ok := payload["syscall_result"].(json.Number)
		_, err := result.Int64()
		operation := firstStr(payload, "operation")
		if !ok || err != nil || operation == "" {
			issue("invalid_syscall_result")
			break
		}
		path := firstStr(payload, "path", "filename")
		host, port := firstStr(payload, "dst_host", "host", "dst_ip", "dst"), comparisonScalar(payload, "dst_port", "port")
		target := path
		if target == "" {
			target = host
			if port != "" {
				target += ":" + port
			}
		}
		partial := path == "" && host == "" || operation == "network_connect" && (host == "" || port == "")
		if partial {
			issue("syscall_target_not_recorded")
		}
		add("syscall_result", "", strings.TrimSpace(operation+" / result "+target),
			fields("operation", "path", "filename", "dst_host", "host", "dst_ip", "dst", "dst_port", "port", "syscall_result", "syscall_outcome", "errno", "mode"),
			partial, operation, path, host, port)
	case "process_exit", "thread_exit":
		body, _ := json.Marshal(payload)
		invalidCode := false
		if code, exists := payload["exit_code"]; exists {
			number, ok := code.(json.Number)
			_, err := number.Int64()
			invalidCode = !ok || err != nil
		}
		if invalidCode || telemetry.ValidateRawPayload(source.Kind, string(body)) != nil {
			issue("invalid_exit_result")
			break
		}
		comm := firstStr(payload, "comm")
		add(source.Kind, "", strings.TrimSpace(source.Kind+" / "+comm), fields("exit_code", "exit_signal", "raw_exit_status", "termination", "exit_scope", "core_dump_flag"), false, comm)
	}
	return records, issues
}
