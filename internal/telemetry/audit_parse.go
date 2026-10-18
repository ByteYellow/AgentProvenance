package telemetry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const AuditSchemaVersion = "agentprovenance.access_control_audit/v1"
const MaxAuditLineBytes = 64 << 10

// Source identities describe the supplied log, never the machine doing import.
type AuditSource struct {
	HostID string `json:"host_id,omitempty"`
	BootID string `json:"boot_id,omitempty"`
}

type AuditRawRecord struct {
	State       string `json:"state"`
	SHA256      string `json:"sha256"`
	Bytes       int    `json:"bytes"`
	Text        string `json:"text,omitempty"`
	Reason      string `json:"reason,omitempty"`
	DigestScope string `json:"digest_scope"`
	Redacted    bool   `json:"redacted"`
}

type AuditRecord struct {
	SchemaVersion        string `json:"schema_version"`
	Mechanism            string `json:"mechanism"`
	EvidenceKind         string `json:"evidence_kind"`
	RecordType           string `json:"record_type"`
	AuditID              string `json:"audit_id"`
	Timestamp            string `json:"timestamp"`
	TimestampPrecisionNS int64  `json:"timestamp_precision_ns"`
	AuditSource
	IdentitySource   string         `json:"identity_source"`
	SourceFormat     string         `json:"source_format"`
	JournalCursor    string         `json:"journal_cursor,omitempty"`
	RecordID         string         `json:"record_id,omitempty"`
	Decision         string         `json:"decision"`
	AuditPID         *int64         `json:"audit_pid,omitempty"`
	PIDSemantics     string         `json:"pid_semantics"`
	Comm             string         `json:"comm,omitempty"`
	Executable       string         `json:"executable,omitempty"`
	Profile          string         `json:"profile,omitempty"`
	ProfileNamespace string         `json:"profile_namespace,omitempty"`
	Label            string         `json:"label,omitempty"`
	Class            string         `json:"class,omitempty"`
	Operation        string         `json:"operation,omitempty"`
	Target           string         `json:"target,omitempty"`
	RequestedMask    string         `json:"requested_mask,omitempty"`
	DeniedMask       string         `json:"denied_mask,omitempty"`
	Arch             string         `json:"arch,omitempty"`
	ABI              string         `json:"abi,omitempty"`
	SyscallNumber    *int64         `json:"syscall_number,omitempty"`
	SyscallName      string         `json:"syscall_name,omitempty"`
	ActionCode       *uint32        `json:"action_code,omitempty"`
	ActionData       *uint16        `json:"action_data,omitempty"`
	Signal           *int64         `json:"signal,omitempty"`
	Warnings         []string       `json:"warnings,omitempty"`
	RawRecord        AuditRawRecord `json:"raw_record"`
}

var auditHeader = regexp.MustCompile(`(?:^|\s)type=([A-Z_]+|[0-9]+)\s+(?:msg=)?audit\(([0-9]{1,12})(?:\.([0-9]{1,9}))?:([0-9]{1,20})\):\s*(.*)$`)

type auditField struct {
	Name, Value string
	Quoted      bool
}

// ParseAuditLine accepts raw audit records (including kernel/syslog prefixes)
// and journalctl JSON. It does not read /proc, install policies, or infer a
// process lifetime from a logged PID. Unrelated log records are skipped.
func ParseAuditLine(line []byte, source AuditSource) (AuditRecord, bool, error) {
	var out AuditRecord
	if len(line) > MaxAuditLineBytes || !utf8.Valid(line) {
		return out, false, fmt.Errorf("audit line exceeds 64 KiB or is not UTF-8")
	}
	message := strings.TrimSpace(string(line))
	out.SourceFormat, out.IdentitySource = "audit_text", "supplied"
	if strings.HasPrefix(message, "{") {
		fields, err := auditJournalObject([]byte(message))
		if err != nil {
			return out, false, err
		}
		if fields["MESSAGE"] == nil {
			return out, false, nil
		}
		read := func(key string) (string, error) {
			var value string
			if raw, ok := fields[key]; ok {
				if err := json.Unmarshal(raw, &value); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					return "", fmt.Errorf("journal %s must be a string", key)
				}
			}
			return value, nil
		}
		message, err = read("MESSAGE")
		if err != nil {
			return out, false, err
		}
		for key, dst := range map[string]*string{"_MACHINE_ID": &source.HostID, "_BOOT_ID": &source.BootID} {
			value, err := read(key)
			if err != nil {
				return out, false, err
			}
			if key == "_BOOT_ID" {
				value = normalizeAuditBoot(value)
				*dst = normalizeAuditBoot(*dst)
			}
			if value != "" && *dst != "" && value != *dst {
				return out, false, fmt.Errorf("journal %s conflicts with supplied source identity", key)
			}
			if value != "" {
				*dst = value
			}
		}
		out.JournalCursor, err = read("__CURSOR")
		if err != nil {
			return out, false, err
		}
		out.SourceFormat, out.IdentitySource = "journal_json", "journal_or_supplied"
	}
	if strings.ContainsAny(message, "\r\n\x00") {
		return out, false, fmt.Errorf("audit message must be one complete line")
	}
	m := auditHeader.FindStringSubmatch(message)
	if m == nil {
		if strings.Contains(message, "apparmor=") || strings.Contains(message, "type=SECCOMP") || strings.Contains(message, "type=1326") {
			return out, false, fmt.Errorf("access-control audit header is malformed")
		}
		return out, false, nil
	}
	out.RecordType = auditRecordType(m[1])
	if out.RecordType != "1326" && (!auditAppArmorType(out.RecordType) || !strings.Contains(m[5], "apparmor=")) {
		return out, false, nil
	}
	fields, err := parseAuditFields(m[5])
	if err != nil {
		return out, false, err
	}
	values := map[string][]auditField{}
	for _, field := range fields {
		values[field.Name] = append(values[field.Name], field)
	}
	get := func(key string) string {
		if len(values[key]) != 1 {
			return ""
		}
		return values[key][0].Value
	}
	switch {
	case out.RecordType == "1326":
		out.Mechanism, out.PIDSemantics = "seccomp", "host_thread_group"
	case len(values["apparmor"]) > 0 && auditAppArmorType(out.RecordType):
		out.Mechanism, out.PIDSemantics = "apparmor", "host_thread_group"
	default:
		return AuditRecord{}, false, nil
	}
	seconds, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil || seconds > 253402300799 {
		return out, false, fmt.Errorf("audit timestamp is out of range")
	}
	nanos, _ := strconv.ParseInt(m[3]+strings.Repeat("0", 9-len(m[3])), 10, 64)
	serial, err := strconv.ParseUint(m[4], 10, 64)
	if err != nil {
		return out, false, fmt.Errorf("audit serial is out of range")
	}
	out.Timestamp = time.Unix(seconds, nanos).UTC().Format(time.RFC3339Nano)
	out.TimestampPrecisionNS = 1
	for i := len(m[3]); i < 9; i++ {
		out.TimestampPrecisionNS *= 10
	}
	out.AuditID = fmt.Sprintf("%d.%09d:%d", seconds, nanos, serial)
	out.AuditSource = source
	out.BootID = normalizeAuditBoot(source.BootID)
	out.SchemaVersion, out.EvidenceKind, out.Decision = AuditSchemaVersion, "audit_decision", "unknown"
	for key, fields := range values {
		if len(fields) > 1 {
			out.Warnings = append(out.Warnings, "duplicate_field:"+key)
		}
	}
	textField := func(key string) string {
		value := get(key)
		if value == "" || values[key][0].Quoted {
			return value
		}
		// audit_log_untrustedstring uses hexadecimal for unsafe byte strings.
		if decoded, err := hex.DecodeString(value); err == nil && len(decoded) > 0 {
			if !utf8.Valid(decoded) || bytes.IndexByte(decoded, 0) >= 0 {
				out.Warnings = append(out.Warnings, "non_text_field:"+key)
				return ""
			}
			return string(decoded)
		}
		return value
	}
	integer := func(key string, minimum int64) *int64 {
		value := get(key)
		if value == "" {
			return nil
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < minimum {
			out.Warnings = append(out.Warnings, "invalid_field:"+key)
			return nil
		}
		return &n
	}
	out.AuditPID, out.Comm, out.Executable = integer("pid", 1), textField("comm"), textField("exe")
	out.Label = textField("subj")
	if out.Mechanism == "apparmor" {
		out.Profile, out.Operation, out.Target = textField("profile"), get("operation"), textField("name")
		out.ProfileNamespace, out.Label, out.Class = textField("namespace"), textField("label"), get("class")
		out.RequestedMask, out.DeniedMask = get("requested_mask"), get("denied_mask")
		switch decision := get("apparmor"); decision {
		case "DENIED", "ALLOWED", "AUDIT", "KILLED":
			out.Decision = decision
		case "STATUS", "HINT", "ERROR":
			out.Decision, out.EvidenceKind = decision, "audit_status"
		default:
			out.Warnings = append(out.Warnings, "unknown_apparmor_decision")
		}
	} else {
		out.Arch, out.SyscallNumber, out.Signal = get("arch"), integer("syscall", 0), integer("sig", 0)
		if out.Signal != nil && *out.Signal > 64 {
			out.Signal = nil
			out.Warnings = append(out.Warnings, "invalid_field:sig")
		}
		out.ABI, out.SyscallName = auditSyscall(out.Arch, out.SyscallNumber)
		if out.ABI == "" {
			out.Warnings = append(out.Warnings, "unknown_audit_abi")
		}
		code := strings.TrimPrefix(strings.ToLower(get("code")), "0x")
		if parsed, err := strconv.ParseUint(code, 16, 32); err == nil {
			c, data := uint32(parsed), uint16(parsed&0xffff)
			out.ActionCode, out.ActionData = &c, &data
			if action := seccompAction(c & 0xffff0000); action != "" {
				out.Decision = action
			} else {
				out.Warnings = append(out.Warnings, "unknown_seccomp_action")
			}
		} else {
			out.Warnings = append(out.Warnings, "missing_or_invalid_seccomp_action")
		}
	}
	if len(out.HostID) > 256 || len(out.BootID) > 64 || strings.ContainsAny(out.HostID+out.BootID, "\r\n\x00") {
		return out, false, fmt.Errorf("invalid audit source identity")
	}
	bootBytes, bootErr := hex.DecodeString(strings.ReplaceAll(out.BootID, "-", ""))
	if out.HostID == "" || len(bootBytes) != 16 || bootErr != nil {
		out.Warnings = append(out.Warnings, "incomplete_source_identity")
	} else {
		// Transport prefixes, whitespace and field order do not change a record.
		// Repeated fields remain in the identity and are never silently overwritten.
		sort.Slice(fields, func(i, j int) bool {
			if fields[i].Name != fields[j].Name {
				return fields[i].Name < fields[j].Name
			}
			if fields[i].Value != fields[j].Value {
				return fields[i].Value < fields[j].Value
			}
			return !fields[i].Quoted && fields[j].Quoted
		})
		canonical, _ := json.Marshal([]any{out.HostID, out.BootID, out.AuditID, out.RecordType, fields})
		sum := sha256.Sum256(canonical)
		out.RecordID = fmt.Sprintf("audit-v1:%x", sum)
	}
	sort.Strings(out.Warnings)
	sum := sha256.Sum256([]byte(message))
	out.RawRecord = AuditRawRecord{State: "available", SHA256: hex.EncodeToString(sum[:]), Bytes: len(message), Text: message, DigestScope: "source_before_redaction"}
	return out, true, nil
}

func auditAppArmorType(value string) bool {
	switch value {
	case "1400", "1501", "1502", "1503", "1504", "1505", "1506", "1507":
		return true
	}
	return false
}

func normalizeAuditBoot(value string) string {
	compact := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
	if len(compact) == 32 {
		if _, err := hex.DecodeString(compact); err == nil {
			return compact[:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" + compact[16:20] + "-" + compact[20:]
		}
	}
	return strings.TrimSpace(value)
}

func auditRecordType(value string) string {
	switch value {
	case "SECCOMP":
		return "1326"
	case "AVC":
		return "1400"
	case "APPARMOR_AUDIT":
		return "1501"
	case "APPARMOR_ALLOWED":
		return "1502"
	case "APPARMOR_DENIED":
		return "1503"
	case "APPARMOR_HINT":
		return "1504"
	case "APPARMOR_STATUS":
		return "1505"
	case "APPARMOR_ERROR":
		return "1506"
	case "APPARMOR_KILL":
		return "1507"
	}
	return value
}

func seccompAction(code uint32) string {
	switch code {
	case 0:
		return "KILL_THREAD"
	case 0x80000000:
		return "KILL_PROCESS"
	case 0x00030000:
		return "TRAP"
	case 0x00050000:
		return "ERRNO"
	case 0x7fc00000:
		return "USER_NOTIF"
	case 0x7ff00000:
		return "TRACE"
	case 0x7ffc0000:
		return "LOG"
	case 0x7fff0000:
		return "ALLOW"
	}
	return ""
}

// Decode only explicit audit ABIs; never use the importing machine's GOARCH.
func auditSyscall(arch string, number *int64) (string, string) {
	var abi string
	var names map[int64]string
	switch strings.TrimPrefix(strings.ToLower(arch), "0x") {
	case "c000003e":
		if number != nil && *number&0x40000000 != 0 {
			return "x32", ""
		}
		abi, names = "x86_64", map[int64]string{0: "read", 1: "write", 2: "open", 3: "close", 39: "getpid", 41: "socket", 42: "connect", 59: "execve", 60: "exit", 231: "exit_group", 257: "openat", 322: "execveat"}
	case "c00000b7":
		abi, names = "aarch64", map[int64]string{56: "openat", 57: "close", 63: "read", 64: "write", 93: "exit", 94: "exit_group", 172: "getpid", 198: "socket", 203: "connect", 221: "execve", 281: "execveat"}
	}
	if number == nil {
		return abi, ""
	}
	return abi, names[*number]
}

func parseAuditFields(input string) ([]auditField, error) {
	var fields []auditField
	for input = strings.TrimSpace(input); input != ""; input = strings.TrimSpace(input) {
		if len(fields) >= 128 {
			return nil, fmt.Errorf("audit record exceeds 128 fields")
		}
		equal := strings.IndexByte(input, '=')
		if equal < 1 || strings.ContainsAny(input[:equal], " \t\r\n\"'") {
			return nil, fmt.Errorf("invalid audit key/value field")
		}
		field := auditField{Name: input[:equal]}
		input = input[equal+1:]
		if strings.HasPrefix(input, `"`) {
			field.Quoted = true
			end := 1
			for end < len(input) && input[end] != '"' {
				if input[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(input) {
				return nil, fmt.Errorf("unterminated audit string")
			}
			value, err := strconv.Unquote(input[:end+1])
			if err != nil {
				return nil, fmt.Errorf("invalid quoted audit string")
			}
			field.Value, input = value, input[end+1:]
			if input != "" && input[0] != ' ' && input[0] != '\t' {
				return nil, fmt.Errorf("audit fields need whitespace separation")
			}
		} else {
			end := strings.IndexAny(input, " \t")
			if end < 0 {
				end = len(input)
			}
			field.Value, input = input[:end], input[end:]
		}
		if len(field.Name) > 128 || len(field.Value) > 16<<10 {
			return nil, fmt.Errorf("audit field exceeds size limit")
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func auditJournalObject(line []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(line))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("journal record must be a JSON object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid journal record: %w", err)
		}
		name, ok := key.(string)
		if !ok || len(name) > 128 || len(fields) >= 256 {
			return nil, fmt.Errorf("invalid journal key or too many fields")
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, fmt.Errorf("duplicate journal field %q", name)
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid journal value: %w", err)
		}
		fields[name] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, fmt.Errorf("invalid journal record: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after journal record")
	}
	return fields, nil
}
