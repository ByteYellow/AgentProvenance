package telemetry

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

var auditTestSource = AuditSource{HostID: "fixture-host", BootID: "01234567-89ab-cdef-0123-456789abcdef"}

const auditTestPrefix = "type=SECCOMP msg=audit(1792342593.757:130): "
const auditTestSeccomp = auditTestPrefix + `pid=42 comm="fixture" arch=c00000b7 syscall=203 sig=0 code=0x7ffc0000`

func parseAuditTest(t *testing.T, input string) AuditRecord {
	t.Helper()
	record, ok, err := ParseAuditLine([]byte(input), auditTestSource)
	if err != nil || !ok {
		t.Fatalf("parse: ok=%v err=%v", ok, err)
	}
	return record
}

func TestAuditParserRetainsAppArmorDecisionWithoutModeInference(t *testing.T) {
	path := "/tmp/secret file"
	line := `type=AVC msg=audit(1792342593.757:130): apparmor="DENIED" operation="open" profile="fixture-policy" pid=42 comm="cat" name=` + hex.EncodeToString([]byte(path)) + ` requested_mask="r" denied_mask="r" fsuid=1000 ouid=0`
	r := parseAuditTest(t, line)
	if r.Mechanism != "apparmor" || r.Decision != "DENIED" || r.EvidenceKind != "audit_decision" || r.Target != path || r.Profile != "fixture-policy" || r.RequestedMask != "r" || r.DeniedMask != "r" || r.AuditPID == nil || *r.AuditPID != 42 {
		t.Fatalf("wrong AppArmor decision: %+v", r)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), `"mode"`) || strings.Contains(string(raw), `"exit_code"`) || r.RawRecord.Text != line || r.RecordID == "" {
		t.Fatalf("invented mode/result or lost source: %s", raw)
	}
	r = parseAuditTest(t, line+` namespace="isolated" label="stacked-label" class="file"`)
	if r.ProfileNamespace != "isolated" || r.Label != "stacked-label" || r.Class != "file" || r.PIDSemantics != "host_thread_group" || r.TimestampPrecisionNS != 1000000 {
		t.Fatalf("lost namespace/label or timestamp precision: %+v", r)
	}
	for _, decision := range []string{"ALLOWED", "AUDIT", "KILLED", "STATUS", "HINT", "ERROR", "FUTURE"} {
		r = parseAuditTest(t, strings.Replace(line, "DENIED", decision, 1))
		if decision == "FUTURE" {
			if r.Decision != "unknown" {
				t.Fatalf("unknown AppArmor decision became %s", r.Decision)
			}
		} else if r.Decision != decision {
			t.Fatalf("lost AppArmor decision %s", decision)
		}
		if decision == "STATUS" && r.EvidenceKind != "audit_status" {
			t.Fatal("profile status counted as a decision")
		}
	}
}

func TestAuditSeccompUsesRecordedABIAndRawAction(t *testing.T) {
	for _, tc := range []struct{ arch, nr, abi, name string }{
		{"c00000b7", "203", "aarch64", "connect"},
		{"c000003e", "42", "x86_64", "connect"},
		{"0XC000003E", "42", "x86_64", "connect"},
		{"c00000b7", "172", "aarch64", "getpid"},
		{"c000003e", "39", "x86_64", "getpid"},
		{"c00000b7", "42", "aarch64", ""},
		{"40000003", "42", "", ""},
		{"c000003e", "1073741866", "x32", ""},
	} {
		r := parseAuditTest(t, auditTestPrefix+fmt.Sprintf("pid=42 arch=%s syscall=%s sig=0 code=0x00050001", tc.arch, tc.nr))
		if r.ABI != tc.abi || r.SyscallName != tc.name || r.Decision != "ERRNO" || r.ActionCode == nil || *r.ActionCode != 0x50001 || r.ActionData == nil || *r.ActionData != 1 || r.Signal == nil || *r.Signal != 0 {
			t.Fatalf("wrong ABI/action: %+v", r)
		}
	}
	for _, tc := range []struct{ code, decision string }{
		{"0x0", "KILL_THREAD"}, {"0x80000000", "KILL_PROCESS"}, {"0x30000", "TRAP"},
		{"0x50000", "ERRNO"}, {"0x7fc00000", "USER_NOTIF"}, {"0x7ff00000", "TRACE"},
		{"0x7ffc0000", "LOG"}, {"0x7fff0000", "ALLOW"}, {"0x12345678", "unknown"},
		{"0X80000000", "KILL_PROCESS"}, {"nonsense", "unknown"},
	} {
		r := parseAuditTest(t, auditTestPrefix+"pid=42 arch=c00000b7 syscall=203 code="+tc.code)
		if r.Decision != tc.decision {
			t.Fatalf("code=%s got=%s want=%s", tc.code, r.Decision, tc.decision)
		}
	}
}

func TestAuditJournalAndTextDeduplicateBySourceRecord(t *testing.T) {
	plain := parseAuditTest(t, auditTestSeccomp)
	message := "audit: type=1326 audit(1792342593.757000:130): code=0x7ffc0000 sig=0 syscall=203 arch=c00000b7 comm=\"fixture\" pid=42"
	data, _ := json.Marshal(map[string]any{"MESSAGE": message, "_MACHINE_ID": auditTestSource.HostID, "_BOOT_ID": strings.ReplaceAll(auditTestSource.BootID, "-", ""), "_PID": "999", "__CURSOR": "journal-cursor", "__REALTIME_TIMESTAMP": "not-the-event-time"})
	journal, ok, err := ParseAuditLine(data, AuditSource{})
	if err != nil || !ok || journal.RecordID != plain.RecordID || journal.Timestamp != plain.Timestamp || *journal.AuditPID != 42 || journal.JournalCursor != "journal-cursor" {
		t.Fatalf("transport changed identity: %+v %+v %v", plain, journal, err)
	}
	if _, _, err := ParseAuditLine(data, AuditSource{HostID: "other-host"}); err == nil {
		t.Fatal("conflicting journal identity accepted")
	}
	for _, source := range []AuditSource{{HostID: "other-host", BootID: auditTestSource.BootID}, {HostID: auditTestSource.HostID, BootID: "11234567-89ab-cdef-0123-456789abcdef"}} {
		r, _, err := ParseAuditLine([]byte(auditTestSeccomp), source)
		if err != nil || r.RecordID == plain.RecordID {
			t.Fatalf("cross-host/boot identity merged: %+v %v", r, err)
		}
	}
	for _, source := range []AuditSource{{}, {HostID: "host"}, {HostID: "host", BootID: "unknown"}} {
		r, ok, err := ParseAuditLine([]byte(auditTestSeccomp), source)
		if err != nil || !ok || r.RecordID != "" || !strings.Contains(strings.Join(r.Warnings, ","), "incomplete_source_identity") {
			t.Fatalf("missing identity guessed: %+v %v", r, err)
		}
	}
}

func TestAuditParserDoesNotOverwriteAmbiguousFields(t *testing.T) {
	r := parseAuditTest(t, auditTestSeccomp+" pid=43 code=0x80000000 syscall=42")
	if r.AuditPID != nil || r.SyscallNumber != nil || r.ActionCode != nil || r.Decision != "unknown" || len(r.Warnings) < 3 {
		t.Fatalf("duplicate fields silently overwritten: %+v", r)
	}
	for _, suffix := range []string{"", "pid=abc syscall=foo sig=-1 code=", "pid=-1 syscall=-3 sig=999 code=xyz"} {
		r := parseAuditTest(t, auditTestPrefix+suffix)
		if r.Decision != "unknown" || r.AuditPID != nil || r.SyscallNumber != nil || r.Signal != nil {
			t.Fatalf("missing/invalid fields became zero: %+v", r)
		}
	}
}

func TestAuditParserBoundsAndUnrelatedLogs(t *testing.T) {
	for _, line := range []string{
		strings.Repeat("x", MaxAuditLineBytes+1),
		auditTestPrefix + `comm="unterminated`,
		auditTestPrefix + `comm="fixture"pid=42`,
		auditTestPrefix + strings.Repeat("key=value ", 129),
		auditTestPrefix + "comm=" + strings.Repeat("a", 16385),
		`{"MESSAGE":"x","MESSAGE":"y"}`,
		`{"MESSAGE":42}`,
		`{"MESSAGE":null}`,
		`{"` + strings.Repeat("k", 129) + `":"value","MESSAGE":"x"}`,
		`{"MESSAGE":"x"} {}`,
		"type=SECCOMP msg=audit(bad): code=0x0",
		auditTestSeccomp + "\n" + auditTestSeccomp,
	} {
		if _, _, err := ParseAuditLine([]byte(line), auditTestSource); err == nil {
			t.Fatalf("malformed input accepted: %.90s", line)
		}
	}
	for _, line := range []string{
		"ordinary application message: permission denied",
		`type=SYSCALL msg=audit(1792342593.757:130): syscall=203 exit=-1`,
		`type=AVC msg=audit(1792342593.757:130): avc: denied { read } for pid=42`,
		`{"MESSAGE":"EPERM"}`,
	} {
		if _, ok, err := ParseAuditLine([]byte(line), auditTestSource); err != nil || ok {
			t.Fatalf("unrelated error inferred as security decision: %q %v", line, err)
		}
	}
}

func FuzzAuditParser(f *testing.F) {
	f.Add([]byte(auditTestSeccomp))
	f.Add([]byte(`type=AVC msg=audit(1792342593.757:130): apparmor="DENIED" name="/tmp/fixture"`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, ok, err := ParseAuditLine(data, auditTestSource)
		if err == nil && ok {
			payload, err := json.Marshal(r)
			if err != nil || ValidateRawPayload("access_control", string(payload)) != nil {
				t.Fatalf("accepted record cannot be stored: %s %v", payload, err)
			}
		}
	})
}
