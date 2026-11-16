package browserlink

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const testBoot = "11111111-1111-4111-8111-111111111111"

func runtimeFixture(t *testing.T) Input {
	t.Helper()
	observation := record(t, "browser-source", "action_start", func(e *entry) { e.Browser.OperationID, e.Browser.Operation = "op", "click" })
	c := RuntimeCustody{RunID: "run", Scope: testScope(), Role: "browser", HostID: "host", PID: 42, ProcessInstanceID: testBoot + ":42:100", SourceRefs: []string{observation.Ref}}
	e := telemetry.EventRecord{ID: "event", RunID: "run", Source: "agentprov_ebpf", EventType: "network_connect", PID: 42,
		Payload: fmt.Sprintf(`{"runtime_process_identity":%q,"host_id":"host","boot_id":%q,"process_instance_id":%q,"dst_ip":"127.0.0.1","dst_port":443}`, telemetry.RuntimeProcessGraphVersion, testBoot, c.ProcessInstanceID)}
	return Input{RunID: "run", Records: []Record{observation}, Events: []telemetry.EventRecord{e}, Custody: []RuntimeCustody{c}}
}

func TestBrowserRuntimeCustodyExactLifetime(t *testing.T) {
	in := runtimeFixture(t)
	file := in.Events[0]
	file.ID, file.EventType = "file", "file_write"
	in.Events = append(in.Events, file)
	p, err := Project(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(relations(p, "browser_scope_process")) != 2 || len(relations(p, "browser_process_activity")) != 2 {
		t.Fatalf("missing process/OS layers: %+v", p)
	}
	id := telemetry.ProcessGraphIdentity(in.Events[0]).Process.ID
	for _, r := range p.Relations {
		if r.Rule != RuntimeRule {
			continue
		}
		if r.SourceEventID == "" || r.Status != "supported" || r.Basis != "runtime_identity" {
			t.Fatalf("missing runtime provenance: %+v", r)
		}
		if r.Kind == "browser_scope_process" && (r.To != id || !strings.HasPrefix(r.From, "browser_scope/")) {
			t.Fatalf("scope mapped to click or bare PID: %+v", r)
		}
		if r.Kind == "browser_process_activity" && r.From != id {
			t.Fatalf("activity not owned by exact process: %+v", r)
		}
		if len(r.SourceRefs) != 2 || r.SourceRefs[0] != "browser-source" || r.SourceRefs[1] != "runtime_event/"+r.SourceEventID {
			t.Fatalf("wrong runtime evidence refs: %+v", r)
		}
	}
}

func TestBrowserRuntimeNegativeControls(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Input)
	}{
		{"no_sensor", func(in *Input) { in.Events = nil }},
		{"no_custody", func(in *Input) { in.Custody = nil }},
		{"missing_support", func(in *Input) { in.Custody[0].SourceRefs = []string{"excluded-source"} }},
		{"pid_reuse", func(in *Input) { in.Events[0].Payload = strings.ReplaceAll(in.Events[0].Payload, ":42:100", ":42:101") }},
		{"host_mismatch", func(in *Input) {
			in.Events[0].Payload = strings.ReplaceAll(in.Events[0].Payload, `"host_id":"host"`, `"host_id":"other"`)
		}},
		{"missing_host", func(in *Input) {
			in.Events[0].Payload = strings.ReplaceAll(in.Events[0].Payload, `"host_id":"host",`, ``)
		}},
		{"boot_mismatch", func(in *Input) {
			in.Events[0].Payload = strings.ReplaceAll(in.Events[0].Payload, testBoot, "22222222-2222-4222-8222-222222222222")
		}},
		{"conflicting_boot", func(in *Input) {
			in.Events[0].Payload = strings.Replace(in.Events[0].Payload, testBoot, "22222222-2222-4222-8222-222222222222", 1)
		}},
		{"bare_pid", func(in *Input) { in.Events[0].Payload = `{"host_id":"host","pid":42}` }},
		{"missing_birth", func(in *Input) { in.Custody[0].ProcessInstanceID = "42" }},
		{"wrong_pid", func(in *Input) { in.Events[0].PID = 43 }},
		{"another_run", func(in *Input) { in.Events[0].RunID = "other" }},
		{"other_context", func(in *Input) { in.Custody[0].Scope.ContextID = "other" }},
		{"other_generation", func(in *Input) { in.Custody[0].Scope.Generation = "other" }},
		{"legacy_v2", func(in *Input) {
			in.Events[0].Payload = strings.ReplaceAll(in.Events[0].Payload, telemetry.RuntimeProcessGraphVersion, telemetry.RuntimeProcessGraphV2)
		}},
		{"sentry_host_pid", func(in *Input) { in.Events[0].Source = "agentprov_seccheck" }},
		{"sentry_identity", func(in *Input) {
			in.Events[0].Payload = strings.ReplaceAll(in.Events[0].Payload, telemetry.RuntimeProcessGraphVersion, telemetry.RuntimeSentryGraphVersion)
		}},
		{"untrusted_capture_source", func(in *Input) { in.Events[0].Source = "browser" }},
		{"conflicting_envelope", func(in *Input) {
			in.Events[0].Payload = fmt.Sprintf(`{"runtime_process_identity":%q,"host_id":"other","payload":%s}`, telemetry.RuntimeProcessGraphVersion, in.Events[0].Payload)
		}},
		{"duplicate_json", func(in *Input) {
			in.Events[0].Payload = strings.ReplaceAll(in.Events[0].Payload, `"host_id":"host"`, `"host_id":"other","host_id":"host"`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := runtimeFixture(t)
			tc.change(&in)
			p, err := Project(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range p.Relations {
				if r.Rule == RuntimeRule {
					t.Fatalf("unsafe runtime link: %+v", r)
				}
			}
		})
	}
}

func TestBrowserRuntimeCustodyConflictAndImportedClaims(t *testing.T) {
	in := runtimeFixture(t)
	conflict := in.Custody[0]
	conflict.ProcessInstanceID = testBoot + ":42:101"
	in.Custody = append(in.Custody, conflict)
	p, err := Project(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(relations(p, "browser_scope_process")) != 0 || !hasIssue(p, "ambiguous", "conflicting_runtime_custody") {
		t.Fatalf("conflicting custody accepted: %+v", p)
	}
	var claim RuntimeCustody
	if err := json.Unmarshal([]byte(`{"authentication":"verified","PID":42}`), &claim); err == nil {
		t.Fatal("JSON authorized runtime custody")
	}
	in = runtimeFixture(t)
	in.Custody = nil
	var body map[string]any
	if err := json.Unmarshal(in.Records[0].Payload, &body); err != nil {
		t.Fatal(err)
	}
	body["browser_runtime_custody"] = map[string]any{"authentication": "verified", "host_id": "host", "process_instance_id": testBoot + ":42:100"}
	in.Records[0].Payload, _ = json.Marshal(body)
	p, err = Project(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(relations(p, "browser_scope_process")) != 0 || !hasIssue(p, "unresolved", "runtime_custody_not_supplied") {
		t.Fatal("artifact self-authorized")
	}
}

func TestBrowserSharedProcessNeverAttributesSocketToClick(t *testing.T) {
	in := runtimeFixture(t)
	other := record(t, "second-tab", "request", func(e *entry) { e.Source.Browser.ContextID = "other"; e.Browser.RequestID = "req" })
	in.Records = append(in.Records, other)
	second := in.Custody[0]
	second.Scope.ContextID, second.SourceRefs = "other", []string{other.Ref}
	in.Custody = append(in.Custody, second)
	p, err := Project(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(relations(p, "browser_scope_process")) != 2 {
		t.Fatal("explicit shared process mapping lost")
	}
	for _, r := range p.Relations {
		if r.Rule == RuntimeRule && (r.From == "second-tab" || r.From == "browser-source") {
			t.Fatal("shared socket assigned to action/request")
		}
	}
}
