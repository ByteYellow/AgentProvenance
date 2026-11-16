package handoff

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"gopkg.in/yaml.v3"
)

func runtimeAPIDocument(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/execution-handoff-api.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document["openapi"] != "3.1.0" {
		t.Fatal("execution API must remain OpenAPI 3.1")
	}
	return document, document["components"].(map[string]any)["schemas"].(map[string]any)
}

func TestRuntimeOpenAPISchemasMatchJSONFields(t *testing.T) {
	document, schemas := runtimeAPIDocument(t)
	var visit func(any)
	visit = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			if ref, ok := node["$ref"].(string); ok {
				if !strings.HasPrefix(ref, "#/") {
					t.Fatalf("runtime schema reference must be local: %s", ref)
				}
				var target any = document
				for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
					parent, _ := target.(map[string]any)
					target = parent[part]
					if target == nil {
						t.Fatalf("unresolved runtime schema reference: %s", ref)
					}
				}
			}
			for _, child := range node {
				visit(child)
			}
		case []any:
			for _, child := range node {
				visit(child)
			}
		}
	}
	for name, value := range map[string]any{
		"PlatformBinding":             runtimeadapter.Binding{},
		"RuntimeReport":               RuntimeReport{},
		"RuntimeExecution":            runtimeadapter.Execution{},
		"RuntimeCaptureReport":        runtimeadapter.CaptureReport{},
		"RuntimeCapturePoint":         runtimeadapter.CapturePoint{},
		"RuntimeReceiverTarget":       seccheck.Target{},
		"RuntimeReceiverRegistration": seccheck.Registration{},
		"RuntimeReceiverTargetStatus": telemetry.SecCheckTargetStatus{},
		"RuntimeReceiverCapabilities": seccheck.Capabilities{},
	} {
		t.Run(name, func(t *testing.T) {
			schema := schemas[name].(map[string]any)
			visit(schema)
			if schema["type"] != "object" || schema["additionalProperties"] != false {
				t.Fatal("runtime wire objects must enumerate their fields")
			}
			properties := schema["properties"].(map[string]any)
			required := schema["required"].([]any)
			fields := 0
			var check func(reflect.Type)
			check = func(typ reflect.Type) {
				for i := 0; i < typ.NumField(); i++ {
					field := typ.Field(i)
					if field.Anonymous {
						check(field.Type)
						continue
					}
					tag := strings.Split(field.Tag.Get("json"), ",")
					if tag[0] == "-" {
						continue
					}
					fields++
					if properties[tag[0]] == nil || slices.Contains(required, any(tag[0])) == slices.Contains(tag, "omitempty") {
						t.Errorf("schema field or requiredness differs from JSON tag %q", field.Tag.Get("json"))
					}
				}
			}
			check(reflect.TypeOf(value))
			if fields != len(properties) {
				t.Fatalf("schema has %d properties for %d JSON fields", len(properties), fields)
			}
		})
	}
	visit(schemas["RuntimeReceiverStatus"])
	execution := schemas["RuntimeExecution"].(map[string]any)["properties"].(map[string]any)
	if execution["schema_version"].(map[string]any)["const"] != runtimeadapter.Schema || execution["state"].(map[string]any)["$ref"] != "#/components/schemas/State/properties/execution" {
		t.Fatal("runtime execution must use its wire version and the handoff execution states")
	}
	mode := schemas["PlatformBinding"].(map[string]any)["properties"].(map[string]any)["mode"].(map[string]any)
	if !reflect.DeepEqual(mode["enum"], []any{"native", "guest", "runsc"}) {
		t.Fatal("platform binding must describe all three supported modes")
	}
	checkpoint := schemas["Checkpoint"].(map[string]any)
	for field, schema := range map[string]string{"platform_binding": "PlatformBinding", "runtime_report": "RuntimeReport"} {
		property := checkpoint["properties"].(map[string]any)[field].(map[string]any)
		if property["$ref"] != "#/components/schemas/"+schema || slices.Contains(checkpoint["required"].([]any), any(field)) {
			t.Fatalf("checkpoint %s must be an optional reference to %s", field, schema)
		}
	}
}

func TestRuntimeOpenAPIWireProjection(t *testing.T) {
	_, schemas := runtimeAPIDocument(t)
	marshal := func(value any) map[string]any {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		return object
	}
	a := Attempt{ID: "handoff-attempt", LocalRunID: "execution-run", Request: fixtureRequest()}
	binding := runtimeadapter.Binding{Target: runtimeadapter.Target(a.Request.Target), Mode: "guest"}.WithGuest(runtimeadapter.GuestIdentity{
		RuntimeClass: "kata", RuntimeHandler: "kata-qemu", PodUID: "pod-uid", ContainerID: "cri-container", GuestBootID: "guest-boot",
	})
	c := Checkpoint{State: State{Execution: Succeeded}, PlatformBinding: &binding, Capture: &NativeCaptureReport{}, Result: &record.Result{RootPID: 42, EndEventID: "exec-end"}}
	c.Runtime = guestRuntimeReport(a, c, binding)
	guest := marshal(c)
	report := guest["runtime_report"].(map[string]any)
	execution := report["execution"].(map[string]any)
	if report["capture"] != nil || guest["capture_report"] == nil || !reflect.DeepEqual(execution["binding"], guest["platform_binding"]) {
		t.Fatal("Guest must retain its platform binding and separate native capture report")
	}
	if execution["run_id"] != a.LocalRunID || execution["attempt_id"] != a.ID || execution["operation_id"] != a.Request.OperationID || execution["state"] != "succeeded" {
		t.Fatal("Guest execution must use the authoritative handoff identities and state")
	}
	if native := marshal(Checkpoint{}); native["runtime_report"] != nil || native["platform_binding"] != nil {
		t.Fatal("legacy native checkpoints must omit absent runtime fields")
	}
	target := seccheck.Target{RunID: "receiver-run", SocketPath: "/run/agentprov/events.sock", Registration: seccheck.Registration{
		Namespace: binding.Target.ProducerID, InstanceID: binding.Target.InstanceID, Generation: binding.Target.Generation, SandboxID: "sandbox", ContainerID: "container",
	}}
	other := target
	other.RunID = "unrelated-run"
	point := runtimeadapter.CapturePoint{Target: binding.Target, Scope: target, ObservedAt: time.Now().UTC(), Status: telemetry.SecCheckCollectStatus{
		SchemaVersion: "agentprovenance.seccheck_status/v1", CollectorID: "collector", GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), State: "listening",
		ExpectedRuntimeRelease: seccheck.RuntimeRelease, ProtocolVersion: seccheck.ProtocolVersion, Capabilities: seccheck.ReceiverCapabilities(), Error: "unrelated node error",
		Targets: []telemetry.SecCheckTargetStatus{{Target: target, State: "connected", ConnectionID: "connection"}, {Target: other, State: "connected"}},
	}}
	x := runtimeadapter.NewExecution(runtimeadapter.Binding{Target: binding.Target, Mode: "runsc", ContainerID: "container", StateCreated: point.ObservedAt.Format(time.RFC3339Nano)},
		runtimeadapter.Request{OperationID: a.Request.OperationID, AttemptID: a.ID, Command: record.Request{RunID: a.LocalRunID}})
	x.State, x.Started, x.RuntimeRelease = "unknown", true, seccheck.RuntimeRelease
	x.SentryPID, x.SentryPIDBasis = 42, "runsc_internal_pid_file"
	x.Gaps = []string{"shared_call_identity_unavailable"}
	runtime := marshal(RuntimeReport{Execution: x, Capture: &runtimeadapter.CaptureReport{
		ObservationLayer: "sentry", State: "incomplete", Start: &point, Gaps: []string{"command_capture_watermark_unavailable"},
	}})
	if observation := runtime["execution"].(map[string]any); observation["state"] != "unknown" || observation["exit_code"] != nil {
		t.Fatal("unknown runtime execution must omit its exit code")
	}
	status := runtime["capture"].(map[string]any)["start"].(map[string]any)["receiver_status"].(map[string]any)
	schema := schemas["RuntimeReceiverStatus"].(map[string]any)
	properties := schema["properties"].(map[string]any)
	if schema["additionalProperties"] != false || len(status) != len(properties) {
		t.Fatal("receiver schema must describe only the persisted status projection")
	}
	for name := range status {
		if properties[name] == nil || !slices.Contains(schema["required"].([]any), any(name)) {
			t.Errorf("receiver projection field %q is undocumented or not required", name)
		}
	}
	for _, name := range []string{"node_spool", "error", "last_worker_error"} {
		if properties[name] != nil || status[name] != nil {
			t.Errorf("node-wide field %s leaked into runtime status", name)
		}
	}
	targets := status["targets"].([]any)
	targetSchema := properties["targets"].(map[string]any)
	if len(targets) != 1 || targets[0].(map[string]any)["run_id"] != target.RunID || targetSchema["minItems"] != 1 || targetSchema["maxItems"] != 1 {
		t.Fatal("runtime status must document and retain exactly the selected receiver target")
	}
	for _, name := range []string{"schema_version", "expected_runtime_release", "protocol_version"} {
		if stringJSON(properties[name].(map[string]any)["const"]) != stringJSON(status[name]) {
			t.Errorf("receiver schema constant %s differs from the wire value", name)
		}
	}
}

func stringJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
