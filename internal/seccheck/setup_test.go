package seccheck

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCollectionConfigurationBoundaries(t *testing.T) {
	valid := CollectionConfig{SchemaVersion: CollectionConfigSchema, RuntimeRelease: RuntimeRelease, Targets: []Target{{RunID: "run", SocketPath: "/tmp/private/one.sock", Registration: testRegistration()}}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*CollectionConfig)
	}{
		{"schema", func(c *CollectionConfig) { c.SchemaVersion = "other" }},
		{"runtime", func(c *CollectionConfig) { c.RuntimeRelease = "latest" }},
		{"empty", func(c *CollectionConfig) { c.Targets = nil }},
		{"limit", func(c *CollectionConfig) { c.Targets = make([]Target, 65) }},
		{"run", func(c *CollectionConfig) { c.Targets[0].RunID = "" }},
		{"relative", func(c *CollectionConfig) { c.Targets[0].SocketPath = "relative.sock" }},
		{"alias", func(c *CollectionConfig) { c.Targets[0].SocketPath = "/tmp/private/../one.sock" }},
		{"identity", func(c *CollectionConfig) { c.Targets[0].Registration.Generation = "" }},
		{"duplicate", func(c *CollectionConfig) {
			c.Targets = append(c.Targets, c.Targets[0])
			c.Targets[1].SocketPath = "/tmp/private/two.sock"
			c.Targets[1].RunID = "another"
		}},
		{"socket", func(c *CollectionConfig) {
			c.Targets = append(c.Targets, c.Targets[0])
			c.Targets[1].Registration.Generation = "another"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			c.Targets = append([]Target(nil), valid.Targets...)
			tc.mutate(&c)
			if c.Validate() == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestTraceConfigurationKeepsCheckpointAndCapabilityScope(t *testing.T) {
	c, err := TraceConfig("/tmp/private/events.sock")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "credentials") || strings.Contains(string(b), "env") || len(c["trace_session"].(map[string]any)["points"].([]TracePoint)) != 10 {
		t.Fatal(string(b))
	}
	cap := ReceiverCapabilities()
	if cap.SystemTelemetry != "partial" || cap.ModelIntent != "none" || cap.AppContext != "none" || cap.IdentityDomain != "sentry" || cap.RuntimeBasis != "trusted_launcher_assertion" {
		t.Fatalf("capability=%+v", cap)
	}
}
