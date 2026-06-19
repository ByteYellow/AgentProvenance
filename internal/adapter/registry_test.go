package adapter

import "testing"

func TestListIncludesCoreAdapterKinds(t *testing.T) {
	items := List()
	seen := map[string]bool{}
	for _, item := range items {
		seen[item.Kind] = true
		if item.Name == "" || item.Status == "" || item.Boundary == "" {
			t.Fatalf("adapter has incomplete identity: %+v", item)
		}
		if len(item.IdentityKeys) == 0 {
			t.Fatalf("adapter %s missing identity keys", item.Name)
		}
		if len(item.Capabilities) == 0 {
			t.Fatalf("adapter %s missing capabilities", item.Name)
		}
	}
	for _, kind := range []string{"agent", "sandbox", "telemetry", "artifact", "snapshot"} {
		if !seen[kind] {
			t.Fatalf("missing adapter kind %s in %+v", kind, items)
		}
	}
}

func TestDockerDoesNotClaimMemorySnapshot(t *testing.T) {
	item, err := Inspect("docker")
	if err != nil {
		t.Fatal(err)
	}
	for _, cap := range item.Capabilities {
		if cap.Name == "memory_snapshot" && cap.Supported {
			t.Fatalf("docker adapter must not claim memory snapshot support: %+v", cap)
		}
	}
}

func TestListByKindFilters(t *testing.T) {
	items := ListByKind("telemetry")
	if len(items) == 0 {
		t.Fatal("expected telemetry adapter")
	}
	for _, item := range items {
		if item.Kind != "telemetry" {
			t.Fatalf("unexpected adapter kind in filter result: %+v", item)
		}
	}
}
