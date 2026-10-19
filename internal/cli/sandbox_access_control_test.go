package cli

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
	"github.com/byteyellow/agentprovenance/internal/producer/k8sinformer"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestInformerConfigSnapshotsDoNotRewriteHistory(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sink := localK8sScopeSink{db: db}
	scope := k8sinformer.ContainerScope{RunID: "run", SessionID: "pod-uid", PodUID: "pod-uid", ContainerName: "worker", ContainerID: "container", StartedAt: "2026-10-19T00:00:00Z", ObservedAt: "2026-10-19T00:00:01Z"}
	if _, err := sink.Bind(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	var original string
	if err := db.QueryRow(`SELECT payload FROM events WHERE event_type='pod_metadata'`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	scope.AccessControl = []accesscontrol.Declaration{{Mechanism: "seccomp", EvidenceKind: "configuration_declaration", Status: "declared", Source: "k8s_api:spec.securityContext.seccompProfile", ResourceVersion: "1", ObservedAt: scope.ObservedAt, ProfileType: "RuntimeDefault"}}
	for i := 0; i < 2; i++ {
		if _, err := sink.Bind(context.Background(), scope); err != nil {
			t.Fatal(err)
		}
		scope.ObservedAt = "2026-10-19T00:00:02Z"
		scope.AccessControl[0].ObservedAt = scope.ObservedAt
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type='access_control_config'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retry duplicated config: %d %v", count, err)
	}
	scope.AccessControl[0].ResourceVersion = "2"
	scope.AccessControl[0].ProfileType = "Unconfined"
	if _, err := sink.Bind(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type='access_control_config'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("updated configuration not appended: %d %v", count, err)
	}
	var after string
	if err := db.QueryRow(`SELECT payload FROM events WHERE event_type='pod_metadata'`).Scan(&after); err != nil || after != original {
		t.Fatal("historical metadata overwritten")
	}
	var raw string
	if err := db.QueryRow(`SELECT payload FROM events WHERE event_type='access_control_config' ORDER BY created_at LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil || body["evidence_kind"] != "configuration_declaration" || body["decision"] != nil {
		t.Fatalf("configuration became decision: %s", raw)
	}
}
