package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
	"github.com/byteyellow/agentprovenance/internal/producer/k8sinformer"
)

func saveK8sAccessDeclarations(ctx context.Context, tx *sql.Tx, scope k8sinformer.ContainerScope) error {
	if len(scope.AccessControl) == 0 {
		return nil
	}
	body := map[string]any{
		"schema_version": "agentprovenance.access_control_config/v1", "evidence_kind": "configuration_declaration", "source": "k8s_api",
		"pod_uid": scope.PodUID, "namespace": scope.Namespace, "pod_name": scope.PodName, "container_name": scope.ContainerName, "container_id": scope.ContainerID,
	}
	stable := append([]accesscontrol.Declaration(nil), scope.AccessControl...)
	for i := range stable {
		stable[i].ObservedAt = ""
	}
	body["declarations"] = stable
	identity, err := json.Marshal(body)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte(scope.RunID+"\x00"), identity...))
	body["declarations"], body["observed_at"] = scope.AccessControl, scope.ObservedAt
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	// Keep historical pod_metadata intact when upgrading an existing binding.
	// One immutable configuration observation per resource version/content is
	// shared by retries; a changed declaration appends a new observation.
	_, err = tx.ExecContext(ctx, `INSERT INTO events (id,run_id,source,event_type,payload,created_at)
		VALUES (?,?,'k8s','access_control_config',?,?) ON CONFLICT(id) DO NOTHING`,
		fmt.Sprintf("evt_k8s_access_%x", digest), scope.RunID, string(payload), scope.ObservedAt)
	return err
}
