package telemetry

import (
	"encoding/json"
	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
)

func validateAccessStateBody(body map[string]any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var snapshot accesscontrol.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return err
	}
	return accesscontrol.ValidateSnapshot(snapshot)
}
