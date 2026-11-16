package runtimeadapter

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

// ReadSecCheckStatus consumes the existing receive-seccheck --json status
// stream. Incomplete final writes are ignored; Probe checks snapshot freshness.
func ReadSecCheckStatus(name string) (telemetry.SecCheckCollectStatus, error) {
	var status telemetry.SecCheckCollectStatus
	raw, err := readTrustedTail(name, 1<<20)
	if err != nil {
		return status, err
	}
	return decodeSecCheckStatus(raw)
}

func decodeSecCheckStatus(raw []byte) (telemetry.SecCheckCollectStatus, error) {
	var status telemetry.SecCheckCollectStatus
	end := bytes.LastIndexByte(raw, '\n')
	if end < 0 {
		return status, fmt.Errorf("SecCheck status has no complete JSON record")
	}
	raw = raw[:end]
	start := bytes.LastIndexByte(raw, '\n') + 1
	if err := json.Unmarshal(raw[start:], &status); err != nil {
		return status, fmt.Errorf("invalid SecCheck status record: %w", err)
	}
	return status, nil
}
