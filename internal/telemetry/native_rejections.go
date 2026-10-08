package telemetry

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const NativeRejectionLimit = 64
const nativeRejectionMaxBytes = 256 << 10

// Rejection diagnostics contain identity and a bounded validation reason,
// never the rejected body, file contents or command arguments.
type NativeRejection struct {
	Timestamp         string `json:"timestamp"`
	EventType         string `json:"event_type"`
	PID               int64  `json:"pid"`
	CgroupID          string `json:"cgroup_id"`
	ProcessInstanceID string `json:"process_instance_id,omitempty"`
	Reason            string `json:"reason"`
}

func (n *NativeStream) reject(event IngestEvent, reason string) error {
	if len(n.rejections) >= NativeRejectionLimit {
		return nil
	}
	n.rejections = append(n.rejections, NativeRejection{Timestamp: rejectionField(event.Timestamp, 40), EventType: rejectionField(event.EventType, 64),
		PID: event.PID, CgroupID: rejectionField(event.CgroupID, 32), ProcessInstanceID: rejectionField(eventIdentity(event).ProcessInstanceID, 80), Reason: rejectionField(reason, 256)})
	raw, err := json.Marshal(n.rejections)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(n.service.Paths.Logs, ".native-rejections-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(n.service.Paths.Logs, "native-rejections.json"))
}

func rejectionField(value string, limit int) string {
	if len(value) > limit {
		value = value[:limit]
	}
	return strings.ToValidUTF8(value, "")
}

func ReadNativeRejections(logs string) ([]NativeRejection, error) {
	f, err := os.Open(filepath.Join(logs, "native-rejections.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, nativeRejectionMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > nativeRejectionMaxBytes {
		return nil, os.ErrInvalid
	}
	var items []NativeRejection
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	if len(items) > NativeRejectionLimit {
		return nil, os.ErrInvalid
	}
	return items, nil
}
