package correlation

import (
	"encoding/json"
	"strings"
)

// CaptureOrigin namespaces kernel-local identifiers by the strongest recorded
// host identity and boot. A boot ID never hides a conflicting explicit host.
// Layers are storage envelopes, not alternative identities to choose between.
func CaptureOrigin(layers []map[string]any, pid int64) (string, bool) {
	field := func(key string) (string, bool) {
		var value string
		for _, layer := range layers {
			raw, exists := layer[key]
			if !exists {
				continue
			}
			s, ok := raw.(string)
			if !ok {
				return "", false
			}
			if s == "" {
				continue
			}
			if strings.TrimSpace(s) != s || (value != "" && value != s) {
				return "", false
			}
			value = s
		}
		return value, true
	}
	var hostKind, host string
	for _, key := range []string{"host_id", "node_name", "node", "hostname", "producer_id"} {
		value, valid := field(key)
		if !valid {
			return "", false
		}
		if host == "" && value != "" {
			hostKind, host = key, value
		}
	}
	instance, valid := field("process_instance_id")
	if !valid {
		return "", false
	}
	boot := ProcessInstanceBootID(instance, pid)
	if instance != "" && boot == "" {
		return "", false
	}
	if explicit, valid := field("boot_id"); !valid {
		return "", false
	} else if explicit != "" {
		parsed := ProcessInstanceBootID(explicit+":1:1", 1)
		if parsed == "" || (boot != "" && boot != parsed) {
			return "", false
		}
		boot = parsed
	}
	if host == "" && boot == "" {
		return "", true
	}
	encoded, _ := json.Marshal([3]string{hostKind, host, boot})
	return string(encoded), true
}
