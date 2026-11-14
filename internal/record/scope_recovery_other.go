//go:build !linux

package record

import "fmt"

func OpenRecoveredScope(_ ExecutionScope) (*RecoveredScope, error) {
	return nil, fmt.Errorf("kernel scope recovery requires Linux cgroup v2")
}
