//go:build !linux && !darwin

package telemetry

import (
	"fmt"
	"os"
)

func lockNativeStream(path string) (*os.File, error) {
	return nil, fmt.Errorf("native sensor streaming requires Linux")
}
func syncNativeDirectory(path string) error { return nil }

func nativeStreamRunning(path string) (bool, error) { return false, nil }
