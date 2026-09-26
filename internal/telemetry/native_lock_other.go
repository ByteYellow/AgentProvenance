//go:build !linux && !darwin

package telemetry

import (
	"os"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func lockNativeStream(path string) (*os.File, error) {
	return nil, i18n.Errorf("native sensor streaming requires Linux")
}
func syncNativeDirectory(path string) error { return nil }

func nativeStreamRunning(path string) (bool, error) { return false, nil }
