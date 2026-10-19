//go:build !linux && !darwin

package telemetry

import (
	"fmt"
	"os"
)

func openAuditLog(path string) (*os.File, string, error) {
	return nil, "", fmt.Errorf("following audit files requires Linux or macOS")
}

func lockAuditReader(path string) (*os.File, error) {
	return nil, fmt.Errorf("following audit files requires Linux or macOS")
}
