//go:build !linux && !darwin

package handoff

import (
	"fmt"
	"os"
)

func lockExecutor(root string) (*os.File, error) {
	return nil, fmt.Errorf("execution worker requires Linux or macOS")
}
