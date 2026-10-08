//go:build !linux && !darwin

package record

import (
	"fmt"
	"os"
)

func openArtifactFile(root, path string) (*os.File, error) {
	return nil, fmt.Errorf("safe file capture is unsupported on this platform")
}
