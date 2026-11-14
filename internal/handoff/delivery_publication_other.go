//go:build !linux && !darwin

package handoff

import (
	"context"
	"fmt"
	"os"
)

func acquirePublication(context.Context, string, bool) (*publicationLease, error) {
	return nil, fmt.Errorf("delivery publication requires Linux or macOS")
}

func removePublicationStaging(context.Context, *os.File, string) (int64, error) {
	return 0, fmt.Errorf("publication cleanup requires Linux or macOS")
}
