//go:build !linux && !darwin

package handoff

import (
	"context"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func removeDeliveryPackage(context.Context, store.Paths, string) (int64, error) {
	return 0, fmt.Errorf("delivery cleanup requires Linux or macOS")
}
