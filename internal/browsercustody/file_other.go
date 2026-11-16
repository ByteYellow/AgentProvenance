//go:build !linux && !darwin

package browsercustody

import (
	"context"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func readPrivate(context.Context, string) ([]byte, error) {
	return nil, i18n.Errorf("receiver-owned Browser custody is supported on Linux and macOS")
}
