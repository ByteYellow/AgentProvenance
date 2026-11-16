package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
)

func loadReplaySigner(ctx context.Context, keyPath, exporter string) (*dashboard.ReplaySigner, error) {
	if keyPath == "" && exporter == "" {
		return nil, nil
	}
	if keyPath == "" || exporter == "" {
		return nil, fmt.Errorf("replay signing requires both a key path and exporter ID")
	}
	key, err := attest.LoadPrivateKeyHex(keyPath)
	if err != nil {
		return nil, err
	}
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	digest, err := dashboard.ReplayImplementationDigest(ctx, binary)
	if err != nil {
		return nil, err
	}
	return &dashboard.ReplaySigner{ExporterID: exporter, Key: key, ImplementationSHA256: digest}, nil
}
