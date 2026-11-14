//go:build linux || darwin

package sensor

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func sensorContext(opts Options) (context.Context, context.CancelFunc) {
	parent := opts.Context
	if parent == nil {
		parent = context.Background()
	}
	if opts.ContextOnly {
		return context.WithCancel(parent)
	}
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
