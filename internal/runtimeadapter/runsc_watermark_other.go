//go:build !linux

package runtimeadapter

import (
	"context"
	"fmt"
)

func (s Runsc) ObserveProcesses(context.Context, []SentryProcess) (ProcessDrain, error) {
	return ProcessDrain{}, fmt.Errorf("runsc task observation requires Linux")
}

func (s Runsc) Barrier(context.Context, string) (RuntimeBarrier, error) {
	return RuntimeBarrier{}, fmt.Errorf("runsc capture barrier requires Linux")
}
