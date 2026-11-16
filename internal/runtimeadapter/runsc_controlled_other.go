//go:build !linux

package runtimeadapter

import (
	"context"
	"fmt"
)

func (s Runsc) runGated(_ context.Context, r Request, _ func(Execution) error) (Execution, error) {
	return NewExecution(s.Binding, r), fmt.Errorf("controlled runsc execution requires Linux")
}
