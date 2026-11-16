package runtimeadapter

import (
	"context"
	"errors"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/record"
)

// Native also runs inside an authenticated Guest. It deliberately preserves
// record's policy, scope lifecycle, process reaping, snapshots and event store.
type Native struct {
	Binding Binding
	Service record.Service
}

func (n Native) Admit(ctx context.Context, r Request) error {
	if n.Binding.Mode != "native" && n.Binding.Mode != "guest" {
		return fmt.Errorf("native executor requires a native or guest binding")
	}
	if _, err := n.Binding.Resolve(ctx, r.Target); err != nil {
		return err
	}
	return r.Validate()
}

func (n Native) Run(ctx context.Context, r Request, started func(Execution) error) (Execution, error) {
	e := NewExecution(n.Binding, r)
	if err := n.Admit(ctx, r); err != nil {
		return e, err
	}
	svc := n.Service
	if started != nil {
		lifecycle := record.Lifecycle{}
		if svc.Lifecycle != nil {
			lifecycle = *svc.Lifecycle
		}
		original := lifecycle.Started
		lifecycle.Started = func(scope record.ExecutionScope) error {
			e.Started, e.State = true, "running"
			if original != nil {
				if err := original(scope); err != nil {
					return err
				}
			}
			return started(e)
		}
		svc.Lifecycle = &lifecycle
	}
	result, err := svc.RunContext(ctx, r.Command)
	e.Record, e.Started = &result, result.RootPID > 0
	e.State = "unknown"
	switch result.Status {
	case "passed":
		if result.RootPID > 0 && result.EndEventID != "" && result.ExitCode == 0 {
			e.State = "succeeded"
		}
	case "failed":
		if result.ExitCode != 0 && (result.RootPID == 0 || result.EndEventID != "") {
			e.State = "failed"
		}
	case "cancelled":
		if result.RootPID == 0 || result.EndEventID != "" {
			e.State = "cancelled"
		}
	}
	if result.Stop != nil && result.Stop.ScopeEmpty != nil && !*result.Stop.ScopeEmpty {
		e.State = "unknown"
	}
	if e.State != "unknown" && result.EndEventID != "" {
		code := result.ExitCode
		e.ExitCode = &code
	} else if !e.Started && err != nil {
		e.State = "failed"
		if errors.Is(err, context.Canceled) {
			e.State = "cancelled"
		}
	}
	return e, err
}
