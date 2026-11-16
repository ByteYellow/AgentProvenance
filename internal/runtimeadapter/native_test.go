package runtimeadapter

import (
	"bytes"
	"context"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestNativeAdapterRunsExistingServiceWithTerminalEvidence(t *testing.T) {
	for _, mode := range []string{"native", "guest"} {
		t.Run(mode, func(t *testing.T) {
			paths, err := store.Init(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			r := testRequest()
			out := &bytes.Buffer{}
			r.Command.Command = []string{"printf", "native-output"}
			r.Command.Stdout = out
			r.Command.PostRootGraceMS = 1
			n := Native{Binding: Binding{Target: r.Target, Mode: mode}, Service: record.Service{DB: db, Paths: paths}}
			starts := 0
			e, err := n.Run(context.Background(), r, func(x Execution) error {
				starts++
				if x.State != "running" {
					t.Error(x.State)
				}
				return nil
			})
			if err != nil || e.State != "succeeded" || e.Record == nil || e.Record.EndEventID == "" || e.ExitCode == nil || *e.ExitCode != 0 || starts != 1 || out.String() != "native-output" {
				t.Fatalf("native parity: %+v %v output=%q starts=%d", e, err, out.String(), starts)
			}
			if e.SentryPID != 0 || e.SentryPIDBasis != "" {
				t.Fatal("native PID entered the Sentry identity domain")
			}
		})
	}
}
