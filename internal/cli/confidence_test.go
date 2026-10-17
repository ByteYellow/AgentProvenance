package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestBindCLIConfidenceZeroAndDefault(t *testing.T) {
	for _, tc := range []struct {
		name, flag, printed string
		want                float64
	}{
		{"default", "", "confidence=0.50", 0.5}, {"zero", "0", "confidence=0.00", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := NewRootCommand()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			args := []string{"--data-dir", dir, "--lang", "en", "telemetry", "bind", "--run", "r", "--tool-call", "", "--source", "ai_asserted"}
			if tc.flag != "" {
				args = append(args, "--confidence", tc.flag)
			}
			root.SetArgs(args)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tc.printed) {
				t.Fatalf("output=%s", out.String())
			}
			paths, err := store.Init(dir)
			if err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			bindings, err := correlation.ListBindings(db, correlation.BindingFilter{RunID: "r"})
			if err != nil || len(bindings) != 1 || bindings[0].Confidence != tc.want {
				t.Fatalf("bindings=%+v err=%v", bindings, err)
			}
		})
	}
}
