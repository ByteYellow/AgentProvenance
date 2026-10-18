//go:build darwin || linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
)

func TestHookLogFiltersBeforeWriting(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hooks.jsonl")
			var out, stderr bytes.Buffer
			cmd := internalHookLogCmd()
			cmd.SetIn(strings.NewReader(`{"hook_event_name":"PostToolUse","session_id":"s","tool_use_id":"c","tool_name":"Bash","tool_response":"HOOK-OUTPUT-MARKER","secret":"sk-hook-test-12345678901234567890"}`))
			cmd.SetOut(&out)
			cmd.SetErr(&stderr)
			cmd.SetArgs([]string{"--file", path, "--capture", preset})
			if err := cmd.Execute(); err != nil || out.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("hook: %v %s", err, stderr.String())
			}
			data, err := os.ReadFile(path)
			if err != nil || !json.Valid(bytes.TrimSpace(data)) || !bytes.Contains(data, []byte(`"_ts"`)) {
				t.Fatalf("invalid log: %s %v", data, err)
			}
			if bytes.Contains(data, []byte("sk-hook-test-")) || bytes.Contains(data, []byte("HOOK-OUTPUT-MARKER")) != (preset == "detailed") {
				t.Fatalf("retention/redaction not applied before write: %s", data)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0600 {
				t.Fatalf("hook log permissions: %v", info.Mode())
			}
			parsed, err := agentcontext.Parse(context.Background(), bytes.NewReader(data), agentcontext.ParseOptions{Harness: "claude", Binding: "exact"})
			if err != nil || parsed.Coverage.Status != agentcontext.OK || len(parsed.Records) != 1 || parsed.Records[0].ToolCallID != "c" {
				t.Fatalf("filtered hook not importable: %+v %v", parsed, err)
			}
		})
	}
}

type hookReadError struct{}

func (hookReadError) Read([]byte) (int, error) { return 0, fmt.Errorf("UNSAFE-INPUT-ERROR") }

func TestHookLogFailureIsBoundedAndDoesNotAbortAgent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input io.Reader
		code  string
	}{
		{"null", strings.NewReader("null"), "hook_input_invalid"},
		{"malformed", strings.NewReader("{UNSAFE-INPUT}"), "hook_input_invalid"},
		{"oversized", io.MultiReader(strings.NewReader(strings.Repeat("x", agentcontext.MaxLineBytes)), strings.NewReader("UNSAFE-INPUT")), "hook_input_limit"},
		{"normalized_limit", strings.NewReader(`{"hook_event_name":"SessionStart","opaque":"` + strings.Repeat("<", agentcontext.MaxLineBytes/6) + `"}`), "hook_input_limit"},
		{"reader", hookReadError{}, "hook_input_read_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hooks.jsonl")
			cmd := internalHookLogCmd()
			var stderr bytes.Buffer
			cmd.SetErr(&stderr)
			cmd.SetIn(tc.input)
			cmd.SetArgs([]string{"--file", path, "--capture", "basic"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("input failure aborted agent: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil || len(data) > 256 || !bytes.Contains(data, []byte(tc.code)) || strings.Contains(string(data)+stderr.String(), "UNSAFE-INPUT") {
				t.Fatalf("unsafe/missing diagnostic: %q %q %v", data, stderr.String(), err)
			}
		})
	}
	cmd := internalHookLogCmd()
	cmd.SetArgs([]string{"--file", filepath.Join(t.TempDir(), "missing", "hooks.jsonl")})
	cmd.SetIn(strings.NewReader(`{"hook_event_name":"SessionStart","session_id":"s"}`))
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("write failure aborted agent: %v", err)
	}
}

func TestHookLogConcurrentAppendsAndLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.jsonl")
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf("{\"id\":%d,\"body\":%q}\n", i, strings.Repeat("payload", 20000)))
			errs <- appendHookLog(path, data, 4<<20)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) != 16 {
		t.Fatalf("lost hook writes: %d", len(lines))
	}
	for _, line := range lines {
		if !json.Valid(line) {
			t.Fatal("concurrent writes interleaved")
		}
	}
	limited := filepath.Join(t.TempDir(), "limited.jsonl")
	for i := 0; i < 20; i++ {
		if err := appendHookLog(limited, []byte(`{"hook_event_name":"SessionStart","session_id":"s"}`+"\n"), 256); err != nil {
			t.Fatal(err)
		}
	}
	data, err = os.ReadFile(limited)
	if err != nil || len(data) > 256 || bytes.Count(data, []byte("hook_log_limit")) != 1 {
		t.Fatalf("log limit did not stop repeated writes: %q %v", data, err)
	}
	p, err := agentcontext.Parse(context.Background(), bytes.NewReader(data), agentcontext.ParseOptions{Harness: "claude"})
	if err != nil || p.Coverage.Status != agentcontext.Partial || p.Coverage.Counts.Truncated == nil || *p.Coverage.Counts.Truncated != 1 {
		t.Fatalf("log limit not visible in coverage: %+v %v", p.Coverage, err)
	}
}

func TestStampHookTimestampPreservesNumbers(t *testing.T) {
	data := stampHookTS([]byte(`{"hook_event_name":"SessionStart","id":9007199254740993,"_ts":"original"}`))
	if !bytes.Contains(data, []byte("9007199254740993")) || !bytes.Contains(data, []byte("original")) {
		t.Fatalf("timestamp stamping changed evidence: %s", data)
	}
	if string(stampHookTS([]byte("null"))) != "null" {
		t.Fatal("null input changed")
	}
}
