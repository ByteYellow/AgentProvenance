package launch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type remoteFixture struct {
	route, config string
	paths         store.Paths
	server        daemon.Server
	requests      atomic.Int64
}

func newRemoteFixture(t *testing.T) *remoteFixture {
	t.Helper()
	return remoteFixtureWithPolicy(t, record.Options{AllowShell: true})
}

func remoteFixtureWithPolicy(t *testing.T, executionPolicy record.Options) *remoteFixture {
	t.Helper()
	x := &remoteFixture{}
	var err error
	x.paths, err = store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serverPaths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(serverPaths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	target := handoff.Target{ProducerID: "linux", InstanceID: "sandbox-b", Generation: "first"}
	x.server = daemon.Server{DB: db, Paths: serverPaths, AuthToken: "fixture-token",
		ExecutionCaller: handoff.Principal{ID: "router", ProducerID: "mac", Namespace: "user", AllowedTargets: []handoff.Target{target}}}
	x.server.Execution = &handoff.Executor{Ledger: handoff.Ledger{DB: db, Target: target}, Paths: serverPaths,
		Options: executionPolicy, PollInterval: time.Millisecond}
	stop, err := x.server.Execution.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiverPub, receiverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x.server.ExecutionDelivery = &handoff.DeliveryService{Ledger: x.server.Execution.Ledger, Paths: serverPaths,
		SignKey: key, ReceiverID: "mac-receiver", ReceiverKey: receiverPub}
	handler := x.server.Handler()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.requests.Add(1)
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(httpServer.Close)
	root := t.TempDir()
	for name, data := range map[string][]byte{"token": []byte("fixture-token"), "sign.key": []byte(hex.EncodeToString(receiverKey)), "executor.pub": []byte(hex.EncodeToString(pub))} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	execution := handoff.Config{Target: target}
	execution.Caller.PrincipalID, execution.Caller.ProducerID, execution.Caller.Namespace = "router", "mac", "user"
	if err := saveRouteJSON(filepath.Join(root, "execution.json"), execution, false); err != nil {
		t.Fatal(err)
	}
	workdir := filepath.Join(serverPaths.Workspaces, "native-command")
	if err := os.MkdirAll(workdir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := RemoteExecutionConfig{SchemaVersion: remoteRouteSchema, URL: httpServer.URL, TokenFile: "token",
		ExecutionConfig: "execution.json", Workdir: workdir, ReceiverID: "mac-receiver", SignKeyFile: "sign.key", PublicKeyFile: "executor.pub"}
	x.config = filepath.Join(root, "route.json")
	if err := saveRouteJSON(x.config, config, false); err != nil {
		t.Fatal(err)
	}
	policy, _ := agentcontext.NewCapturePolicy("detailed", nil)
	x.route, err = prepareRemoteRoute(Options{RemoteExecution: x.config, SelfExe: "/agent prov"}, x.paths, "run-native", policy)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func nativeBash(session, tool, command string) []byte {
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": session,
		"tool_use_id": tool, "tool_input": map[string]any{"command": command, "description": "Read input", "timeout": 30000},
		"producer_id": "model-supplied", "target": "untrusted-target"})
	return raw
}

func preparedCalls(t *testing.T, route string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(route), "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for _, path := range paths {
		if filepath.Base(path) != "route.json" && !strings.HasSuffix(path, "-admission.json") && !strings.HasSuffix(path, "-collection.json") {
			result = append(result, path)
		}
	}
	return result
}

func TestPrepareNativeClaudeRemoteIdentityAndRetry(t *testing.T) {
	x := newRemoteFixture(t)
	raw := nativeBash("native-session", "native-call", "printf 'total,42\\n'")
	output, err := PrepareClaudeRemoteCall(x.route, raw)
	if err != nil {
		t.Fatal(err)
	}
	decision := output["hookSpecificOutput"].(map[string]any)
	if _, found := decision["permissionDecision"]; found {
		t.Fatal("routing bypassed native permission checks")
	}
	input := decision["updatedInput"].(map[string]json.RawMessage)
	if string(input["description"]) != `"Read input"` || string(input["timeout"]) != "30000" {
		t.Fatalf("native parameters lost: %+v", input)
	}
	paths := preparedCalls(t, x.route)
	if len(paths) != 1 {
		t.Fatalf("prepared paths: %v", paths)
	}
	before, _ := os.ReadFile(paths[0])
	var prepared PreparedRemoteCall
	if err := json.Unmarshal(before, &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.Request.Source.SessionID != "native-session" || prepared.Request.Source.ToolCallID != "native-call" ||
		prepared.Request.Source.ProducerID != "mac" || prepared.Request.Target.InstanceID != "sandbox-b" {
		t.Fatalf("native or trusted identity changed: %+v", prepared)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := PrepareClaudeRemoteCall(x.route, raw); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	after, _ := os.ReadFile(paths[0])
	if !bytes.Equal(before, after) || x.requests.Load() != 0 {
		t.Fatal("preparation refreshed an identity or made a network request")
	}
	if _, err := PrepareClaudeRemoteCall(x.route, nativeBash("native-session", "native-call", "changed")); !errors.Is(err, handoff.ErrConflict) {
		t.Fatalf("same native call accepted changed command: %v", err)
	}
	if _, err := PrepareClaudeRemoteCall(x.route, nativeBash("other-session", "native-call", "printf 'total,42\\n'")); err != nil {
		t.Fatal(err)
	}
	if len(preparedCalls(t, x.route)) != 2 {
		t.Fatal("native sessions with the same call ID merged")
	}
}

func TestNativeRemotePreparationDeniesUnsupportedInput(t *testing.T) {
	x := newRemoteFixture(t)
	for _, raw := range [][]byte{
		nativeBash("", "call", "echo a"), nativeBash("session", "", "echo a"), []byte(`{`),
		[]byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"s","tool_use_id":"t","tool_input":{"command":"sleep 1","run_in_background":true}}`),
	} {
		result, err := RemoteHookOutput(x.route, raw)
		if err != nil || !bytes.Contains(result, []byte(`"permissionDecision":"deny"`)) {
			t.Fatalf("invalid call did not fail closed: %s %v", result, err)
		}
	}
	other, err := PrepareClaudeRemoteCall(x.route, []byte(`{"hook_event_name":"PreToolUse","tool_name":"Read"}`))
	if err != nil || len(other) != 0 || x.requests.Load() != 0 || len(preparedCalls(t, x.route)) != 0 {
		t.Fatalf("non-Bash or denied calls submitted work: %+v %v", other, err)
	}
}

func TestNativeRemoteCommandQuotedWithoutLocalExecution(t *testing.T) {
	x := newRemoteFixture(t)
	route, _ := ReadRemoteRoute(x.route)
	stub := filepath.Join(t.TempDir(), "argument printer")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	route.SelfExe = stub
	if err := saveRouteJSON(x.route, route, true); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	native := "printf 'quoted'; touch " + shQuote(marker) + "; echo $(uname)"
	output, err := PrepareClaudeRemoteCall(x.route, nativeBash("s", "t", native))
	if err != nil {
		t.Fatal(err)
	}
	input := output["hookSpecificOutput"].(map[string]any)["updatedInput"].(map[string]json.RawMessage)
	var command string
	if err := json.Unmarshal(input["command"], &command); err != nil {
		t.Fatal(err)
	}
	printed, err := exec.Command("/bin/sh", "-c", command).Output()
	if err != nil || !strings.HasSuffix(string(printed), "--native-command\n"+native+"\n") {
		t.Fatalf("original command changed during shell quoting: %s %v", printed, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("command executed on the caller during preparation")
	}
}

func TestNativeRemoteCommandSignedResultAndReplay(t *testing.T) {
	x := newRemoteFixture(t)
	route, _ := ReadRemoteRoute(x.route)
	route.Config.FileDiff = true
	if err := saveRouteJSON(x.route, route, true); err != nil {
		t.Fatal(err)
	}
	command := "printf 'total,42\\n' > result.csv; cat result.csv; printf 'diagnostic\\n' >&2; exit 7"
	if _, err := PrepareClaudeRemoteCall(x.route, nativeBash("s", "t", command)); err != nil {
		t.Fatal(err)
	}
	request := preparedCalls(t, x.route)[0]
	for range 2 {
		var stdout, stderr bytes.Buffer
		exit, err := ExecuteRemoteCall(context.Background(), x.route, request, command, &stdout, &stderr)
		if err != nil || exit != 7 || stdout.String() != "total,42\n" || !strings.Contains(stderr.String(), "diagnostic\n") ||
			!strings.Contains(stderr.String(), "delivery=acknowledged") {
			t.Fatalf("remote result exit=%d err=%v stdout=%q stderr=%q", exit, err, stdout.String(), stderr.String())
		}
	}
	for _, table := range []string{"execution_attempts", "tool_calls"} {
		var count int
		if err := x.server.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("replay duplicated %s: %d %v", table, count, err)
		}
	}
	var admission daemon.ExecutionAdmission
	if err := readRouteJSON(strings.TrimSuffix(request, ".json")+"-admission.json", &admission, 2<<20); err != nil {
		t.Fatal(err)
	}
	if admission.Attempt.Request.Source.SessionID != "s" || admission.Attempt.Request.Source.ToolCallID != "t" {
		t.Fatal("saved admission lost native source")
	}
	db, err := store.Open(x.paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var admissionRef string
	if err := db.QueryRow(`SELECT hash FROM provenance_objects WHERE run_id=? AND object_type='execution_source_admission'`, route.RunID).Scan(&admissionRef); err != nil {
		t.Fatalf("native source admission is missing from evidence storage: %v", err)
	}
	var source struct {
		Identity handoff.ExecutionIdentity `json:"identity"`
	}
	if err := provenance.ReadObjectPayload(db, route.RunID, admissionRef, &source); err != nil || source.Identity != handoff.IdentityOf(admission.Attempt) {
		t.Fatalf("source admission identity: %+v %v", source, err)
	}
	var admissionCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='execution_source_admission'`, route.RunID).Scan(&admissionCount); err != nil || admissionCount != 1 {
		t.Fatalf("replayed admission was duplicated: %d %v", admissionCount, err)
	}
	var proofCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='execution_delivery_evidence'`, admission.Attempt.LocalRunID).Scan(&proofCount); err != nil || proofCount != 1 {
		t.Fatalf("native delivery link was not saved exactly once: %d %v", proofCount, err)
	}
	report, err := x.server.Execution.Ledger.Report(context.Background(), x.server.ExecutionCaller, admission.Attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	files := report.Checkpoint.Result.ArtifactCapture.Files
	if len(files) != 1 || files[0].Path != "result.csv" {
		t.Fatalf("changed artifact missing: %+v", files)
	}
	page, err := provenance.ReadTextContentPage(db, admission.Attempt.LocalRunID, files[0].ContentRef, 0, 1024)
	if err != nil || page.Content != "total,42\n" {
		t.Fatalf("signed artifact body lost: %+v %v", page, err)
	}
}

func TestNativeRemoteCommandCancellationRequestsStop(t *testing.T) {
	x := newRemoteFixture(t)
	raw := nativeBash("s", "slow", "sleep 20")
	if _, err := PrepareClaudeRemoteCall(x.route, raw); err != nil {
		t.Fatal(err)
	}
	request := preparedCalls(t, x.route)[0]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := ExecuteRemoteCall(ctx, x.route, request, "sleep 20", io.Discard, io.Discard)
		done <- err
	}()
	started := time.Now().Add(5 * time.Second)
	for time.Now().Before(started) {
		var count int
		if err := x.server.DB.QueryRow(`SELECT COUNT(*) FROM execution_attempts WHERE execution_state='running'`).Scan(&count); err == nil && count == 1 {
			cancel()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ctx.Err() == nil {
		cancel()
		t.Fatalf("execution never started: %v", <-done)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not reported: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var stopped int
		if err := x.server.DB.QueryRow(`SELECT COUNT(*) FROM execution_stop_requests`).Scan(&stopped); err == nil && stopped == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("native tool cancellation did not persist a stop request")
}

func TestNativeRemoteCommandKeepsExecutorShellPolicy(t *testing.T) {
	x := remoteFixtureWithPolicy(t, record.Options{})
	if _, err := PrepareClaudeRemoteCall(x.route, nativeBash("s", "denied", "echo should-not-run")); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	exit, err := ExecuteRemoteCall(context.Background(), x.route, preparedCalls(t, x.route)[0], "echo should-not-run", &output, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "refusing shell interpreter") || exit == 0 || output.Len() != 0 {
		t.Fatalf("executor shell policy bypassed: exit=%d error=%v output=%q", exit, err, output.String())
	}
}

func TestRemoteRouteConfigAndOverlay(t *testing.T) {
	x := newRemoteFixture(t)
	route, _ := ReadRemoteRoute(x.route)
	for _, endpoint := range []string{"http://evil.example", "http://localhost:80", "https://user:pass@example.test", "https://example.test/path", "https://example.test?secret=1"} {
		bad := route.Config
		bad.URL = endpoint
		if err := bad.validate(); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	basic, _ := agentcontext.NewCapturePolicy("basic", nil)
	if _, err := prepareRemoteRoute(Options{RemoteExecution: x.config, SelfExe: "/agentprov"}, x.paths, "basic", basic); err == nil {
		t.Fatal("omitted tool outputs silently enabled")
	}
	keep := true
	basic, _ = agentcontext.NewCapturePolicy("basic", &keep)
	if _, err := prepareRemoteRoute(Options{RemoteExecution: x.config, SelfExe: "/agentprov"}, x.paths, "basic-outputs", basic); err != nil {
		t.Fatal(err)
	}
	argv, cleanup, err := injectClaudeCode([]string{"claude", "-p", "task"}, "/agent prov", filepath.Join(x.paths.Logs, "route-hooks.jsonl"), x.paths, route.Policy)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := addRemoteClaudeHooks(argv[2], "/agent prov", x.route); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argv[2])
	if err != nil || !bytes.Contains(raw, []byte("internal hook-log")) || !bytes.Contains(raw, []byte("internal remote-hook")) ||
		bytes.Contains(raw, []byte("fixture-token")) || !bytes.Contains(raw, []byte("|| exit 2")) ||
		!bytes.Contains(raw, []byte(`"onFailure": "block"`)) {
		t.Fatalf("overlay lost capture, leaked credentials or failed open: %s %v", raw, err)
	}
	context, err := PrepareClaudeRemoteCall(x.route, []byte(`{"hook_event_name":"SessionStart","session_id":"s"}`))
	if err != nil || !strings.Contains(fmt.Sprint(context), route.Config.Workdir) {
		t.Fatalf("remote workspace not explained to the harness: %v %v", context, err)
	}
}

func TestRemoteClaudeVersionRequiresBlockingHooks(t *testing.T) {
	for _, test := range []struct {
		version string
		ok      bool
	}{{"2.1.294 (Claude Code)", false}, {"2.1.295 (Claude Code)", true}, {"2.1.304 (Claude Code)", true},
		{"2.2.0 (Claude Code)", true}, {"unknown", false}, {"2.1.300-invalid", false}} {
		t.Run(test.version, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "claude")
			if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' "+shQuote(test.version)+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := checkRemoteClaudeVersion(path); (err == nil) != test.ok {
				t.Fatalf("version result: %v", err)
			}
		})
	}
}

func TestRemoteClaudeModeRequiresForegroundHooks(t *testing.T) {
	t.Setenv("CLAUDE_CODE_SIMPLE", "")
	t.Setenv("CLAUDE_CODE_SAFE_MODE", "")
	for _, flag := range []string{"--bare", "--safe-mode", "--bg", "--background", "--cloud=task", "--desktop", "--environment=env"} {
		if err := checkRemoteClaudeMode([]string{"claude", flag, "task"}); err == nil {
			t.Fatalf("unsupported remote lifecycle accepted: %s", flag)
		}
	}
	if err := checkRemoteClaudeMode([]string{"claude", "-p", "task"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CODE_SIMPLE", "1")
	if err := checkRemoteClaudeMode([]string{"claude", "-p", "task"}); err == nil {
		t.Fatal("hook-disabled environment accepted")
	}
}

func TestRemoteClaudeHooksMustActuallyInitialize(t *testing.T) {
	x := newRemoteFixture(t)
	route, _ := ReadRemoteRoute(x.route)
	client := filepath.Join(t.TempDir(), "claude")
	argv, cleanup, err := injectClaudeCode([]string{client, "-p", "task"}, "/agentprov", filepath.Join(x.paths.Logs, "probe-hooks.jsonl"), x.paths, route.Policy)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := addRemoteClaudeHooks(argv[2], "/agentprov", x.route); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(client, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkRemoteClaudeHooks(argv, Options{}, x.route); err == nil {
		t.Fatal("a successful client exit was treated as proof that hooks ran")
	}
	ready, _ := json.Marshal(map[string]string{"run_id": route.RunID, "session_id": "native-probe"})
	script := "#!/bin/sh\ntest \"$1\" = --init-only || exit 1\nprintf '%s\\n' " + shQuote(string(ready)) + " > " + shQuote(filepath.Join(filepath.Dir(x.route), "hook-ready")) + "\n"
	if err := os.WriteFile(client, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkRemoteClaudeHooks(argv, Options{}, x.route); err != nil {
		t.Fatal(err)
	}
	if len(preparedCalls(t, x.route)) != 0 || x.requests.Load() != 0 {
		t.Fatal("hook initialization prepared or submitted a command")
	}
}
