package launch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/klauspost/compress/zstd"
)

func contextService(t *testing.T) agentcontext.Service {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return agentcontext.Service{DB: db, Paths: paths}
}

func writeFixture(t *testing.T, path, input string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
}

func codexSession(id, cwd, timestamp string) string {
	header, _ := json.Marshal(map[string]any{"type": "session_meta", "timestamp": timestamp,
		"payload": map[string]any{"id": id, "cwd": cwd}})
	return string(header) + "\n"
}

func sourceReport(t *testing.T, o agentcontext.Overview, channel string) agentcontext.Coverage {
	t.Helper()
	for _, c := range o.Coverage {
		if c.Source.Channel == channel {
			return c
		}
	}
	t.Fatalf("missing %s report: %+v", channel, o.Coverage)
	return agentcontext.Coverage{}
}

func TestCaptureConcurrentSessionsRemainUnbound(t *testing.T) {
	ctx, svc := context.Background(), contextService(t)
	dir, workdir := t.TempDir(), t.TempDir()
	c, err := prepareContext(ctx, Options{ContextDir: dir, Workdir: workdir}, detectRecipe([]string{"codex"}))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Second)
	for _, id := range []string{"one", "two"} {
		writeFixture(t, filepath.Join(dir, "rollout-"+id+".jsonl"), codexSession(id, workdir, time.Now().Format(time.RFC3339Nano)))
	}
	o, err := c.finish(ctx, svc, "run", "", start, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status := sourceReport(t, o, "discovery")
	if status.Status != agentcontext.Ambiguous || *status.Counts.Discovered != 2 || *status.Counts.Matched != 0 || status.Counts.Read != nil {
		t.Fatalf("selection: %+v", status)
	}
	p, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run"})
	if err != nil || len(p.Entries) != 0 {
		t.Fatalf("ambiguous activity bound: %+v %v", p, err)
	}
}

func TestCaptureResumeUsesVerifiedPrefix(t *testing.T) {
	ctx, svc := context.Background(), contextService(t)
	dir, workdir := t.TempDir(), t.TempDir()
	path := filepath.Join(dir, "rollout-old.jsonl")
	old := codexSession("native-id", workdir, "2020-01-01T00:00:00Z") + `{"type":"response_item","payload":{"type":"message","role":"user","content":"old task"}}` + "\n"
	writeFixture(t, path, old)
	c, err := prepareContext(ctx, Options{ContextFile: path, ContextSession: "native-id", Workdir: workdir}, detectRecipe([]string{"codex"}))
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, path, old+`{"type":"response_item","payload":{"type":"message","role":"user","content":"new task"}}`+"\n")
	o, err := c.finish(ctx, svc, "run", "", time.Now().Add(-time.Second), time.Now())
	if err != nil || o.Messages == nil || *o.Messages != 2 {
		t.Fatalf("resume: %+v %v", o, err)
	}
	p, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run", Kind: "message"})
	if err != nil || len(p.Entries) != 2 || p.Entries[0].ExecutionScope != agentcontext.PriorContext || p.Entries[1].Sequence != 3 || p.Entries[1].ExecutionScope != agentcontext.CurrentExecution {
		t.Fatalf("resume entries: %+v %v", p, err)
	}
	body, err := provenance.ReadTextContentPage(svc.DB, "run", p.Entries[1].Content.Ref, 0, 100)
	if err != nil || body.Content != "new task" {
		t.Fatalf("old activity imported: %+v %v", body, err)
	}
	prior, err := provenance.ReadTextContentPage(svc.DB, "run", p.Entries[0].Content.Ref, 0, 100)
	if err != nil || prior.Content != "old task" {
		t.Fatalf("historical context lost: %+v %v", prior, err)
	}
	writeFixture(t, path, strings.ReplaceAll(old, "old task", "changed task"))
	bad, err := c.finish(ctx, svc, "other-run", "", time.Now().Add(-time.Second), time.Now())
	if err != nil || sourceReport(t, bad, "discovery").Status != agentcontext.Ambiguous {
		t.Fatalf("replaced prefix accepted: %+v %v", bad, err)
	}
}

func TestCaptureClaudeHookAnchorAndChild(t *testing.T) {
	ctx, svc := context.Background(), contextService(t)
	dir, workdir := t.TempDir(), t.TempDir()
	c, err := prepareContext(ctx, Options{ContextDir: dir, Workdir: workdir}, detectRecipe([]string{"claude"}))
	if err != nil {
		t.Fatal(err)
	}
	mainPath, childPath := filepath.Join(dir, "session.jsonl"), filepath.Join(dir, "subagents", "agent-child.jsonl")
	entry := func(agent string) string {
		raw, _ := json.Marshal(map[string]any{"type": "user", "sessionId": "s", "agentId": agent, "cwd": workdir,
			"timestamp": time.Now().Format(time.RFC3339Nano), "message": map[string]any{"role": "user", "content": "task"}})
		return string(raw) + "\n"
	}
	writeFixture(t, mainPath, entry(""))
	writeFixture(t, childPath, entry("child"))
	hook, _ := json.Marshal(map[string]any{"session_id": "s", "hook_event_name": "SubagentStart", "agent_id": "child",
		"transcript_path": mainPath, "agent_transcript_path": childPath})
	hookPath := filepath.Join(t.TempDir(), "run-hook.jsonl")
	writeFixture(t, hookPath, string(hook)+"\n")
	o, err := c.finish(ctx, svc, "run", hookPath, time.Now().Add(-time.Second), time.Now())
	if err != nil || o.Messages == nil || *o.Messages != 2 {
		t.Fatalf("capture: %+v %v", o, err)
	}
	if d := sourceReport(t, o, "discovery"); d.Status != agentcontext.OK || *d.Counts.Matched != 2 {
		t.Fatalf("selection: %+v", d)
	}
	p, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run", Kind: "message"})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range p.Entries {
		if e.Source.Binding != "exact" || strings.Contains(strings.Join(e.Source.BindingEvidence, " "), "user_selected") {
			t.Fatalf("wrong binding provenance: %+v", e.Source)
		}
	}
}

func TestContextOptionsAndDefaultLocations(t *testing.T) {
	for env, harness := range map[string]string{"CODEX_HOME": "codex", "CLAUDE_CONFIG_DIR": "claude", "DSH_HOME": "deepseek"} {
		dir := t.TempDir()
		t.Setenv(env, dir)
		if root := contextRoot(harness); !strings.HasPrefix(root, dir+string(os.PathSeparator)) {
			t.Fatalf("%s ignored: %s", env, root)
		}
	}
	for _, options := range []Options{
		{NoContext: true, ContextSession: "s"},
		{ContextFile: "a", ContextDir: "b"},
		{ContextHarness: "unsupported"},
	} {
		if _, err := prepareContext(context.Background(), options, detectRecipe([]string{"codex"})); err == nil {
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
	if _, err := prepareContext(context.Background(), Options{ContextDir: t.TempDir()}, detectRecipe([]string{"sh"})); err == nil {
		t.Fatal("unknown wrapper silently assigned a format")
	}
	for _, opts := range []Options{{Command: []string{"claude"}, NoContext: true, Sensor: "off"},
		{Command: []string{"claude"}, ContextHarness: "codex", Sensor: "off"}} {
		for _, check := range Preflight(opts).Checks {
			if check.Name == "Claude hooks" && check.Status != CheckSkip {
				t.Fatalf("preflight advertised disabled hooks: %+v", check)
			}
		}
	}
}

func TestCaptureAbsentAndDisabledHaveDistinctCoverage(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		svc := contextService(t)
		c := contextCapture{harness: "codex", root: t.TempDir(), disabled: disabled}
		var err error
		c.before, err = agentcontext.Discover(context.Background(), agentcontext.DiscoverOptions{Harness: c.harness, Root: c.root})
		if err != nil {
			t.Fatal(err)
		}
		o, err := c.finish(context.Background(), svc, "run", "", time.Now(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		report := sourceReport(t, o, "discovery")
		if disabled {
			if report.Status != agentcontext.Disabled || report.Counts.Discovered != nil {
				t.Fatalf("disabled claimed a scan: %+v", report)
			}
		} else if report.Status != agentcontext.NoInput || report.Counts.Discovered == nil || *report.Counts.Discovered != 0 {
			t.Fatalf("empty discovery: %+v", report)
		}
		var stderr bytes.Buffer
		r := Report{}
		contextProblem(svc.DB, svc.Paths, "run", "context_graph_projection_failed", &r, &stderr)
		if len(r.ContextIssues) != 1 || r.AgentContext == nil || sourceReport(t, *r.AgentContext, "processing").Status != agentcontext.Failed {
			t.Fatalf("processing failure not visible: %+v / %s", r, stderr.String())
		}
	}
}

func TestCaptureSelectedSourceLimitIsReported(t *testing.T) {
	ctx, svc := context.Background(), contextService(t)
	dir, workdir := t.TempDir(), t.TempDir()
	c, err := prepareContext(ctx, Options{ContextDir: dir, Workdir: workdir}, detectRecipe([]string{"codex"}))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Second)
	writeFixture(t, filepath.Join(dir, "rollout-main.jsonl"), codexSession("main", workdir, time.Now().Format(time.RFC3339Nano)))
	for i := 0; i < maxContextSources; i++ {
		data, _ := json.Marshal(map[string]any{"type": "session_meta", "timestamp": time.Now().Format(time.RFC3339Nano),
			"payload": map[string]any{"id": fmt.Sprintf("child-%03d", i), "source": map[string]any{"subagent": map[string]any{"thread_spawn": map[string]any{"parent_thread_id": "main"}}}}})
		writeFixture(t, filepath.Join(dir, fmt.Sprintf("rollout-%03d.jsonl", i)), string(data)+"\n")
	}
	o, err := c.finish(ctx, svc, "run", "", start, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := sourceReport(t, o, "discovery")
	if r.Status != agentcontext.Partial || r.Counts.Matched == nil || *r.Counts.Matched != maxContextSources {
		t.Fatalf("source cap: %+v", r)
	}
	for _, issue := range r.Issues {
		if issue.Code == "selected_source_limit" {
			return
		}
	}
	t.Fatal("source cap silently omitted sources")
}

func TestCaptureMissingHookLogIsReported(t *testing.T) {
	ctx, svc := context.Background(), contextService(t)
	c, err := prepareContext(ctx, Options{ContextDir: t.TempDir()}, detectRecipe([]string{"claude"}))
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.finish(ctx, svc, "run", filepath.Join(t.TempDir(), "absent.jsonl"), time.Now(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := sourceReport(t, o, "hooks")
	if r.Status != agentcontext.NoInput || r.Counts.Read != nil || r.Issues[0].Code != "hook_log_not_found" {
		t.Fatalf("missing hook input hidden: %+v", r)
	}
}

// A subprocess exercises the real record/launch path without an external model
// or harness dependency. Real DeepSeek acceptance remains a separate VM test.
func TestLaunchContextHelper(t *testing.T) {
	mode := os.Getenv("AGENTPROV_TEST_CONTEXT_HELPER")
	if mode == "" {
		return
	}
	dir, workdir := os.Getenv("AGENTPROV_TEST_CONTEXT_DIR"), os.Getenv("AGENTPROV_TEST_CONTEXT_CWD")
	if mode == "deepseek" {
		header, _ := json.Marshal(map[string]any{"type": "session", "version": 4, "id": "dsh-real-format", "cwd": workdir, "createdAt": time.Now().UnixMilli()})
		events := `{"type":"tool/call","seq":0,"time":1790548592000,"data":{"callId":"c","name":"bash","arguments":"{\"command\":\"true\"}"}}
{"type":"tool/result","seq":1,"time":1790548592001,"data":{"message":{"role":"tool","toolCallId":"c","content":[{"type":"text","text":"completed"}]}}}
`
		enc, err := zstd.NewWriter(nil)
		if err != nil {
			t.Fatal(err)
		}
		data := enc.EncodeAll(append(header, '\n'), nil)
		data = append(data, enc.EncodeAll([]byte(events), nil)...)
		enc.Close()
		if err := os.WriteFile(filepath.Join(dir, "session.v4.jsonl.zstd"), data, 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		data := codexSession("native-session", workdir, time.Now().Format(time.RFC3339Nano)) + `{"type":"response_item","payload":{"type":"function_call","call_id":"c","name":"exec_command","arguments":"{\"cmd\":\"true\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"completed"}}
`
		writeFixture(t, filepath.Join(dir, "rollout-native.jsonl"), data)
	}
	fmt.Println("AGENT_OUTPUT")
	os.Exit(0)
}

func TestLaunchCapturesNativeContextAndPortableBundle(t *testing.T) {
	for _, harness := range []string{"codex", "deepseek"} {
		t.Run(harness, func(t *testing.T) {
			dir, workdir := t.TempDir(), t.TempDir()
			t.Setenv("AGENTPROV_TEST_CONTEXT_HELPER", harness)
			t.Setenv("AGENTPROV_TEST_CONTEXT_DIR", dir)
			t.Setenv("AGENTPROV_TEST_CONTEXT_CWD", workdir)
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			r, err := Run(Options{DataDir: t.TempDir(), Command: []string{exe, "-test.run=^TestLaunchContextHelper$"}, Workdir: workdir,
				ContextHarness: harness, ContextDir: dir, Sensor: "off", JSON: true, Stdout: &stdout, Stderr: &stderr})
			if err != nil || r.ExitCode != 0 || r.HooksIngested != 1 || len(r.ContextIssues) != 0 {
				t.Fatalf("launch: %+v %v\n%s", r, err, stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "AGENT_OUTPUT") {
				t.Fatalf("machine output contaminated: %q / %q", stdout.String(), stderr.String())
			}
			if r.AgentContext == nil || r.AgentContext.ToolCalls == nil || *r.AgentContext.ToolCalls != 1 || *r.AgentContext.ToolResults != 1 {
				t.Fatalf("missing common context: %+v", r.AgentContext)
			}
			if r.ArtifactCapture == nil || r.ArtifactCapture.Status != "disabled" || r.ArtifactCapture.Candidates != nil || r.ArtifactCapture.Ref == "" {
				t.Fatalf("default launch unexpectedly enabled file capture: %+v", r.ArtifactCapture)
			}
			if c := sourceReport(t, *r.AgentContext, "discovery"); c.Status != agentcontext.OK {
				t.Fatalf("discovery failed: %+v", c)
			}
			if r.RuntimeCorrelation == nil || r.RuntimeCorrelation.Ref == "" || r.RuntimeCorrelation.Method != "agentprov.command_time_process/v2" {
				t.Fatalf("missing runtime correlation diagnostic: %+v", r.RuntimeCorrelation)
			}
			if r.RuntimeCapture == nil || r.RuntimeCapture.Ref == "" || r.RuntimeCapture.Status != "disabled" || r.RuntimeCapture.RunDroppedEvents != nil {
				t.Fatalf("missing explicit capture state: %+v", r.RuntimeCapture)
			}
			fresh := contextService(t)
			if _, err := (forensics.Service{DB: fresh.DB, Paths: fresh.Paths}).ImportBundle(r.BundlePath); err != nil {
				t.Fatalf("offline bundle: %v", err)
			}
			o, err := fresh.Overview(context.Background(), r.RunID)
			if err != nil || o.ToolCalls == nil || *o.ToolCalls != 1 {
				t.Fatalf("lost portable context: %+v %v", o, err)
			}
			if o.RuntimeCoverage.Capture.Status != "disabled" || o.RuntimeCoverage.Capture.Ref != r.RuntimeCapture.Ref || o.RuntimeCoverage.Correlation.Summary.RuntimeEvents == 0 {
				t.Fatalf("lost capture state or wrapper events: %+v", o.RuntimeCoverage)
			}
			c := sourceReport(t, o, "runtime_correlation")
			if string(c.Status) != r.RuntimeCorrelation.Status || len(c.Source.BindingEvidence) != 1 || c.Source.BindingEvidence[0] != r.RuntimeCorrelation.Ref {
				t.Fatalf("correlation coverage not portable: %+v", c)
			}
			var reports int
			if err := fresh.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='runtime_correlation' AND hash=?`, r.RunID, r.RuntimeCorrelation.Ref).Scan(&reports); err != nil || reports != 1 {
				t.Fatalf("report object omitted: count=%d %v", reports, err)
			}
			v, err := provenance.Verify(fresh.DB, r.RunID)
			if err != nil || v.ErrorCount != 0 {
				t.Fatalf("verify imported: %+v %v", v, err)
			}
		})
	}
}

func TestLaunchFileDiffSavesPortableBody(t *testing.T) {
	workdir := t.TempDir()
	var stdout, stderr bytes.Buffer
	r, err := Run(Options{DataDir: t.TempDir(), Workdir: workdir, Command: []string{"sh", "-c", "printf 'saved from launch\n' > report.txt"},
		FileDiff: true, NoContext: true, Sensor: "off", JSON: true, Stdout: &stdout, Stderr: &stderr})
	if err != nil || r.ExitCode != 0 || r.ArtifactCapture == nil {
		t.Fatalf("launch file capture: %+v %v\n%s", r, err, stderr.String())
	}
	report := r.ArtifactCapture
	if report.Status != "ok" || report.Candidates == nil || *report.Candidates != 1 || report.Stored != 1 || len(report.Files) != 1 || report.Ref == "" {
		t.Fatalf("file capture report: %+v", report)
	}
	fresh := contextService(t)
	info, err := (forensics.Service{DB: fresh.DB, Paths: fresh.Paths}).ImportBundle(r.BundlePath)
	if err != nil || info.Omitted != 0 {
		t.Fatalf("offline import: %+v %v", info, err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "report.txt"), []byte("changed after capture"), 0600); err != nil {
		t.Fatal(err)
	}
	body, err := provenance.ReadTextContentPage(fresh.DB, r.RunID, report.Files[0].ContentRef, 0, 65536)
	if err != nil || body.Content != "saved from launch\n" {
		t.Fatalf("launch did not preserve saved body: %+v %v", body, err)
	}
	v, err := provenance.Verify(fresh.DB, r.RunID)
	if err != nil || v.ErrorCount != 0 {
		t.Fatalf("verify imported: %+v %v", v, err)
	}
}
