package agentcontext

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func notebookHeader(kernel string) map[string]any {
	return map[string]any{"type": "notebook_session", "schema_version": "agentprovenance.jupyter_capture/v1",
		"producer_id": "lab", "namespace": "team", "instance_id": "vm", "generation": "g1",
		"notebook_id": "analysis", "kernel_id": "python", "kernel_session_id": kernel,
		"jupyter_client_version": "8.10.0", "timestamp": "2026-11-14T10:00:00Z"}
}

func notebookMessage(channel, direction, session, id, typ, parentSession, parentID string, content any) map[string]any {
	parent := map[string]any{}
	if parentID != "" {
		parent = map[string]any{"session": parentSession, "msg_id": parentID, "msg_type": "execute_request"}
	}
	return map[string]any{"type": "notebook_message", "schema_version": "agentprovenance.jupyter_capture/v1",
		"channel": channel, "direction": direction, "observed_at": "2026-11-14T10:00:01Z",
		"message": map[string]any{"header": map[string]any{"session": session, "msg_id": id,
			"msg_type": typ, "date": "2026-11-14T10:00:00Z", "version": "5.3"},
			"parent_header": parent, "content": content, "metadata": map[string]any{}}}
}

func parseNotebook(t *testing.T, values ...map[string]any) Parsed {
	t.Helper()
	var b strings.Builder
	for _, v := range values {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	p, err := Parse(context.Background(), strings.NewReader(b.String()), ParseOptions{Harness: "jupyter", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNotebookNativeRequestScope(t *testing.T) {
	request := func(client string) map[string]any {
		return notebookMessage("shell", "send", client, "same-id", "execute_request", "", "", map[string]any{"code": "print(42)"})
	}
	output := func(id, client string) map[string]any {
		return notebookMessage("iopub", "receive", "kernel-1", id, "stream", client, "same-id", map[string]any{"name": "stdout", "text": "42\n"})
	}
	p := parseNotebook(t, notebookHeader("kernel-1"), request("client-a"), request("client-b"), output("out-b", "client-b"), output("late-a", "client-a"))
	if p.Coverage.Status != OK || len(p.Records) != 5 {
		t.Fatalf("unexpected capture: %+v", p)
	}
	a, b := p.Records[1].ToolCallID, p.Records[2].ToolCallID
	if a == "" || a == b || p.Records[3].ToolCallID != b || p.Records[4].ToolCallID != a {
		t.Fatalf("client request identities or late output confused: %+v", p.Records)
	}
	restarted := parseNotebook(t, notebookHeader("kernel-2"), request("client-a"))
	if restarted.Source.SessionID == p.Source.SessionID || restarted.Records[1].ToolCallID == a {
		t.Fatal("kernel restart reused execution identity")
	}
}

func TestNotebookIdentityAndMissingParent(t *testing.T) {
	output := notebookMessage("iopub", "receive", "kernel-1", "out", "stream", "", "", map[string]any{"text": "background"})
	p := parseNotebook(t, notebookHeader("kernel-1"), output)
	if p.Coverage.Status != Partial || p.Records[1].ToolCallID != "" || p.Records[1].Notebook.Association != "kernel_session" {
		t.Fatalf("parentless output was attributed: %+v", p)
	}
	for _, field := range []string{"producer_id", "namespace", "instance_id", "generation", "kernel_id", "kernel_session_id"} {
		t.Run(field, func(t *testing.T) {
			header := notebookHeader("kernel-1")
			header[field] = "another"
			q := parseNotebook(t, header)
			if p.Source.SessionID == q.Source.SessionID {
				t.Fatal("unqualified notebook source")
			}
		})
	}
	changed := notebookMessage("iopub", "receive", "restarted", "out", "stream", "client", "call", map[string]any{"text": "new"})
	p = parseNotebook(t, notebookHeader("kernel-1"), changed)
	if p.Coverage.Status != Ambiguous || len(p.Records) != 0 {
		t.Fatalf("changed kernel silently accepted: %+v", p)
	}
	header := notebookHeader("kernel-1")
	delete(header, "generation")
	p = parseNotebook(t, header)
	if p.Coverage.Status != Failed || len(p.Records) != 0 {
		t.Fatalf("missing lifecycle identity accepted: %+v", p)
	}
}

func TestNotebookRetentionKeepsNativeIdentity(t *testing.T) {
	call := notebookMessage("shell", "send", "client", "request", "execute_request", "", "", map[string]any{"code": "print('hello')"})
	out := notebookMessage("iopub", "receive", "kernel", "out", "stream", "client", "request", map[string]any{"text": "NOTEBOOK_OUTPUT_BODY"})
	p := parseNotebook(t, notebookHeader("kernel"), call, out)
	var previous []Entry
	for _, preset := range []string{"basic", "detailed"} {
		svc := testService(t)
		policy, _ := NewCapturePolicy(preset, nil)
		svc.CapturePolicy = &policy
		for i := 0; i < 2; i++ {
			result, err := svc.Save(context.Background(), "run", p.Source, p.Records, p.Coverage)
			if err != nil || i == 0 && result.Stored != 3 || i == 1 && result.Duplicates != 3 {
				t.Fatalf("save %s/%d: %+v %v", preset, i, result, err)
			}
		}
		page, err := svc.Entries(context.Background(), PageOptions{RunID: "run"})
		if err != nil || len(page.Entries) != 3 {
			t.Fatalf("entries: %+v %v", page, err)
		}
		for i, e := range page.Entries {
			if !reflect.DeepEqual(e.Source.Notebook, p.Source.Notebook) ||
				!reflect.DeepEqual(e.Notebook, p.Records[i].Notebook) {
				t.Fatal("native identity lost on save")
			}
			if previous != nil && (e.ToolCallID != previous[i].ToolCallID || !reflect.DeepEqual(e.Notebook, previous[i].Notebook)) {
				t.Fatal("retention changed association")
			}
		}
		if preset == "basic" {
			if page.Entries[2].Content.State != "omitted" || page.Entries[2].RawContent.State != "omitted" {
				t.Fatal("basic retained output")
			}
		} else {
			body, err := provenance.ReadTextContentPage(svc.DB, "run", page.Entries[2].Content.Ref, 0, 4096)
			if err != nil || !strings.Contains(body.Content, "NOTEBOOK_OUTPUT_BODY") || page.Entries[2].RawContent.Reason != "notebook_protocol_projection" {
				t.Fatalf("detailed output: %+v %v", body, err)
			}
		}
		previous = page.Entries
	}
}

func TestNotebookRichOutputHasExplicitOmissions(t *testing.T) {
	out := notebookMessage("iopub", "receive", "kernel", "out", "display_data", "client", "request", map[string]any{
		"data": map[string]any{"text/html": "<script>neverRun()</script>", "text/plain": "chart",
			"image/png": "PNG_BODY_NOT_RETAINED", "image/svg+xml": "SVG_BODY_NOT_RETAINED"}})
	out["message"].(map[string]any)["buffers"] = []string{"BUFFER_NOT_RETAINED"}
	p := parseNotebook(t, notebookHeader("kernel"), out)
	if p.Coverage.Status != Partial || len(p.Records[1].Notebook.OmittedContent) != 3 {
		t.Fatalf("missing omission inventory: %+v", p)
	}
	r := p.Records[1]
	if strings.Contains(*r.Body, "NOT_RETAINED") || strings.Contains(*r.RawBody, "NOT_RETAINED") || !strings.Contains(*r.Body, "neverRun()") {
		t.Fatal("content projection lost inert text or retained binary")
	}
	for i := 0; i < 10; i++ {
		q := parseNotebook(t, notebookHeader("kernel"), out)
		if !reflect.DeepEqual(q.Records[1].Notebook, r.Notebook) || *q.Records[1].RawBody != *r.RawBody {
			t.Fatal("non-deterministic content projection")
		}
	}
}

func TestNotebookConflictingMessageAndCaptureGap(t *testing.T) {
	a := notebookMessage("shell", "send", "client", "same", "execute_request", "", "", map[string]any{"code": "1"})
	b := notebookMessage("shell", "send", "client", "same", "execute_request", "", "", map[string]any{"code": "2"})
	p := parseNotebook(t, notebookHeader("kernel"), a, b)
	if p.Coverage.Status != Ambiguous || len(p.Records) != 0 {
		t.Fatalf("conflicting message overwritten: %+v", p)
	}
	p = parseNotebook(t, notebookHeader("kernel"), a, map[string]any{"type": "notebook_gap",
		"schema_version": NotebookCaptureVersion, "timestamp": "2026-11-14T10:00:02Z", "reason": "capture_budget_exceeded"})
	if p.Coverage.Status != Partial || len(p.Records) != 3 || *p.Coverage.Counts.Truncated != 1 {
		t.Fatalf("capture gap lost: %+v", p)
	}
}
