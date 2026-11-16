package browserlink

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func testScope() Scope {
	return Scope{"producer", "namespace", "instance", "generation", "browser", "context"}
}

func record(t *testing.T, ref, kind string, change func(*entry)) Record {
	t.Helper()
	e := entry{RunID: "run", ExecutionScope: "current_execution", Browser: &native{EventID: ref, Kind: kind, TargetID: "page", TargetType: "page", CDPSessionID: "cdp", FrameID: "frame", LoaderID: "loader"}}
	e.Source.ID, e.Source.SessionID, e.Source.Harness = "source", "session", "browser"
	scope := testScope()
	e.Source.Browser = &scope
	if change != nil {
		change(&e)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return Record{Ref: ref, Payload: raw}
}

func project(t *testing.T, records ...Record) Projection {
	t.Helper()
	p, err := Project(context.Background(), Input{RunID: "run", Records: records})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func relations(p Projection, kind string) []Relation {
	var found []Relation
	for _, r := range p.Relations {
		if r.Kind == kind {
			found = append(found, r)
		}
	}
	return found
}

func hasIssue(p Projection, status, reason string) bool {
	for _, issue := range p.Issues {
		if issue.Status == status && issue.Reason == reason {
			return true
		}
	}
	return false
}

func TestBrowserNativeLayeredReferences(t *testing.T) {
	request := func(id string, hop int) func(*entry) {
		return func(e *entry) { e.Browser.RequestID, e.Browser.RedirectIndex = id, hop }
	}
	op := func(e *entry) { e.Browser.OperationID, e.Browser.Operation = "op", "navigate" }
	records := []Record{
		record(t, "start", "action_start", op),
		record(t, "end", "action_end", func(e *entry) { op(e); request("req", 0)(e); e.Browser.DownloadID = "download" }),
		record(t, "frame", "frame", nil),
		record(t, "request", "request", request("req", 0)),
		record(t, "redirect", "request", request("req", 1)),
		record(t, "response", "response", request("req", 1)),
		record(t, "finished", "request_finished", request("req", 1)),
		record(t, "script", "request", request("script", 0)),
		record(t, "script_finished", "request_finished", request("script", 0)),
		record(t, "child", "request", func(e *entry) { request("child", 0)(e); e.Browser.InitiatorRequestID = "script" }),
		record(t, "download", "download", func(e *entry) { e.Browser.DownloadID = "download"; request("req", 1)(e) }),
		record(t, "download_end", "download_finished", func(e *entry) { e.Browser.DownloadID = "download" }),
	}
	p := project(t, records...)
	for kind, count := range map[string]int{"browser_scope_member": 12, "browser_action_result": 1, "browser_action_request": 1, "browser_action_document": 1, "browser_action_download": 1,
		"browser_request_redirect": 1, "browser_request_lifecycle": 3, "browser_request_initiator": 1, "browser_document_request": 4,
		"browser_document_download": 1, "browser_request_download": 1, "browser_download_lifecycle": 1} {
		if got := len(relations(p, kind)); got != count {
			t.Errorf("%s count=%d want=%d", kind, got, count)
		}
	}
	for _, r := range p.Relations {
		if r.Rule != NativeRule || r.Status != "supported" || r.Scope != testScope() || len(r.SourceRefs) == 0 || r.EvidenceGrade != "application_observed" {
			t.Fatalf("missing layered evidence: %+v", r)
		}
	}
	if refs := relations(p, "browser_action_request")[0].SourceRefs; !reflect.DeepEqual(refs, []string{"end", "request", "start"}) {
		t.Fatalf("anchor refs: %v", refs)
	}
	slices.Reverse(records)
	if other := project(t, records...); !reflect.DeepEqual(p, other) {
		t.Fatal("record order changed projection")
	}
	if p2 := project(t, append(records, records[0])...); !reflect.DeepEqual(p, p2) {
		t.Fatal("identical retained object duplicated claims")
	}
}

func TestBrowserContextIsNotActionCausality(t *testing.T) {
	for _, kind := range []string{"background", "service_worker", "cache", "iframe", "websocket"} {
		t.Run(kind, func(t *testing.T) {
			start := record(t, "click", "action_start", func(e *entry) { e.Browser.OperationID, e.Browser.Operation = "click", "click" })
			end := record(t, "end", "action_end", func(e *entry) {
				e.Browser.OperationID, e.Browser.Operation = "click", "click"
				e.Browser.FrameID, e.Browser.LoaderID = "", ""
			})
			request := record(t, "background", "request", func(e *entry) {
				e.Browser.RequestID = "req"
				if kind == "service_worker" {
					e.Browser.TargetID, e.Browser.CDPSessionID, e.Browser.TargetType = "worker", "worker-cdp", "service_worker"
				}
			})
			p := project(t, start, end, request)
			for _, r := range p.Relations {
				if r.Kind == "browser_action_request" || r.Rule == RuntimeRule {
					t.Fatalf("context guessed action/OS cause: %+v", r)
				}
			}
			if !hasIssue(p, "unresolved", "action_effect_requires_explicit_native_reference") {
				t.Fatal("missing unanchored action diagnostic")
			}
		})
	}
}

func TestBrowserNativeNegativeControls(t *testing.T) {
	base := func(e *entry) { e.Browser.RequestID = "req" }
	for _, tc := range []struct {
		name           string
		mutate         func(*entry)
		status, reason string
	}{
		{"other_tab", func(e *entry) { e.Browser.TargetID, e.Browser.CDPSessionID = "other", "other-cdp" }, "unresolved", "missing_request_reference"},
		{"other_context", func(e *entry) { e.Source.Browser.ContextID = "other" }, "unresolved", "missing_request_reference"},
		{"other_generation", func(e *entry) { e.Source.Browser.Generation = "other" }, "unresolved", "missing_request_reference"},
		{"reused_cdp", func(e *entry) { e.Browser.TargetID = "other" }, "ambiguous", "conflicting_native_owner_or_event"},
		{"loader_conflict", func(e *entry) { e.Browser.LoaderID = "other" }, "contradicted", "native_reference_identity_mismatch"},
		{"frame_conflict", func(e *entry) { e.Browser.FrameID = "other" }, "contradicted", "native_reference_identity_mismatch"},
		{"other_hop", func(e *entry) { e.Browser.RedirectIndex = 1 }, "unresolved", "missing_request_reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := project(t, record(t, "request", "request", base), record(t, "response", "response", func(e *entry) { base(e); tc.mutate(e) }))
			if len(relations(p, "browser_request_lifecycle")) != 0 || !hasIssue(p, tc.status, tc.reason) {
				t.Fatalf("unsafe association: %+v", p)
			}
		})
	}
	for _, field := range []string{"producer", "namespace", "instance", "browser"} {
		t.Run(field, func(t *testing.T) {
			p := project(t, record(t, "request", "request", base), record(t, "response", "response", func(e *entry) {
				base(e)
				switch field {
				case "producer":
					e.Source.Browser.ProducerID = "other"
				case "namespace":
					e.Source.Browser.Namespace = "other"
				case "instance":
					e.Source.Browser.InstanceID = "other"
				case "browser":
					e.Source.Browser.BrowserID = "other"
				}
			}))
			if len(relations(p, "browser_request_lifecycle")) != 0 {
				t.Fatal("cross-scope match")
			}
		})
	}
}

func TestBrowserAmbiguousRequestsAndInitiators(t *testing.T) {
	request := func(e *entry) { e.Browser.RequestID = "req" }
	p := project(t, record(t, "first", "request", request), record(t, "duplicate", "request", request), record(t, "response", "response", request))
	if len(relations(p, "browser_request_lifecycle")) != 0 || !hasIssue(p, "ambiguous", "multiple_request_claims") {
		t.Fatalf("duplicate request: %+v", p)
	}
	p = project(t, record(t, "first", "request", request), record(t, "redirect", "request", func(e *entry) { request(e); e.Browser.RedirectIndex = 1 }),
		record(t, "child", "request", func(e *entry) { e.Browser.RequestID, e.Browser.InitiatorRequestID = "child", "req" }))
	if len(relations(p, "browser_request_initiator")) != 0 || !hasIssue(p, "ambiguous", "multiple_initiator_claims") {
		t.Fatalf("redirect initiator guessed latest hop: %+v", p)
	}
}

func TestBrowserMissingSupportAndHistoricalContext(t *testing.T) {
	start := record(t, "start", "action_start", func(e *entry) { e.Browser.OperationID, e.Browser.Operation = "op", "navigate" })
	end := record(t, "end", "action_end", func(e *entry) {
		e.Browser.OperationID, e.Browser.Operation, e.Browser.RequestID = "op", "navigate", "req"
	})
	request := record(t, "request", "request", func(e *entry) { e.Browser.RequestID = "req" })
	for _, records := range [][]Record{{start, request}, {end, request}, {start, end}} {
		if p := project(t, records...); len(relations(p, "browser_action_request")) != 0 {
			t.Fatal("missing support kept action relation")
		}
	}
	prior := record(t, "prior", "request", func(e *entry) { e.Browser.RequestID = "req"; e.ExecutionScope = "prior_context" })
	if p := project(t, start, end, prior); len(relations(p, "browser_action_request")) != 0 {
		t.Fatal("historical evidence used as current")
	}
	download := record(t, "download", "download", func(e *entry) { e.Browser.DownloadID = "d"; e.Browser.LoaderID = "" })
	if p := project(t, download, record(t, "frame", "frame", nil)); len(relations(p, "browser_document_download")) != 0 || !hasIssue(p, "unresolved", "missing_document_loader_reference") {
		t.Fatal("download assigned latest frame loader")
	}
}

func TestBrowserProjectionInputBounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Project(ctx, Input{RunID: "run"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"source":{},"source":{}}`, `{"source":{},"Source":{}}`, `{"browser":{"request_id":"a","request_id":"b"}}`, `{} {}`, `null`, strings.Repeat("[", 66) + strings.Repeat("]", 66)} {
		_, err := Project(context.Background(), Input{RunID: "run", Records: []Record{{Ref: "x", Payload: json.RawMessage(raw)}}})
		if err == nil && raw != "null" {
			t.Errorf("accepted ambiguous input %s", raw)
		}
	}
	if _, err := Project(context.Background(), Input{RunID: "run", Records: make([]Record, MaxRecords+1)}); err == nil {
		t.Fatal("record bound ignored")
	}
	r := record(t, "x", "request", nil)
	other := record(t, "x", "response", nil)
	if _, err := Project(context.Background(), Input{RunID: "run", Records: []Record{r, other}}); err == nil {
		t.Fatal("conflicting content ref accepted")
	}
}

func TestBrowserInitiatorSelectionCannotUpgradeRedirect(t *testing.T) {
	parent := record(t, "hop-0", "request", func(e *entry) { e.Browser.RequestID = "parent" })
	redirect := record(t, "hop-1", "request", func(e *entry) {
		e.Browser.RequestID, e.Browser.RedirectIndex = "parent", 1
	})
	terminal := record(t, "finished", "request_finished", func(e *entry) {
		e.Browser.RequestID, e.Browser.RedirectIndex = "parent", 1
	})
	child := record(t, "child", "request", func(e *entry) {
		e.Browser.RequestID, e.Browser.InitiatorRequestID = "child", "parent"
	})
	for _, tc := range []struct {
		name    string
		records []Record
	}{
		{"complete_redirect", []Record{parent, redirect, terminal, child}},
		{"exclude_first_hop", []Record{redirect, terminal, child}},
		{"exclude_final_hop", []Record{parent, terminal, child}},
		{"exclude_final_hop_and_terminal", []Record{parent, child}},
		{"only_redirect_hop", []Record{redirect, child}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := project(t, tc.records...)
			if got := len(relations(p, "browser_request_initiator")); got != 0 {
				t.Fatalf("selection upgraded unspecified redirect hop: supported_initiators=%d want=0", got)
			}
			for _, r := range p.Relations {
				for _, ref := range r.SourceRefs {
					if !slices.ContainsFunc(tc.records, func(record Record) bool { return record.Ref == ref }) {
						t.Fatal("relation retained excluded support")
					}
				}
			}
		})
	}
}

func TestBrowserInitiatorRequiresRetainedCompletion(t *testing.T) {
	parent := record(t, "parent", "request", func(e *entry) { e.Browser.RequestID = "parent" })
	child := record(t, "child", "request", func(e *entry) {
		e.Browser.RequestID, e.Browser.InitiatorRequestID = "child", "parent"
	})
	for _, phase := range []string{"request_finished", "request_failed"} {
		t.Run(phase, func(t *testing.T) {
			terminal := record(t, "terminal", phase, func(e *entry) { e.Browser.RequestID = "parent" })
			p := project(t, parent, terminal, child)
			edges := relations(p, "browser_request_initiator")
			if len(edges) != 1 || !reflect.DeepEqual(edges[0].SourceRefs, []string{"child", "parent", "terminal"}) {
				t.Fatalf("completed non-redirect initiator must retain its terminal proof: %+v", edges)
			}
			for _, records := range [][]Record{{parent, child}, {terminal, child}, {parent, terminal}} {
				if got := len(relations(project(t, records...), "browser_request_initiator")); got != 0 {
					t.Fatalf("excluded support retained %d initiator edges", got)
				}
			}
			for _, change := range []func(*entry){
				func(e *entry) { e.Source.Browser.Generation = "other" },
				func(e *entry) { e.Browser.LoaderID = "other" },
				func(e *entry) { e.Browser.RedirectIndex = 1 },
				func(e *entry) { e.Browser.TargetID, e.Browser.CDPSessionID = "other", "other-cdp" },
			} {
				other := record(t, "other-terminal", phase, func(e *entry) { e.Browser.RequestID = "parent"; change(e) })
				if got := len(relations(project(t, parent, other, child), "browser_request_initiator")); got != 0 {
					t.Fatal("mismatched completion authorized an initiator edge")
				}
			}
			duplicate := record(t, "duplicate-terminal", phase, func(e *entry) { e.Browser.RequestID = "parent" })
			if got := len(relations(project(t, parent, terminal, duplicate, child), "browser_request_initiator")); got != 0 {
				t.Fatal("ambiguous completion authorized an initiator edge")
			}
		})
	}
}

func TestBrowserOperationOwnerConflictAcrossLanes(t *testing.T) {
	for _, mode := range []string{"other_tab", "other_cdp", "other_action", "admission_without_cdp"} {
		t.Run(mode, func(t *testing.T) {
			base := func(e *entry) { e.Browser.OperationID, e.Browser.Operation = "op", "navigate" }
			start, end := record(t, "start", "action_start", base), record(t, "end", "action_end", base)
			other := func(e *entry) {
				base(e)
				switch mode {
				case "other_tab", "admission_without_cdp":
					e.Browser.TargetID, e.Browser.CDPSessionID = "other", "other-cdp"
				case "other_cdp":
					e.Browser.CDPSessionID = "other-cdp"
				case "other_action":
					e.Browser.Operation = "click"
				}
			}
			records := []Record{start, end, record(t, "other-start", "action_start", other), record(t, "other-end", "action_end", other)}
			if mode == "admission_without_cdp" {
				records = []Record{start, end, record(t, "accept", "action_accept", func(e *entry) {
					other(e)
					e.Browser.CDPSessionID, e.Browser.TargetType = "", ""
				})}
			}
			p := project(t, records...)
			if got := len(relations(p, "browser_action_result")); got != 0 || !hasIssue(p, "ambiguous", "conflicting_operation_owner") {
				t.Fatalf("scope-wide duplicate operation accepted: supported_results=%d want=0; conflict_diagnostic=%v", got, hasIssue(p, "ambiguous", "conflicting_operation_owner"))
			}
			slices.Reverse(records)
			if other := project(t, records...); !reflect.DeepEqual(p, other) {
				t.Fatal("operation conflict changed with record order")
			}
		})
	}
}

func TestBrowserOperationIDsRemainIndependentAcrossGenerations(t *testing.T) {
	var records []Record
	for _, generation := range []string{"original", "restarted"} {
		for _, kind := range []string{"action_start", "action_end"} {
			records = append(records, record(t, generation+"-"+kind, kind, func(e *entry) {
				e.Source.Browser.Generation = generation
				e.Browser.EventID, e.Browser.OperationID, e.Browser.Operation = kind, "op", "navigate"
			}))
		}
	}
	p := project(t, records...)
	if got := len(relations(p, "browser_action_result")); got != 2 || hasIssue(p, "ambiguous", "conflicting_operation_owner") {
		t.Fatalf("legitimate multi-generation operations collapsed: supported_results=%d want=2", got)
	}
	for _, edge := range relations(p, "browser_action_result") {
		if !strings.HasPrefix(edge.From, edge.Scope.Generation+"-") || !strings.HasPrefix(edge.To, edge.Scope.Generation+"-") {
			t.Fatal("cross-generation operation edge")
		}
	}
}
