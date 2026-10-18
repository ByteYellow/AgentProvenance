package dashboard

import (
	"context"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
)

func addRetentionFixture(t *testing.T, svc agentcontext.Service) {
	t.Helper()
	for _, preset := range []string{"basic", "detailed"} {
		policy, _ := agentcontext.NewCapturePolicy(preset, nil)
		svc.CapturePolicy = &policy
		run := "ui-retention-" + preset
		source := agentcontext.Source{ID: run + "-source", Harness: "codex", Channel: "transcript", SessionID: "retention-" + preset, Binding: "explicit", ParserVersion: "synthetic-retention-fixture/v1"}
		body := func(s string) *string { return &s }
		records := []agentcontext.Record{
			{Key: "task", Kind: "message", Role: "user", Sequence: 1, Body: body("Synthetic retention fixture: inspect report.txt. No live agent was executed.")},
			{Key: "config", Kind: "configuration", Sequence: 2, Status: "session_metadata", Body: body(`{"sandbox":"read-only","model":"fixture"}`)},
			{Key: "call", Kind: "tool_call", ToolCallID: "read-report", ToolName: "exec_command", Sequence: 3, Body: body(`{"cmd":"cat report.txt"}`)},
			{Key: "result", Kind: "tool_result", ToolCallID: "read-report", ToolName: "exec_command", Sequence: 4, Status: "error", Body: body("permission denied: RETENTION-RESULT-ONLY")},
		}
		for i := range records {
			records[i].ExecutionScope = agentcontext.CurrentExecution
			records[i].RawBody = body(`{"synthetic":true,"raw_source":"RETENTION-RAW-ONLY"}`)
		}
		if _, err := svc.Save(context.Background(), run, source, records, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
			t.Fatal(err)
		}
		if _, err := hooksbridge.IngestContext(context.Background(), svc.DB, svc.Paths, run); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRetentionReasonsReachSearchAndComparison(t *testing.T) {
	paths, db, _ := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	addRetentionFixture(t, svc)
	server := Server{DB: db}
	for _, preset := range []string{"basic", "detailed"} {
		run := "ui-retention-" + preset
		page, err := server.SearchSources(context.Background(), SearchSourceOptions{RunID: run})
		if err != nil {
			t.Fatal(err)
		}
		var resultFound bool
		for _, source := range page.Sources {
			if source.Kind == "tool_result" {
				resultFound = true
				if source.Entry == nil || source.Entry.Status != "error" || source.ToolCallID != "read-report" {
					t.Fatalf("tool outcome or identity lost: %+v", source)
				}
				if (source.Content.Reason == "capture_policy") != (preset == "basic") {
					t.Fatalf("search lost omission reason: %+v", source.Content)
				}
				if preset == "basic" && source.Content.Ref != "" {
					t.Fatal("omitted content has a fictitious body reference")
				}
			}
		}
		if !resultFound {
			t.Fatal("tool outcome missing from source catalog")
		}
		entries, err := svc.Entries(context.Background(), agentcontext.PageOptions{RunID: run, Kind: "configuration"})
		if err != nil || len(entries.Entries) != 1 {
			t.Fatalf("configuration: %+v %v", entries, err)
		}
		fields, reason, err := svc.SnapshotFields(context.Background(), entries.Entries[0])
		if err != nil || (reason == "capture_policy") != (preset == "basic") || (len(fields) == 0) != (preset == "basic") {
			t.Fatalf("configuration omission presented as a recorded value: %+v %s %v", fields, reason, err)
		}
		comparison, err := server.ComparisonRecords(context.Background(), run, "")
		if err != nil {
			t.Fatal(err)
		}
		var omitted bool
		for _, record := range comparison.Records {
			if record.Operation == "configuration_unavailable" {
				omitted = true
				if record.Value != nil || !record.Partial || record.Evidence.Content.Reason != "capture_policy" {
					t.Fatalf("comparison lost omission semantics: %+v", record)
				}
			}
		}
		if omitted != (preset == "basic") {
			t.Fatalf("unexpected configuration comparison: %+v", comparison)
		}
	}
}
