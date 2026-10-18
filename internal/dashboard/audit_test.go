package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestAuditReplayKeepsFrozenCandidatesAndSelectionBoundary(t *testing.T) {
	_, db, _ := artifactStore(t)
	ctx := context.Background()
	const run = "audit-interface-fixture"
	const boot = "01234567-89ab-cdef-0123-456789abcdef"
	const thread = boot + ":43:1000000000"
	stamp := time.Unix(1792342593, 757000000).UTC()
	for _, e := range []struct {
		id, typ, stage string
		offset         time.Duration
	}{
		{"before", "execve", "", -5 * time.Millisecond},
		{"entry", "network_connect", "attempt", 100 * time.Microsecond},
		{"result", "syscall_result", "result", 200 * time.Microsecond},
		{"second-entry", "network_connect", "attempt", 300 * time.Microsecond},
		{"after", "execve", "", 5 * time.Millisecond},
	} {
		f := map[string]any{"host_id": "fixture-host", "boot_id": boot, "realtime_coarse_resolution_ns": 4000000,
			"process_instance_id": boot + ":42:1000000000", "process_start_ns": "1000000000", "monotonic_ns": strconv.FormatInt(int64(10*time.Second+e.offset), 10),
			"thread_instance_id": thread, "thread_start_ns": "1000000000", "tid": 43, "comm": "fixture"}
		if e.stage != "" {
			start := "10000100000"
			if e.id == "second-entry" {
				start = "10000300000"
				f["marker"] = "EXCLUDED-AUDIT-CANDIDATE-BODY"
			}
			f["operation_id"], f["operation"], f["syscall_start_ns"] = "syscall-v1:"+thread+":42:1000000000:"+start, "network_connect", start
			f["observation_stage"], f["syscall_number"], f["sensor_arch"] = e.stage, 203, "arm64"
			if e.stage == "result" {
				f["syscall_result"], f["syscall_outcome"] = 0, "success"
			}
		}
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO events(id,run_id,pid,source,event_type,payload,created_at) VALUES(?,?,42,'agentprov_ebpf',?,?,?)`, e.id, run, e.typ, string(raw), stamp.Add(e.offset).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	var lines strings.Builder
	for i := 0; i < 101; i++ {
		fmt.Fprintf(&lines, "type=SECCOMP msg=audit(1792342593.757:%d): pid=42 comm=\"fixture\" arch=c00000b7 syscall=203 code=0x7ffc0000\n", 130+i)
	}
	if _, err := telemetry.IngestAuditReader(ctx, db, telemetry.AuditIngestOptions{RunID: run, Source: telemetry.AuditSource{HostID: "fixture-host", BootID: boot}}, strings.NewReader(lines.String())); err != nil {
		t.Fatal(err)
	}
	want, err := telemetry.BuildAuditAssociations(ctx, db, telemetry.AuditAssociationOptions{RunID: run, Limit: 500})
	if err != nil || len(want.Items) != 101 || want.Items[0].Operation.Status != "ambiguous" {
		t.Fatalf("fixture=%+v %v", want, err)
	}
	for _, partial := range []bool{false, true} {
		name := "whole"
		selection := ReplaySelection{RunID: run, Scope: "whole_run"}
		if partial {
			name = "partial"
			selection.ExcludeRecords = []string{"3/second-entry"}
		}
		t.Run(name, func(t *testing.T) {
			p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(ctx, selection)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			files, all := replayZIPData(t, p)
			if partial && strings.Contains(all, "EXCLUDED-AUDIT-CANDIDATE-BODY") {
				t.Fatal("excluded runtime body leaked")
			}
			found := map[string]telemetry.AuditAssociationItem{}
			for _, data := range files {
				var page telemetry.AuditAssociationReport
				if json.Unmarshal(data, &page) != nil || page.SchemaVersion != "agentprovenance.audit_associations/v1" {
					continue
				}
				if page.AnalysisScope != "export_pages" || page.NextCursor != "" {
					t.Fatal("internal source cursor escaped export")
				}
				for _, item := range page.Items {
					found[item.EventID] = item
					if partial && (item.Operation.Status != "unassociated" || item.Operation.Reason != "replay_evidence_excluded" || len(item.Operations) != 0 || len(item.Process.Candidates) != 0) {
						t.Fatalf("excluded competitor upgraded inference: %+v", item)
					}
				}
			}
			if len(found) != 101 {
				t.Fatalf("exported %d decisions", len(found))
			}
			if !partial {
				for _, item := range want.Items {
					if !reflect.DeepEqual(found[item.EventID], item) {
						t.Fatal("export changed frozen candidates")
					}
				}
			}
			if root := os.Getenv("AGENTPROV_AUDIT_UI_FIXTURE_DIR"); root != "" {
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				f, err := os.Create(filepath.Join(root, name+".zip"))
				if err != nil {
					t.Fatal(err)
				}
				writeErr := p.WriteZIP(ctx, f)
				closeErr := f.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("save fixture: %v %v", writeErr, closeErr)
				}
			}
		})
	}
}

func TestAuditProjectionFiltersContextAndTruncatedDependencies(t *testing.T) {
	zero := int64(0)
	item := telemetry.AuditAssociationItem{EventID: "audit", Process: telemetry.AuditAssociation{Status: "inferred"},
		Operation: telemetry.AuditAssociation{Status: "inferred"}, Operations: []telemetry.AuditOperation{{ID: "operation", Result: &zero,
			Context: []telemetry.AuditContextRef{{EventID: "runtime", ToolCallID: "omitted-tool"}, {EventID: "included", ToolCallID: "selected-tool"}}}}}
	got, withheld := projectAuditItem(item, map[string]bool{"3/runtime": true, "3/included": true, "2/selected-tool": true})
	if withheld || len(got.Operations[0].Context) != 1 || got.Operations[0].Context[0].EventID != "included" || *got.Operations[0].Result != 0 {
		t.Fatalf("context projection: %+v", got)
	}
	item.Process.CandidatesTruncated = true
	got, withheld = projectAuditItem(item, map[string]bool{})
	if !withheld || len(got.Operations) != 0 || got.Process.Reason != "replay_evidence_excluded" {
		t.Fatal("unverifiable dependency retained")
	}
}
