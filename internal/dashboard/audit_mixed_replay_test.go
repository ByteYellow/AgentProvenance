package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestRecordedMixedAuditReplay(t *testing.T) {
	directory := os.Getenv("AGENTPROV_AUDIT_MIXED_BUNDLES")
	if directory == "" {
		t.Skip("set AGENTPROV_AUDIT_MIXED_BUNDLES to both signed retention-preset bundles")
	}
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			paths, db, _ := artifactStore(t)
			if _, err := (forensics.Service{DB: db, Paths: paths}).ImportBundle(filepath.Join(directory, preset+".forensics.json")); err != nil {
				t.Fatal(err)
			}
			server, ctx := Server{DB: db}, context.Background()
			const run = "live-audit-mixed"
			report, err := telemetry.BuildAuditAssociations(ctx, db, telemetry.AuditAssociationOptions{RunID: run})
			if err != nil || report.Status != "complete" || len(report.Items) < 6 {
				t.Fatalf("imported association: %+v %v", report, err)
			}
			sources := map[string]SearchSource{}
			for cursor := ""; ; {
				page, err := server.SearchSources(ctx, SearchSourceOptions{RunID: run, Cursor: cursor})
				if err != nil {
					t.Fatal(err)
				}
				for _, source := range page.Sources {
					sources[source.ID] = source
				}
				if !page.HasMore {
					break
				}
				cursor = page.NextCursor
			}
			exclude := ""
			for _, item := range report.Items {
				source := sources["3/"+item.EventID]
				if source.Kind != "access_control" || source.Node == "" || source.SessionID != "" || source.SessionAssociation != nil {
					t.Fatalf("real audit lost or assigned a fictional Agent Session: %+v", source)
				}
				var languageBody string
				for _, lang := range []string{"en", "zh-CN"} {
					r := httptest.NewRequest("GET", "/api/artifact?run="+run+"&node="+url.QueryEscape(source.Node)+"&mode=body", nil)
					r.Header.Set("Accept-Language", lang)
					w := httptest.NewRecorder()
					server.Handler().ServeHTTP(w, r)
					if w.Code != 200 {
						t.Fatalf("audit body: %d %s", w.Code, w.Body.String())
					}
					if lang == "en" {
						languageBody = w.Body.String()
					} else if languageBody != w.Body.String() {
						t.Fatal("recorded audit API was localized")
					}
				}
				if item.Decision == "DENIED" {
					exclude = source.ID
				}
			}
			if exclude == "" {
				t.Fatal("missing denied record for partial export")
			}
			comparison := accessRows(readComparison(t, server, run))
			counts := map[string]int{}
			for _, row := range comparison {
				counts[row.EvidenceKind]++
				if row.EvidenceKind == "audit_decision" && (strings.Contains(row.Value.Preview, "syscall_result") || strings.Contains(row.Value.Preview, `"errno"`)) {
					t.Fatal("audit decision became a runtime return")
				}
				if row.EvidenceKind == "syscall_result" && row.Mechanism != "" {
					t.Fatal("runtime failure acquired an inferred mechanism")
				}
			}
			if counts["audit_decision"] != len(report.Items) || counts["state_snapshot"] != 12 || counts["syscall_result"] < 3 {
				t.Fatalf("mixed comparison evidence missing: %v", counts)
			}
			for _, partial := range []bool{false, true} {
				name := preset
				selection := ReplaySelection{RunID: run, Scope: "whole_run"}
				if partial {
					name += "-partial"
					selection.ExcludeRecords = []string{exclude}
				}
				p, err := server.PrepareSelectedOfflineReplay(ctx, selection)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				files, _ := replayZIPData(t, p)
				frozen := map[string]telemetry.AuditAssociationItem{}
				frozenRows := []ComparisonRecord{}
				for _, data := range files {
					var associations telemetry.AuditAssociationReport
					if json.Unmarshal(data, &associations) == nil && associations.SchemaVersion == "agentprovenance.audit_associations/v1" {
						for _, item := range associations.Items {
							frozen[item.EventID] = item
						}
					}
					var page ComparisonPage
					if json.Unmarshal(data, &page) == nil && page.SchemaVersion == "agentprovenance.comparison_records/v1" {
						frozenRows = append(frozenRows, accessRows(page)...)
					}
				}
				want := len(report.Items)
				if partial {
					want--
				}
				if len(frozen) != want {
					t.Fatalf("frozen audit count got=%d want=%d", len(frozen), want)
				}
				for _, item := range report.Items {
					if partial && "3/"+item.EventID == exclude {
						if _, exists := frozen[item.EventID]; exists {
							t.Fatal("excluded audit in frozen association")
						}
						continue
					}
					if partial {
						item.EvidenceScope = "selected_records_only"
					}
					if !reflect.DeepEqual(item, frozen[item.EventID]) {
						t.Fatalf("frozen audit candidates or actual outcomes changed: got=%+v want=%+v", frozen[item.EventID], item)
					}
				}
				wantRows := slices.Clone(comparison)
				if partial {
					wantRows = slices.DeleteFunc(wantRows, func(row ComparisonRecord) bool { return row.Evidence.ID == exclude })
				}
				order := func(a, b ComparisonRecord) int { return strings.Compare(a.Key+a.Evidence.ID, b.Key+b.Evidence.ID) }
				slices.SortFunc(wantRows, order)
				slices.SortFunc(frozenRows, order)
				if !reflect.DeepEqual(wantRows, frozenRows) {
					t.Fatal("mixed comparison changed after export")
				}
				if output := os.Getenv("AGENTPROV_AUDIT_MIXED_REPLAY_OUTPUT"); output != "" {
					if err := os.MkdirAll(output, 0700); err != nil {
						t.Fatal(err)
					}
					file, err := os.Create(filepath.Join(output, name+".zip"))
					if err != nil {
						t.Fatal(err)
					}
					writeErr := p.WriteZIP(ctx, file)
					closeErr := file.Close()
					if writeErr != nil || closeErr != nil {
						t.Fatalf("export mixed capture: %v %v", writeErr, closeErr)
					}
				}
				t.Logf("%s: audit=%d comparison=%d; original Session identities and frozen references preserved", name, len(frozen), len(frozenRows))
			}
		})
	}
}
