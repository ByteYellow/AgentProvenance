package dashboard

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/browserlink"
)

func TestReplayBrowserInitiatorSelectionDoesNotUpgrade(t *testing.T) {
	for _, redirected := range []bool{false, true} {
		name := "completed_non_redirect"
		if redirected {
			name = "redirected"
		}
		t.Run(name, func(t *testing.T) {
			paths, db, _ := artifactStore(t)
			ctx := context.Background()
			var input strings.Builder
			input.WriteString(`{"type":"browser_session","schema_version":"agentprovenance.browser_capture/v1","producer_id":"p","namespace":"n","instance_id":"i","generation":"g","browser_id":"b","context_id":"c"}` + "\n")
			add := func(id, kind, request, initiator string, hop int) {
				raw, err := json.Marshal(map[string]any{"type": "browser_event", "schema_version": agentcontext.BrowserCaptureVersion,
					"context_id": "c", "event_id": id, "kind": kind, "target_id": "page", "target_type": "page", "cdp_session_id": "cdp",
					"request_id": request, "redirect_index": hop, "initiator_request_id": initiator,
					"payload": map[string]any{"url": "https://example.test/PRIVATE_NATIVE_" + id}})
				if err != nil {
					t.Fatal(err)
				}
				input.Write(raw)
				input.WriteByte('\n')
			}
			add("parent", "request", "parent-request", "", 0)
			hop := 0
			if redirected {
				hop = 1
				add("redirect", "request", "parent-request", "", hop)
			}
			add("terminal", "request_finished", "parent-request", "", hop)
			add("child", "request", "child-request", "parent-request", 0)
			parsed, err := agentcontext.Parse(ctx, strings.NewReader(input.String()), agentcontext.ParseOptions{Harness: "browser", Binding: "explicit"})
			if err != nil {
				t.Fatal(err)
			}
			svc := agentcontext.Service{DB: db, Paths: paths}
			if _, err := svc.Save(ctx, "browser-native-selection", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
				t.Fatal(err)
			}
			page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "browser-native-selection"})
			if err != nil {
				t.Fatal(err)
			}
			entries := map[string]agentcontext.Entry{}
			for _, entry := range page.Entries {
				if entry.Browser != nil {
					entries[entry.Browser.EventID] = entry
				}
			}
			selections := [][]string{nil, {"parent"}, {"terminal"}, {"child"}}
			if redirected {
				selections = append(selections, []string{"redirect"}, []string{"redirect", "terminal"})
			}
			for _, excluded := range selections {
				t.Run("exclude_"+strings.Join(excluded, "_"), func(t *testing.T) {
					selection := ReplaySelection{RunID: "browser-native-selection", Scope: "whole_run"}
					for _, id := range excluded {
						selection.ExcludeRecords = append(selection.ExcludeRecords, "entry/"+entries[id].ID)
					}
					prepared, err := (Server{DB: db}).PrepareOfflineReplaySet(ctx, []ReplaySelection{selection})
					if err != nil {
						t.Fatal(err)
					}
					defer prepared.Close()
					files, all := replayZIPData(t, prepared)
					for _, id := range excluded {
						if strings.Contains(all, "PRIVATE_NATIVE_"+id) {
							t.Fatalf("excluded native body leaked: %s", id)
						}
					}
					found := false
					var walk func(any)
					walk = func(value any) {
						switch v := value.(type) {
						case map[string]any:
							if v["derivation_rule"] == browserlink.NativeRule {
								refs, _ := v["evidence_refs"].([]any)
								for _, id := range excluded {
									if slices.Contains(refs, any(entries[id].ObjectHash)) {
										t.Fatalf("excluded ref retained in native edge: %s", id)
									}
								}
								if v["edge_type"] == "browser_request_initiator" {
									found = true
									if !slices.Contains(refs, any(entries["terminal"].ObjectHash)) {
										t.Error("initiator edge lost its terminal evidence")
									}
								}
							}
							for _, child := range v {
								walk(child)
							}
						case []any:
							for _, child := range v {
								walk(child)
							}
						}
					}
					for _, raw := range files {
						var value any
						if json.Unmarshal(raw, &value) == nil {
							walk(value)
						}
					}
					want := !redirected && len(excluded) == 0
					if found != want {
						t.Fatalf("selected ZIP initiator_supported=%v want=%v", found, want)
					}
				})
			}
		})
	}
}
