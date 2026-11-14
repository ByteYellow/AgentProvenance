package agentcontext

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestSessionRelationReaderReusesPayloadsWithoutChangingPages(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	spawn, fork := `{"session_id":"child","parent_session_id":"root"}`, `{"id":"branch","forked_from_id":"root"}`
	relationSource(t, s, "a", "codex", "root", "", Record{Key: "spawn", Kind: "session", ToolName: "spawn_agent", Status: "started", Body: &spawn})
	relationSource(t, s, "b", "codex", "root", "")
	relationSource(t, s, "b", "codex", "child", "root")
	relationSource(t, s, "b", "codex", "branch", "", Record{Key: "fork", Kind: "configuration", Status: "session_metadata", Body: &fork})
	relationSource(t, s, "b", "claude", "root", "")
	reader := s.NewSessionRelationReader()
	reads := map[relationPayloadKey]int{}
	reader.payloads.load = func(run, hash string, target any) error {
		reads[relationPayloadKey{run, hash}]++
		return provenance.ReadObjectPayload(s.DB, run, hash, target)
	}
	for repeat := 0; repeat < 2; repeat++ {
		for _, query := range []SessionRelationOptions{
			{RunID: "a", Harness: "codex", SessionID: "root", Limit: 1},
			{RunID: "b", Harness: "codex", SessionID: "child", Limit: 1},
			{RunID: "a", Harness: "codex", SessionID: "root", VisibleRuns: []string{"a"}},
			{RunID: "b", Harness: "codex", SessionID: "branch", VisibleRuns: []string{"b"}},
			{RunID: "b", Harness: "claude", SessionID: "root"},
		} {
			for {
				want, err := s.SessionRelations(ctx, query)
				if err != nil {
					t.Fatal(err)
				}
				got, err := reader.SessionRelations(ctx, query)
				if err != nil || !reflect.DeepEqual(want, got) {
					t.Fatalf("query %+v changed: %v\nwant=%+v\ngot=%+v", query, err, want, got)
				}
				if len(got.Relations) > 0 {
					got.Relations[0].Evidence[0].Basis = "caller mutation"
				}
				if !want.HasMore {
					break
				}
				query.Cursor = want.NextCursor
			}
		}
	}
	if len(reads) != 7 {
		t.Fatalf("expected five reports and two native entries: %v", reads)
	}
	for key, count := range reads {
		if count != 1 {
			t.Fatalf("repeated payload I/O for %v: %d", key, count)
		}
	}
	query := SessionRelationOptions{RunID: "a", Harness: "codex", SessionID: "root"}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := reader.SessionRelations(canceled, query); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	// Cached bytes do not bypass each query's database identity checks.
	if _, err := s.DB.Exec(`UPDATE agent_context_reports SET session_id='wrong' WHERE run_id='a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.SessionRelations(ctx, query); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("cached source bypassed identity validation: %v", err)
	}
}

func TestSessionRelationReaderVerifiesFirstReadAndKeepsLiveQueriesFresh(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	relationSource(t, s, "a", "codex", "child", "parent")
	query := SessionRelationOptions{RunID: "a", Harness: "codex", SessionID: "child"}
	var path string
	if err := s.DB.QueryRow(`SELECT o.path FROM provenance_objects o JOIN agent_context_reports r
 ON o.run_id=r.run_id AND o.hash=r.object_hash WHERE r.run_id='a'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader := s.NewSessionRelationReader()
	if err := os.WriteFile(path, []byte(`{"tampered":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.SessionRelations(ctx, query); err == nil {
		t.Fatal("unverified payload accepted")
	}
	if len(reader.payloads.values) != 0 {
		t.Fatal("failed verification entered cache")
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	page, err := reader.SessionRelations(ctx, query)
	if err != nil || len(page.Relations) != 1 || page.Relations[0].From.Available {
		t.Fatalf("retry after failed read: %+v %v", page, err)
	}
	relationSource(t, s, "b", "codex", "parent", "")
	live, err := s.SessionRelations(ctx, query)
	if err != nil || !live.Relations[0].From.Available || live.Relations[0].From.RunID != "b" {
		t.Fatalf("live query failed to see new evidence: %+v %v", live, err)
	}
	isolated := s.NewSessionRelationReader()
	if len(isolated.payloads.values) != 0 {
		t.Fatal("new export inherited another cache")
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.SessionRelations(ctx, query); err == nil {
		t.Fatal("cached payload concealed database failure")
	}
}

func TestRelationPayloadCacheBoundsAndOwnership(t *testing.T) {
	for _, mode := range []string{"entries", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			reads := map[relationPayloadKey]int{}
			body, count := "small", relationCacheEntries+1
			if mode == "bytes" {
				body, count = strings.Repeat("x", 1<<20), 9
			}
			cache := relationPayloadCache{load: func(run, hash string, target any) error {
				reads[relationPayloadKey{run, hash}]++
				raw, _ := json.Marshal(map[string]string{"run": run, "hash": hash, "body": body})
				return json.Unmarshal(raw, target)
			}}
			for i := 0; i < count; i++ {
				var got map[string]string
				hash := fmt.Sprint(i)
				if err := cache.read("a", hash, &got); err != nil || got["body"] != body || got["hash"] != hash {
					t.Fatalf("bounded cache changed result: %v", err)
				}
			}
			if cache.bytes > relationCacheBytes || len(cache.values) > relationCacheEntries {
				t.Fatalf("cache exceeded budget: bytes=%d entries=%d", cache.bytes, len(cache.values))
			}
			last := fmt.Sprint(count - 1)
			var got map[string]string
			if err := cache.read("a", last, &got); err != nil || reads[relationPayloadKey{"a", last}] != 2 {
				t.Fatalf("full cache must fall back to a verified read: %v", err)
			}
		})
	}
	reads := 0
	cache := relationPayloadCache{load: func(run, hash string, target any) error {
		reads++
		raw, _ := json.Marshal(map[string]string{"run": run})
		return json.Unmarshal(raw, target)
	}}
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var got map[string]string
			if err := cache.read("a", "same-hash", &got); err != nil || got["run"] != "a" {
				t.Errorf("concurrent read: %v %+v", err, got)
			}
			got["run"] = "changed"
		}()
	}
	workers.Wait()
	var got map[string]string
	if err := cache.read("b", "same-hash", &got); err != nil || got["run"] != "b" || reads != 2 {
		t.Fatalf("run namespace lost: %v %+v reads=%d", err, got, reads)
	}
}
