package agentcontext

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func snapshot(t *testing.T, s Service, run, key, kind, status string, body *string) Entry {
	t.Helper()
	if _, err := s.Save(context.Background(), run, testSource(), []Record{{Key: key, Sequence: 1, Kind: kind, Status: status, Body: body}}, Coverage{Status: OK}); err != nil {
		t.Fatal(err)
	}
	page, err := s.Entries(context.Background(), PageOptions{RunID: run, IncludeRevisions: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range page.Entries {
		if e.SourceKey == key {
			return e
		}
	}
	t.Fatal("snapshot not found")
	return Entry{}
}

func TestSnapshotComparisonDistinguishesMissingFromNull(t *testing.T) {
	s, ctx := testService(t), context.Background()
	a := `{"model":"first","permissions":null,"mcp":["files"],"same":1}`
	b := `{"same":1,"model":"second","mcp":["files","search"],"plugins":[]}`
	left := snapshot(t, s, "run", "before", "configuration", "observed", &a)
	right := snapshot(t, s, "run", "after", "configuration", "observed", &b)
	diff, err := s.CompareSnapshots(ctx, "run", left.ID, "", right.ID)
	if err != nil || diff.Status != "different" || len(diff.Changes) != 4 || diff.HasMore || diff.Scope != "recorded_values" {
		t.Fatalf("comparison: %+v %v", diff, err)
	}
	changes := map[string]SnapshotChange{}
	for _, c := range diff.Changes {
		changes[c.Path] = c
	}
	permission := changes["/content/permissions"]
	if !permission.Before.Present || permission.Before.Preview != "null" || permission.After.Present {
		t.Fatalf("missing field became an authorization: %+v", permission)
	}
	if diff.Left.ID != left.ID || diff.Right.ObjectHash != right.ObjectHash {
		t.Fatal("comparison lost source evidence identities")
	}
	// Reordering object keys is not a configuration change.
	reordered := `{"mcp":["files"],"same":1,"permissions":null,"model":"first"}`
	equal := snapshot(t, s, "run", "equal", "configuration", "observed", &reordered)
	same, err := s.CompareSnapshots(ctx, "run", left.ID, "", equal.ID)
	if err != nil || same.Status != "same" || len(same.Changes) != 0 {
		t.Fatalf("key ordering reported as a change: %+v %v", same, err)
	}
}

func TestSnapshotComparisonBoundsUnknownsAndIsolation(t *testing.T) {
	s, ctx := testService(t), context.Background()
	body := "task"
	left := snapshot(t, s, "one", "before", "task", "observed", &body)
	right := snapshot(t, s, "two", "after", "task", "changed", &body)
	if _, err := s.CompareSnapshots(ctx, "one", left.ID, "", right.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-run lookup was implicit: %v", err)
	}
	diff, err := s.CompareSnapshots(ctx, "one", left.ID, "two", right.ID)
	if err != nil || diff.Status != "different" || len(diff.Changes) != 1 || diff.Changes[0].Path != "/status" {
		t.Fatalf("source status ignored: %+v %v", diff, err)
	}
	missing := snapshot(t, s, "one", "missing", "task", "observed", nil)
	unknown, err := s.CompareSnapshots(ctx, "one", left.ID, "", missing.ID)
	if err != nil || unknown.Status != "unknown" || unknown.Reason != "content_not_recorded" || len(unknown.Changes) != 0 {
		t.Fatalf("absent evidence became equality: %+v %v", unknown, err)
	}
	big := strings.Repeat("x", maxComparisonBytes+1)
	large := snapshot(t, s, "one", "large", "task", "observed", &big)
	limited, err := s.CompareSnapshots(ctx, "one", left.ID, "", large.ID)
	if err != nil || limited.Status != "unknown" || limited.Reason != "comparison_content_limit" {
		t.Fatalf("comparison budget: %+v %v", limited, err)
	}
	config := snapshot(t, s, "one", "config", "configuration", "observed", &body)
	if _, err := s.CompareSnapshots(ctx, "one", left.ID, "", config.ID); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("different kinds compared as equivalent: %v", err)
	}
}

func TestSnapshotDiffLimitsPreviewAndChanges(t *testing.T) {
	out := SnapshotComparison{Changes: []SnapshotChange{}}
	many := map[string]any{}
	for i := 0; i < maxSnapshotChanges+10; i++ {
		many[fmt.Sprintf("%03d", i)] = i
	}
	diffSnapshots(&out, "", map[string]any{}, true, many, true, 0)
	if !out.HasMore || len(out.Changes) != maxSnapshotChanges {
		t.Fatalf("unbounded comparison: %d %v", len(out.Changes), out.HasMore)
	}
	// Non-ASCII source values are preserved without cutting a UTF-8 code point.
	p := snapshotValue(strings.Repeat("\u4e2d", 300), true)
	if !p.Truncated || !utf8.ValidString(p.Preview) || len(p.Preview) > maxSnapshotPreview || p.SHA256 == "" {
		t.Fatalf("invalid preview: %+v", p)
	}
}

func TestSnapshotComparisonHTTPReadsOnlyRecordedRedactedValues(t *testing.T) {
	s := testService(t)
	a, b := `{"model":"a"}`, `{"model":"b","token":"sk-`+strings.Repeat("a", 40)+`"}`
	left := snapshot(t, s, "run", "left", "configuration", "observed", &a)
	right := snapshot(t, s, "run", "right", "configuration", "observed", &b)
	w := httptest.NewRecorder()
	s.ReadHandler().ServeHTTP(w, httptest.NewRequest("GET", "/context/compare?run=run&left="+left.ID+"&right="+right.ID, nil))
	var diff SnapshotComparison
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &diff) != nil || diff.Status != "different" || strings.Contains(w.Body.String(), "sk-"+strings.Repeat("a", 40)) {
		t.Fatalf("unsafe response: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.ReadHandler().ServeHTTP(w, httptest.NewRequest("GET", "/context/compare?run=run&left="+left.ID, nil))
	if w.Code != 400 {
		t.Fatalf("missing right accepted: %d", w.Code)
	}
}
