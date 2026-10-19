package telemetry

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestAuditHTTPContractAndFailureStates(t *testing.T) {
	db, _ := nativeTestStore(t)
	a := auditInputFixture(t)
	line := a.record.RawRecord.Text
	if _, err := IngestAuditReader(context.Background(), db, AuditIngestOptions{RunID: "run", Source: a.record.AuditSource},
		strings.NewReader(line+"\n"+strings.Replace(line, ":130)", ":131)", 1))); err != nil {
		t.Fatal(err)
	}
	storeAuditRuntimeFixtures(t, db, auditRuntimeSet(), "run")
	h := AuditAssociationsHandler(db)
	get := func(query string, status int) AuditAssociationReport {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/?"+query, nil)
		r.Header.Set("Accept-Language", "zh-CN")
		h.ServeHTTP(w, r)
		if w.Code != status || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %s", query, w.Code, w.Body.String())
		}
		var result AuditAssociationReport
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if status != 200 && strings.Contains(w.Body.String(), `"items"`) {
			t.Fatal("failure returned a successful empty report")
		}
		if status != 200 {
			for _, ch := range w.Body.String() {
				if ch > 127 {
					t.Fatal("generated API error was localized")
				}
			}
		}
		return result
	}
	want, err := BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: "run", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	first := get("run=run&limit=1", 200)
	if !reflect.DeepEqual(want, first) || first.Items[0].Operations[0].Result == nil || *first.Items[0].Operations[0].Result != 0 {
		t.Fatalf("HTTP changed inference or zero return: %+v", first)
	}
	second := get("run=run&limit=1&cursor="+url.QueryEscape(first.NextCursor), 200)
	if len(second.Items) != 1 || second.HasMore || second.Items[0].EventID == first.Items[0].EventID {
		t.Fatal("pagination repeated or omitted evidence")
	}
	one := get("run=run&event="+url.QueryEscape(first.Items[0].EventID), 200)
	if len(one.Items) != 1 || !reflect.DeepEqual(one.Items[0], first.Items[0]) {
		t.Fatal("single-event filter changed evidence")
	}
	for _, q := range []string{"", "run=", "run=run&limit=0", "run=run&limit=501", "run=run&limit=1.5", "run=run&limit=", "run=run&limit=+1", "run=run&run=other", "run=run&session=x", "run=run&harness=claude", "run=run&cursor=bad", "run=run&event=%ZZ", "run=run;limit=1", "run=other&cursor=" + first.NextCursor, "run=run&event=other&cursor=" + first.NextCursor} {
		get(q, 400)
	}
	if len(get("run=empty", 200).Items) != 0 {
		t.Fatal("another run leaked into query")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	get("run=run", 503)
}
