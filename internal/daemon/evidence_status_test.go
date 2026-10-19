package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestBindingAPIConfidence(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        float64
		status      int
	}{
		{"default", "", .5, 200}, {"zero", `,"confidence":0`, 0, 200},
		{"fraction", `,"confidence":0.25`, .25, 200}, {"null", `,"confidence":null`, 0, 400},
		{"negative", `,"confidence":-0.1`, 0, 400}, {"high", `,"confidence":1.1`, 0, 400},
		{"wrong_type", `,"confidence":"0"`, 0, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/telemetry/bind", strings.NewReader(`{"run_id":"r","process_id":"p","binding_source":"ai_asserted"`+tc.field+`}`)))
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			bindings, err := correlation.ListBindings(s.DB, correlation.BindingFilter{RunID: "r"})
			if err != nil {
				t.Fatal(err)
			}
			if tc.status != 200 {
				if len(bindings) != 0 {
					t.Fatalf("invalid input saved: %+v", bindings)
				}
				return
			}
			if len(bindings) != 1 || bindings[0].Confidence != tc.want {
				t.Fatalf("bindings=%+v", bindings)
			}
		})
	}
}

func TestGraphVerifyAPIUnavailable(t *testing.T) {
	s := testServer(t)
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/graph/verify?run=r", nil))
	var result provenance.VerifyResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusServiceUnavailable || result.Status != "unavailable" || result.Error == "" || result.IssueCount != 0 {
		t.Fatalf("status=%d result=%+v", w.Code, result)
	}
}
