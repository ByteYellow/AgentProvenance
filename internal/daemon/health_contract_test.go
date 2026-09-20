package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHealthQueueNullabilityMatchesOpenAPI31(t *testing.T) {
	data, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		OpenAPI    string `yaml:"openapi"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]yaml.Node `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.OpenAPI != "3.1.0" {
		t.Fatalf("expected OpenAPI 3.1, got %q", contract.OpenAPI)
	}
	for _, field := range []string{"queued_spool", "queued_spool_bytes"} {
		node := contract.Components.Schemas["DaemonHealth"].Properties[field]
		var property struct {
			Types    []string `yaml:"type"`
			Nullable *bool    `yaml:"nullable"`
		}
		if err := node.Decode(&property); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(property.Types, []string{"integer", "null"}) || property.Nullable != nil {
			t.Fatalf("%s must use the 3.1 integer/null union: %+v", field, property)
		}
	}
	for _, unavailable := range []bool{false, true} {
		s := testServer(t)
		if unavailable {
			if err := s.DB.Close(); err != nil {
				t.Fatal(err)
			}
		}
		for _, endpoint := range []string{"/v1/health", "/v1/ready"} {
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, endpoint, nil))
			wantStatus := http.StatusOK
			if unavailable {
				wantStatus = http.StatusServiceUnavailable
			}
			if w.Code != wantStatus {
				t.Fatalf("%s status=%d want=%d", endpoint, w.Code, wantStatus)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"queued_spool", "queued_spool_bytes"} {
				raw, present := body[field]
				if !present || (unavailable && string(raw) != "null") {
					t.Fatalf("%s unavailable=%v %s=%s", endpoint, unavailable, field, raw)
				}
				if !unavailable {
					var count int64
					if string(raw) == "null" || json.Unmarshal(raw, &count) != nil || count < 0 {
						t.Fatalf("%s must be a nonnegative integer when available: %s", field, raw)
					}
				}
			}
		}
	}
}
