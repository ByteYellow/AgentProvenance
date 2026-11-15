package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/capturemanifest"
)

func TestCaptureManifestAPIKeepsAuthenticationAndEnglishErrors(t *testing.T) {
	s := testServer(t)
	s.AuthToken = "fixture-manifest-token"
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	for _, tc := range []struct {
		query, token string
		status       int
	}{{"?run=r", "", 401}, {"?run=r", s.AuthToken, 200}, {"?run=r&limit=0", s.AuthToken, 400}, {"?run=r&run=other", s.AuthToken, 400}} {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/capture-manifest"+tc.query, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept-Language", "zh-CN")
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s: %d %+v", tc.query, resp.StatusCode, body)
		}
		if tc.status != 401 && (err != nil || body["schema_version"] != capturemanifest.SchemaVersion) {
			t.Fatalf("response: %+v %v", body, err)
		}
		if tc.status == 400 {
			problem := body["error"].(map[string]any)
			if problem["code"] != "invalid_argument" {
				t.Fatalf("translated error: %+v", problem)
			}
			for _, c := range problem["message"].(string) {
				if c > 127 {
					t.Fatal("non-English protocol message")
				}
			}
		}
	}
}
