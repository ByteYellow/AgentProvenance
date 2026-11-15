package capturemanifest

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// Handler must remain behind the daemon authentication or Dashboard read guard.
func (s Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fail := func(status int, code, message string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": SchemaVersion, "error": map[string]string{"code": code, "message": message}})
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			fail(405, "method_not_allowed", "Use GET to read saved capture capabilities.")
			return
		}
		q, limit := r.URL.Query(), 50
		for key, values := range q {
			if (key != "run" && key != "cursor" && key != "limit") || len(values) != 1 {
				fail(400, "invalid_argument", "Unsupported or repeated capture manifest parameter.")
				return
			}
		}
		if q.Has("limit") {
			var err error
			limit, err = strconv.Atoi(q.Get("limit"))
			if err != nil || limit < 1 || limit > 200 {
				fail(400, "invalid_argument", "limit must be between 1 and 200.")
				return
			}
		}
		page, err := s.List(r.Context(), Options{RunID: q.Get("run"), Cursor: q.Get("cursor"), Limit: limit})
		if errors.Is(err, ErrInvalid) {
			fail(400, "invalid_argument", "A valid run and matching pagination cursor are required.")
			return
		}
		if err != nil {
			fail(500, "capture_evidence_read_failed", "Saved capture evidence could not be read or verified.")
			return
		}
		_ = json.NewEncoder(w).Encode(page)
	})
}
