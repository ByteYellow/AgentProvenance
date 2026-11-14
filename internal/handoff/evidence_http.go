package handoff

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// ReadHandler exposes saved evidence, not remote execution control. The caller
// mounts it behind the existing dashboard origin guard or daemon authentication.
func (s EvidenceService) ReadHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fail := func(status int, code, message string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": ExecutionLinksSchema,
				"error": map[string]string{"code": code, "message": message}})
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			fail(405, "method_not_allowed", "Use GET to read saved execution links.")
			return
		}
		q := r.URL.Query()
		limit := 50
		if q.Has("limit") {
			var err error
			limit, err = strconv.Atoi(q.Get("limit"))
			if err != nil || limit < 1 || limit > 100 {
				fail(400, "invalid_argument", "limit must be between 1 and 100.")
				return
			}
		}
		page, err := s.Links(r.Context(), ExecutionLinksOptions{RunID: q.Get("run"), Direction: q.Get("direction"),
			Harness: q.Get("harness"), SessionID: q.Get("session"), ToolCallID: q.Get("tool_call"), Cursor: q.Get("cursor"), Limit: limit})
		if errors.Is(err, ErrInvalid) {
			fail(400, "invalid_argument", err.Error())
			return
		}
		if err != nil {
			fail(500, "evidence_read_failed", "Saved execution evidence could not be read or verified.")
			return
		}
		_ = json.NewEncoder(w).Encode(page)
	})
}
