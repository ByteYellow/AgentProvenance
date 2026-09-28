package agentcontext

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

// ReadHandler is shared by the local dashboard and daemon. It only resolves
// registered objects within the requested run; it never accepts disk paths.
func (s Service) ReadHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /context/overview", s.httpOverview)
	mux.HandleFunc("GET /context/entries", s.httpEntries)
	mux.HandleFunc("GET /context/content", s.httpContent)
	mux.HandleFunc("GET /context/compare", s.httpCompare)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		run := r.URL.Query().Get("run")
		if run == "" || len(run) > 512 {
			contextError(w, 400, "invalid_argument", "A run id is required.")
			return
		}
		var exists bool
		err := s.DB.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM provenance_objects WHERE run_id=?
			UNION ALL SELECT 1 FROM events WHERE run_id=? UNION ALL SELECT 1 FROM sessions WHERE run_id=?
			UNION ALL SELECT 1 FROM tool_calls WHERE run_id=? UNION ALL SELECT 1 FROM rollouts WHERE run_id=?)`, run, run, run, run, run).Scan(&exists)
		if err != nil {
			contextError(w, 503, "store_unavailable", "The evidence store is unavailable.")
			return
		}
		if !exists {
			contextError(w, 404, "run_not_found", "The run was not found.")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s Service) httpCompare(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	value, err := s.CompareSnapshots(r.Context(), q.Get("run"), q.Get("left"), q.Get("right_run"), q.Get("right"))
	contextResult(w, value, err)
}

func contextError(w http.ResponseWriter, code int, kind, message string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": SchemaVersion, "error": map[string]string{"code": kind, "message": message}})
}

func contextResult(w http.ResponseWriter, value any, err error) {
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidArgument), errors.Is(err, provenance.ErrContentRange):
			contextError(w, 400, "invalid_argument", err.Error())
		case errors.Is(err, sql.ErrNoRows):
			contextError(w, 404, "content_not_found", "Recorded content was not found in this run.")
		default:
			contextError(w, 500, "evidence_read_failed", "The stored evidence could not be read or verified.")
		}
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}

func (s Service) httpOverview(w http.ResponseWriter, r *http.Request) {
	value, err := s.Overview(r.Context(), r.URL.Query().Get("run"))
	contextResult(w, value, err)
}

func (s Service) httpEntries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if q.Get("limit") != "" {
		n, err := strconv.Atoi(q.Get("limit"))
		if err != nil || n < 1 || n > 200 {
			contextError(w, 400, "invalid_argument", "limit must be between 1 and 200.")
			return
		}
		limit = n
	}
	revisions := false
	if q.Get("revisions") != "" {
		v, err := strconv.ParseBool(q.Get("revisions"))
		if err != nil {
			contextError(w, 400, "invalid_argument", "revisions must be a boolean.")
			return
		}
		revisions = v
	}
	value, err := s.Entries(r.Context(), PageOptions{RunID: q.Get("run"), SourceID: q.Get("source"), SessionID: q.Get("session"),
		Kind: q.Get("kind"), ToolCallID: q.Get("tool_call"), Cursor: q.Get("cursor"), Limit: limit, IncludeRevisions: revisions})
	contextResult(w, value, err)
}

func (s Service) httpContent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset, limit := int64(0), 64<<10
	if q.Get("offset") != "" {
		n, err := strconv.ParseInt(q.Get("offset"), 10, 64)
		if err != nil || n < 0 {
			contextError(w, 400, "invalid_argument", "offset must be a nonnegative byte offset.")
			return
		}
		offset = n
	}
	if q.Get("limit") != "" {
		n, err := strconv.Atoi(q.Get("limit"))
		if err != nil || n < 4 || n > provenance.MaxContentPageBytes {
			contextError(w, 400, "invalid_argument", "limit must be between 4 and 262144 bytes.")
			return
		}
		limit = n
	}
	if len(q.Get("ref")) != 71 {
		contextError(w, 400, "invalid_argument", "A stored content hash is required.")
		return
	}
	value, err := provenance.ReadTextContentPage(s.DB, q.Get("run"), q.Get("ref"), offset, int64(limit))
	contextResult(w, value, err)
}
