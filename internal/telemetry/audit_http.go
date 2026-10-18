package telemetry

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// ParseAuditAssociationQuery is shared by HTTP and tool callers. Reject unknown
// filters instead of silently returning evidence outside the requested scope.
func ParseAuditAssociationQuery(q url.Values) (AuditAssociationOptions, error) {
	opts := AuditAssociationOptions{RunID: q.Get("run"), EventID: q.Get("event"), Cursor: q.Get("cursor")}
	for key, values := range q {
		if (key != "run" && key != "event" && key != "limit" && key != "cursor") || len(values) != 1 {
			return opts, fmt.Errorf("%w: unsupported or repeated parameter", ErrAuditAssociationQuery)
		}
	}
	if q.Has("limit") {
		value := q.Get("limit")
		for _, ch := range value {
			if ch < '0' || ch > '9' {
				return opts, fmt.Errorf("%w: limit must be an integer from 1 to 500", ErrAuditAssociationQuery)
			}
		}
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 500 {
			return opts, fmt.Errorf("%w: limit must be an integer from 1 to 500", ErrAuditAssociationQuery)
		}
		opts.Limit = limit
	}
	opts, _, err := validateAuditAssociationOptions(opts)
	return opts, err
}

func AuditAssociationsHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		q, err := url.ParseQuery(r.URL.RawQuery)
		var opts AuditAssociationOptions
		if err != nil {
			err = fmt.Errorf("%w: malformed query", ErrAuditAssociationQuery)
		} else {
			opts, err = ParseAuditAssociationQuery(q)
		}
		var report AuditAssociationReport
		if err == nil {
			report, err = BuildAuditAssociations(r.Context(), db, opts)
		}
		if err != nil {
			status, message := http.StatusServiceUnavailable, "audit association evidence unavailable"
			if errors.Is(err, ErrAuditAssociationQuery) {
				status, message = http.StatusBadRequest, err.Error()
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
			return
		}
		_ = json.NewEncoder(w).Encode(report)
	})
}
