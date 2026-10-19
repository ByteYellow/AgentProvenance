package agentcontext

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const (
	sessionEnumerationPageSize    = 200
	sessionEnumerationMaxSources  = 1000000
	sessionEnumerationMaxSessions = 10000
)

var ErrSessionEnumerationLimit = errors.New("session enumeration resource limit exceeded")

// SessionIdentity is namespaced by harness, not by source/channel or run.
type SessionIdentity struct {
	Harness   string `json:"harness"`
	SessionID string `json:"session_id"`
}

type SessionEnumerationOptions struct {
	RunID string
	// Zero uses the fixed resource budget. Callers may lower, never raise it.
	MaxSources, MaxSessions int
}

const latestSessionReport = `NOT EXISTS (SELECT 1 FROM agent_context_reports n
	WHERE n.run_id=r.run_id AND n.source_id=r.source_id
	AND (n.created_at,n.id)>(r.created_at,r.id))`

const sessionEnumerationPageSQL = `SELECT r.id,r.source_id,r.harness,r.session_id,r.object_hash
	FROM agent_context_reports r WHERE r.run_id=? AND ` + latestSessionReport + `
	AND r.source_id>? ORDER BY r.source_id LIMIT ?`

// EnumerateSessions walks latest source reports in bounded keyset pages and
// verifies their immutable identities before deduplicating native sessions.
// Export callers must use their already frozen (and selected) database for this
// entire operation and for all subsequent indexes. Overview is only a summary.
// Errors return no partial catalog, including cancellation and budget exhaustion.
func (s Service) EnumerateSessions(ctx context.Context, opts SessionEnumerationOptions) ([]SessionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.RunID == "" || len(opts.RunID) > 512 || opts.MaxSources < 0 || opts.MaxSources > sessionEnumerationMaxSources || opts.MaxSessions < 0 || opts.MaxSessions > sessionEnumerationMaxSessions {
		return nil, fmt.Errorf("%w: invalid session enumeration identity or budget", ErrInvalidArgument)
	}
	if opts.MaxSources == 0 {
		opts.MaxSources = sessionEnumerationMaxSources
	}
	if opts.MaxSessions == 0 {
		opts.MaxSessions = sessionEnumerationMaxSessions
	}
	var expected int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
		SELECT 1 FROM agent_context_reports r WHERE r.run_id=? AND `+latestSessionReport+` LIMIT ?
	)`, opts.RunID, opts.MaxSources+1).Scan(&expected); err != nil {
		return nil, err
	}
	if expected > opts.MaxSources {
		return nil, fmt.Errorf("%w: more than %d sources", ErrSessionEnumerationLimit, opts.MaxSources)
	}
	type sourceRef struct{ id, source, harness, session, hash string }
	seen := map[SessionIdentity]bool{}
	cursor, actual := "", 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Keep the range predicate unconditional so SQLite seeks to the cursor.
		// An invalid empty source ID is caught by final count reconciliation.
		rows, err := s.DB.QueryContext(ctx, sessionEnumerationPageSQL, opts.RunID, cursor, sessionEnumerationPageSize)
		if err != nil {
			return nil, err
		}
		refs := []sourceRef{}
		for rows.Next() {
			var ref sourceRef
			if err := rows.Scan(&ref.id, &ref.source, &ref.harness, &ref.session, &ref.hash); err != nil {
				rows.Close()
				return nil, err
			}
			refs = append(refs, ref)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if len(refs) == 0 {
			break
		}
		for _, ref := range refs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			actual++
			if actual > opts.MaxSources {
				return nil, fmt.Errorf("%w: more than %d sources", ErrSessionEnumerationLimit, opts.MaxSources)
			}
			var c Coverage
			if err := provenance.ReadObjectPayload(s.DB, opts.RunID, ref.hash, &c); err != nil {
				return nil, err
			}
			if c.SchemaVersion != SchemaVersion || c.ID != ref.id || c.RunID != opts.RunID || c.Source.ID == "" || c.Source.ID != ref.source || c.Source.Harness != ref.harness || c.Source.SessionID != ref.session {
				return nil, fmt.Errorf("session enumeration source identity mismatch: %s", ref.source)
			}
			if !nativeSession(c.Source) {
				continue
			}
			if len(c.Source.Harness) > 128 || len(c.Source.SessionID) > 512 {
				return nil, fmt.Errorf("%w: session enumeration identity too long", ErrInvalidArgument)
			}
			seen[SessionIdentity{Harness: c.Source.Harness, SessionID: c.Source.SessionID}] = true
			if len(seen) > opts.MaxSessions {
				return nil, fmt.Errorf("%w: more than %d sessions", ErrSessionEnumerationLimit, opts.MaxSessions)
			}
		}
		next := refs[len(refs)-1].source
		if next <= cursor {
			return nil, fmt.Errorf("session enumeration cursor did not advance")
		}
		cursor = next
	}
	if actual != expected {
		return nil, fmt.Errorf("session enumeration source count mismatch: expected %d, read %d", expected, actual)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sessions := make([]SessionIdentity, 0, len(seen))
	for identity := range seen {
		sessions = append(sessions, identity)
	}
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].Harness != sessions[j].Harness {
			return sessions[i].Harness < sessions[j].Harness
		}
		return sessions[i].SessionID < sessions[j].SessionID
	})
	return sessions, nil
}
