package agentcontext

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const relationCacheBytes = 8 << 20
const relationCacheEntries = 1024

// SessionRelationReader reuses verified payloads within one immutable export
// database. It must not be shared between exports or used for live HTTP queries.
// Catalog queries, discovery limits, identity checks and pagination remain fresh.
type SessionRelationReader struct {
	service  Service
	payloads relationPayloadCache
}

func (s Service) NewSessionRelationReader() *SessionRelationReader {
	return &SessionRelationReader{service: s, payloads: relationPayloadCache{
		load: func(run, hash string, target any) error {
			return provenance.ReadObjectPayload(s.DB, run, hash, target)
		},
	}}
}

func (r *SessionRelationReader) SessionRelations(ctx context.Context, opts SessionRelationOptions) (SessionRelationsPage, error) {
	return r.service.sessionRelations(ctx, opts, r.payloads.read)
}

type relationPayloadKey struct{ run, hash string }

type relationPayloadCache struct {
	mu     sync.Mutex
	load   func(string, string, any) error
	values map[relationPayloadKey]json.RawMessage
	bytes  int
}

func (c *relationPayloadCache) read(run, hash string, target any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := relationPayloadKey{run, hash}
	raw, cached := c.values[key]
	if !cached {
		if err := c.load(run, hash, &raw); err != nil {
			return err
		}
	}
	// Decode independently so a caller cannot mutate another session's data.
	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}
	cost := len(run) + len(hash) + len(raw)
	if !cached && len(c.values) < relationCacheEntries && cost <= relationCacheBytes-c.bytes {
		if c.values == nil {
			c.values = map[relationPayloadKey]json.RawMessage{}
		}
		c.values[key] = append(json.RawMessage(nil), raw...)
		c.bytes += cost
	}
	return nil
}
