package aitools

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func auditAssociationsTool() Tool {
	schema := objSchema(map[string]any{
		"run": strProp("run id"), "event": strProp("optional saved audit event id"),
		"cursor": strProp("next_cursor from the preceding page with the same run and event"),
		"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
	}, "run")
	schema["additionalProperties"] = false
	return Tool{
		Name: "get_audit_associations", InputSchema: schema,
		Description: "Read AppArmor/seccomp decisions and process/operation candidates from saved evidence. Keeps concurrent candidates ambiguous and distinguishes policy decisions from observed syscall outcomes. Does not change policy, bindings or evidence.",
		Run: func(db *sql.DB, in map[string]any) (any, error) {
			q := url.Values{}
			for key, raw := range in {
				if key == "limit" {
					var value string
					switch n := raw.(type) {
					case int:
						value = strconv.Itoa(n)
					case float64:
						value = strconv.FormatFloat(n, 'f', -1, 64)
					case json.Number:
						value = n.String()
					default:
						return nil, fmt.Errorf("%w: limit must be an integer", telemetry.ErrAuditAssociationQuery)
					}
					q.Set(key, value)
				} else {
					value, ok := raw.(string)
					if !ok {
						return nil, fmt.Errorf("%w: expected string parameter", telemetry.ErrAuditAssociationQuery)
					}
					q.Set(key, value)
				}
			}
			opts, err := telemetry.ParseAuditAssociationQuery(q)
			if err != nil {
				return nil, err
			}
			return telemetry.BuildAuditAssociations(context.Background(), db, opts)
		},
	}
}
