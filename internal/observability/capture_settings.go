package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const CaptureSettingsVersion = "agentprovenance.capture_settings/v1"

// CaptureSettings records launch-owned options, not successful probe coverage.
// Unknown historical settings are absent; false is an explicitly saved choice.
type CaptureSettings struct {
	Version           string `json:"version"`
	Source            string `json:"source"`
	SensorMode        string `json:"sensor_mode"`
	WorkspaceSnapshot *bool  `json:"workspace_snapshot"`
	TLSFullBody       *bool  `json:"tls_full_body"`
	AgentContext      *bool  `json:"agent_context"`
	Ref               string `json:"ref,omitempty"`
}

func (s CaptureSettings) validate() error {
	if s.Version != CaptureSettingsVersion || s.Source != "launch" ||
		(s.SensorMode != "auto" && s.SensorMode != "off") ||
		s.WorkspaceSnapshot == nil || s.TLSFullBody == nil || s.AgentContext == nil {
		return fmt.Errorf("invalid recorded capture settings")
	}
	return nil
}

type captureSettingsReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func ReadCaptureSettings(ctx context.Context, db captureSettingsReader, run string) (*CaptureSettings, error) {
	rows, err := db.QueryContext(ctx, `SELECT hash FROM provenance_objects
		WHERE run_id=? AND object_type='run_capture_settings' LIMIT 2`, run)
	if err != nil {
		return nil, err
	}
	var refs []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			rows.Close()
			return nil, err
		}
		refs = append(refs, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(refs) == 0 {
		return nil, err
	}
	if len(refs) > 1 {
		return nil, fmt.Errorf("run has conflicting capture settings")
	}
	var settings CaptureSettings
	if err := provenance.ReadObjectPayload(db, run, refs[0], &settings); err != nil {
		return nil, err
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	settings.Ref = refs[0]
	return &settings, nil
}

// SaveCaptureSettings runs before launch starts any collector or workload. It
// stores only a fixed allowlist of options, never environment values or paths.
func SaveCaptureSettings(ctx context.Context, db *sql.DB, paths store.Paths, run string, settings CaptureSettings) error {
	if run == "" {
		return fmt.Errorf("capture settings require a run")
	}
	if err := settings.validate(); err != nil {
		return err
	}
	settings.Ref = ""
	return store.WithWriteTx(ctx, db, func(tx *sql.Tx) error {
		saved, err := ReadCaptureSettings(ctx, tx, run)
		if err != nil {
			return err
		}
		if saved != nil {
			saved.Ref = ""
			if !reflect.DeepEqual(*saved, settings) {
				return fmt.Errorf("capture settings are fixed for this run")
			}
			return nil
		}
		raw, err := json.Marshal(settings)
		if err != nil {
			return err
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		_, err = (provenance.ObjectStore{DB: db, Paths: paths, Tx: tx}).PutExternalObject(provenance.ExternalObjectInput{
			RunID: run, Type: "run_capture_settings", SourceID: "launch-capture/v1", Payload: payload,
		})
		return err
	})
}
