package observability

import (
	"context"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestCaptureSettingsSavedChoicesAndUnknownHistory(t *testing.T) {
	db, paths := coverageDB(t)
	ctx := context.Background()
	db.SetMaxOpenConns(1)
	if got, err := ReadCaptureSettings(ctx, db, "old"); err != nil || got != nil {
		t.Fatalf("historical settings: %+v %v", got, err)
	}
	yes, no := true, false
	settings := CaptureSettings{Version: CaptureSettingsVersion, Source: "launch", SensorMode: "off",
		WorkspaceSnapshot: &no, TLSFullBody: &no, AgentContext: &yes}
	for i := 0; i < 2; i++ {
		if err := SaveCaptureSettings(ctx, db, paths, "run", settings); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AGENTPROV_TLS_CAPTURE_BODY", "1")
	got, err := ReadCaptureSettings(ctx, db, "run")
	if err != nil || got == nil || got.Ref == "" || *got.WorkspaceSnapshot || *got.TLSFullBody || !*got.AgentContext || got.SensorMode != "off" {
		t.Fatalf("saved settings changed on query: %+v %v", got, err)
	}
	settings.TLSFullBody = &yes
	if err := SaveCaptureSettings(ctx, db, paths, "run", settings); err == nil {
		t.Fatal("allowed changing capture settings on the same run")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id='run' AND object_type='run_capture_settings'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("settings count %d: %v", count, err)
	}
	settings.WorkspaceSnapshot = nil
	if err := SaveCaptureSettings(ctx, db, paths, "missing", settings); err == nil {
		t.Fatal("missing setting treated as false")
	}
}

func TestCaptureSettingsInvalidEvidenceDoesNotBecomeDisabled(t *testing.T) {
	for _, scenario := range []string{"missing-fields", "conflicting", "unreadable"} {
		t.Run(scenario, func(t *testing.T) {
			db, paths := coverageDB(t)
			objects := provenance.ObjectStore{DB: db, Paths: paths}
			payload := map[string]any{"version": CaptureSettingsVersion, "source": "launch", "sensor_mode": "auto",
				"workspace_snapshot": false, "tls_full_body": true, "agent_context": true}
			if scenario == "missing-fields" {
				delete(payload, "tls_full_body")
			}
			if _, err := objects.PutExternalObject(provenance.ExternalObjectInput{RunID: "run", Type: "run_capture_settings", SourceID: "one", Payload: payload}); err != nil {
				t.Fatal(err)
			}
			if scenario == "conflicting" {
				payload["tls_full_body"] = false
				if _, err := objects.PutExternalObject(provenance.ExternalObjectInput{RunID: "run", Type: "run_capture_settings", SourceID: "two", Payload: payload}); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "unreadable" {
				if _, err := db.Exec(`UPDATE provenance_objects SET path='missing' WHERE run_id='run'`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ReadCaptureSettings(context.Background(), db, "run"); err == nil {
				t.Fatal("invalid settings silently accepted")
			}
		})
	}
}
