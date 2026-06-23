package baseline

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

type Profile struct {
	ID                string
	TemplateName      string
	ExecCount         int64
	NetworkEventCount int64
	PolicyBlockCount  int64
	ActiveCPUSeconds  float64
	Features          FeatureVector
	Payload           string
	Status            string
	CreatedAt         string
}

type FeatureVector struct {
	ExecCount              int64   `json:"exec_count"`
	ProcessObservedCount   int64   `json:"process_observed_count"`
	OutlivedRootCount      int64   `json:"outlived_root_count"`
	FileOpenCount          int64   `json:"file_open_count"`
	FileWriteCount         int64   `json:"file_write_count"`
	SecretPathCount        int64   `json:"secret_path_count"`
	NetworkEventCount      int64   `json:"network_event_count"`
	MetadataIPCount        int64   `json:"metadata_ip_count"`
	PrivateCIDRCount       int64   `json:"private_cidr_count"`
	PolicyBlockCount       int64   `json:"policy_block_count"`
	ActiveCPUSeconds       float64 `json:"active_cpu_seconds"`
	RuntimeEventCount      int64   `json:"runtime_event_count"`
	SuspiciousRuntimeCount int64   `json:"suspicious_runtime_count"`
}

type DeviationRecord struct {
	ID                string  `json:"id"`
	RunID             string  `json:"run_id"`
	TemplateName      string  `json:"template_name"`
	ProfileID         string  `json:"profile_id"`
	DeviationType     string  `json:"deviation_type"`
	Status            string  `json:"status"`
	ExpectedValue     float64 `json:"expected_value"`
	ObservedValue     float64 `json:"observed_value"`
	RecommendedAction string  `json:"recommended_action"`
	Payload           string  `json:"payload"`
	CreatedAt         string  `json:"created_at"`
}

type DeviationQuery struct {
	Drilldowns []string `json:"drilldowns"`
}

type DeviationView struct {
	Deviation DeviationRecord `json:"deviation"`
	Query     DeviationQuery  `json:"query"`
}

type DeviationsReport struct {
	SchemaVersion string          `json:"schema_version"`
	RunID         string          `json:"run_id,omitempty"`
	ResultSetID   string          `json:"result_set_id"`
	PageHash      string          `json:"page_hash"`
	Count         int             `json:"count"`
	Deviations    []DeviationView `json:"deviations"`
}

func Learn(db *sql.DB, templateName, runID string) (Profile, error) {
	if templateName == "" || runID == "" {
		return Profile{}, fmt.Errorf("template and run are required")
	}
	features, err := ExtractFeatures(db, runID)
	if err != nil {
		return Profile{}, err
	}
	payload, _ := json.Marshal(features)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	profile := Profile{
		ID:                ids.New("base"),
		TemplateName:      templateName,
		ExecCount:         features.ExecCount,
		NetworkEventCount: features.NetworkEventCount,
		PolicyBlockCount:  features.PolicyBlockCount,
		ActiveCPUSeconds:  features.ActiveCPUSeconds,
		Features:          features,
		Payload:           string(payload),
		Status:            "ready",
		CreatedAt:         now,
	}
	_, err = db.Exec(`INSERT INTO baseline_profiles (id, template_name, exec_count, network_event_count, policy_block_count, active_cpu_seconds, payload, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, profile.ID, profile.TemplateName, profile.ExecCount, profile.NetworkEventCount, profile.PolicyBlockCount, profile.ActiveCPUSeconds, profile.Payload, profile.Status, profile.CreatedAt)
	return profile, err
}

func Check(db *sql.DB, templateName, runID string) (string, []string, error) {
	profile, err := latestProfile(db, templateName)
	if err != nil {
		return "", nil, err
	}
	current, err := currentProfile(db, templateName, runID)
	if err != nil {
		return "", nil, err
	}
	var deviations []string
	records := []DeviationRecord{}
	checks := []struct {
		name     string
		expected float64
		observed float64
		delta    float64
		ratio    float64
		action   string
	}{
		{"exec_count", float64(profile.Features.ExecCount), float64(current.Features.ExecCount), 3, 2, "audit"},
		{"process_observed_count", float64(profile.Features.ProcessObservedCount), float64(current.Features.ProcessObservedCount), 3, 2, "audit"},
		{"outlived_root_count", float64(profile.Features.OutlivedRootCount), float64(current.Features.OutlivedRootCount), 0, 1, "review"},
		{"file_write_count", float64(profile.Features.FileWriteCount), float64(current.Features.FileWriteCount), 5, 2, "audit"},
		{"secret_path_count", float64(profile.Features.SecretPathCount), float64(current.Features.SecretPathCount), 0, 1, "review"},
		{"network_event_count", float64(profile.Features.NetworkEventCount), float64(current.Features.NetworkEventCount), 2, 2, "audit"},
		{"metadata_ip_count", float64(profile.Features.MetadataIPCount), float64(current.Features.MetadataIPCount), 0, 1, "review"},
		{"private_cidr_count", float64(profile.Features.PrivateCIDRCount), float64(current.Features.PrivateCIDRCount), 0, 1, "review"},
		{"policy_block_count", float64(profile.Features.PolicyBlockCount), float64(current.Features.PolicyBlockCount), 0, 1, "review"},
		{"suspicious_runtime_count", float64(profile.Features.SuspiciousRuntimeCount), float64(current.Features.SuspiciousRuntimeCount), 0, 1, "review"},
	}
	for _, check := range checks {
		if deviates(check.expected, check.observed, check.delta, check.ratio) {
			deviations = append(deviations, check.name)
			records = append(records, deviationRecord(runID, templateName, profile.ID, check.name, check.expected, check.observed, check.action))
		}
	}
	if profile.Features.ActiveCPUSeconds > 0 && current.Features.ActiveCPUSeconds > profile.Features.ActiveCPUSeconds*2 {
		deviations = append(deviations, "active_cpu_seconds")
		records = append(records, deviationRecord(runID, templateName, profile.ID, "active_cpu_seconds", profile.Features.ActiveCPUSeconds, current.Features.ActiveCPUSeconds, "audit"))
	}
	if len(deviations) == 0 {
		return "normal", deviations, nil
	}
	if err := persistDeviations(db, records); err != nil {
		return "", nil, err
	}
	return "anomalous", deviations, nil
}

func ListDeviations(db *sql.DB, runID string) ([]DeviationRecord, error) {
	query := `SELECT id, run_id, template_name, profile_id, deviation_type, status, expected_value, observed_value,
		recommended_action, payload, created_at FROM baseline_deviations`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []DeviationRecord
	for rows.Next() {
		var record DeviationRecord
		if err := rows.Scan(&record.ID, &record.RunID, &record.TemplateName, &record.ProfileID, &record.DeviationType, &record.Status, &record.ExpectedValue, &record.ObservedValue, &record.RecommendedAction, &record.Payload, &record.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func BuildDeviationsReport(db *sql.DB, runID string) (DeviationsReport, error) {
	records, err := ListDeviations(db, runID)
	if err != nil {
		return DeviationsReport{}, err
	}
	views := make([]DeviationView, 0, len(records))
	for _, record := range records {
		views = append(views, DeviationView{Deviation: record, Query: DeviationQuery{Drilldowns: deviationDrilldowns(record)}})
	}
	report := DeviationsReport{
		SchemaVersion: "agentprovenance.security_deviations/v1",
		RunID:         runID,
		Count:         len(views),
		Deviations:    views,
	}
	resultSetID, pageHash, err := deviationReportIntegrity(runID, views)
	if err == nil {
		report.ResultSetID = resultSetID
		report.PageHash = pageHash
	}
	return report, nil
}

func deviationDrilldowns(record DeviationRecord) []string {
	return []string{
		"timeline --run " + record.RunID + " --type baseline_deviation --json",
		"timeline --run " + record.RunID + " --view causality",
		"observe summary --run " + record.RunID + " --json",
	}
}

func deviationReportIntegrity(runID string, items []DeviationView) (string, string, error) {
	resultSetID, err := digestDeviation(map[string]any{
		"kind":   "security_deviations_result_set",
		"run_id": runID,
		"items":  items,
	})
	if err != nil {
		return "", "", err
	}
	pageHash, err := digestDeviation(map[string]any{
		"kind":          "security_deviations_page",
		"result_set_id": resultSetID,
		"items":         items,
	})
	if err != nil {
		return "", "", err
	}
	return resultSetID, pageHash, nil
}

func digestDeviation(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func deviationRecord(runID, templateName, profileID, deviationType string, expected, observed float64, action string) DeviationRecord {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if action == "" {
		action = "audit"
	}
	return DeviationRecord{
		ID:                ids.New("dev"),
		RunID:             runID,
		TemplateName:      templateName,
		ProfileID:         profileID,
		DeviationType:     deviationType,
		Status:            "anomalous",
		ExpectedValue:     expected,
		ObservedValue:     observed,
		RecommendedAction: action,
		Payload:           fmt.Sprintf(`{"deviation_type":%q,"expected":%.6f,"observed":%.6f,"recommended_action":%q}`, deviationType, expected, observed, action),
		CreatedAt:         now,
	}
}

func persistDeviations(db *sql.DB, records []DeviationRecord) error {
	for _, record := range records {
		if _, err := db.Exec(`INSERT INTO baseline_deviations
			(id, run_id, template_name, profile_id, deviation_type, status, expected_value, observed_value, recommended_action, payload, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			record.ID, record.RunID, record.TemplateName, record.ProfileID, record.DeviationType, record.Status,
			record.ExpectedValue, record.ObservedValue, record.RecommendedAction, record.Payload, record.CreatedAt); err != nil {
			return err
		}
		severity := "medium"
		if record.RecommendedAction == "review" {
			severity = "high"
		}
		riskID := ids.New("risk")
		if _, err := db.Exec(`INSERT INTO risk_signals
			(id, run_id, signal_type, severity, reason, recommended_action, payload, created_at)
			VALUES (?, ?, 'baseline_deviation', ?, ?, ?, ?, ?)`,
			riskID, record.RunID, severity, record.DeviationType, record.RecommendedAction, record.Payload, record.CreatedAt); err != nil {
			return err
		}
		_, _ = db.Exec(`INSERT OR REPLACE INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
			VALUES (?, ?, ?, ?, 'baseline_deviation_risk_signal', ?)`,
			ids.New("edge"), record.RunID, "baseline_deviation/"+record.ID, "risk_signal/"+riskID, record.CreatedAt)
	}
	return nil
}

func latestProfile(db *sql.DB, templateName string) (Profile, error) {
	var p Profile
	err := db.QueryRow(`SELECT id, template_name, exec_count, network_event_count, policy_block_count, active_cpu_seconds, COALESCE(payload, '{}'), status, created_at
		FROM baseline_profiles WHERE template_name = ? ORDER BY created_at DESC LIMIT 1`, templateName).
		Scan(&p.ID, &p.TemplateName, &p.ExecCount, &p.NetworkEventCount, &p.PolicyBlockCount, &p.ActiveCPUSeconds, &p.Payload, &p.Status, &p.CreatedAt)
	if err == nil {
		p.Features = decodeFeatures(p.Payload, p)
	}
	return p, err
}

func currentProfile(db *sql.DB, templateName, runID string) (Profile, error) {
	features, err := ExtractFeatures(db, runID)
	if err != nil {
		return Profile{}, err
	}
	payload, _ := json.Marshal(features)
	p := Profile{TemplateName: templateName, Features: features, Payload: string(payload)}
	p.ExecCount = features.ExecCount
	p.NetworkEventCount = features.NetworkEventCount
	p.PolicyBlockCount = features.PolicyBlockCount
	p.ActiveCPUSeconds = features.ActiveCPUSeconds
	return p, nil
}

func ExtractFeatures(db *sql.DB, runID string) (FeatureVector, error) {
	var f FeatureVector
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type IN ('exec_start', 'execve', 'call')`, runID).Scan(&f.ExecCount); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'process_observed'`, runID).Scan(&f.ProcessObservedCount); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'file_open'`, runID).Scan(&f.FileOpenCount); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'file_write'`, runID).Scan(&f.FileWriteCount); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'secret_path'`, runID).Scan(&f.SecretPathCount); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type IN ('network_connect', 'metadata_ip', 'private_cidr')`, runID).Scan(&f.NetworkEventCount); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'metadata_ip'`, runID).Scan(&f.MetadataIPCount); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'private_cidr'`, runID).Scan(&f.PrivateCIDRCount); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_decisions WHERE run_id = ? AND decision != 'allow'`, runID).Scan(&f.PolicyBlockCount); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COALESCE(SUM(active_cpu_seconds), 0) FROM cost_samples WHERE run_id = ?`, runID).Scan(&f.ActiveCPUSeconds); err != nil {
		return f, err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ?`, runID).Scan(&f.RuntimeEventCount); err != nil {
		return f, err
	}
	f.SuspiciousRuntimeCount = f.SecretPathCount + f.MetadataIPCount + f.PrivateCIDRCount + f.PolicyBlockCount
	outlived, err := countOutlivedRoot(db, runID)
	if err != nil {
		return f, err
	}
	f.OutlivedRootCount = outlived
	return f, nil
}

func countOutlivedRoot(db *sql.DB, runID string) (int64, error) {
	rows, err := db.Query(`SELECT payload FROM events WHERE run_id = ? AND event_type = 'process_observed'`, runID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return 0, err
		}
		var body struct {
			OutlivedRoot bool `json:"outlived_root"`
		}
		if json.Unmarshal([]byte(payload), &body) == nil && body.OutlivedRoot {
			count++
		}
	}
	return count, rows.Err()
}

func decodeFeatures(payload string, fallback Profile) FeatureVector {
	var f FeatureVector
	if json.Unmarshal([]byte(payload), &f) != nil {
		f.ExecCount = fallback.ExecCount
		f.NetworkEventCount = fallback.NetworkEventCount
		f.PolicyBlockCount = fallback.PolicyBlockCount
		f.ActiveCPUSeconds = fallback.ActiveCPUSeconds
		return f
	}
	if f == (FeatureVector{}) && (fallback.ExecCount != 0 || fallback.NetworkEventCount != 0 || fallback.PolicyBlockCount != 0 || fallback.ActiveCPUSeconds != 0) {
		f.ExecCount = fallback.ExecCount
		f.NetworkEventCount = fallback.NetworkEventCount
		f.PolicyBlockCount = fallback.PolicyBlockCount
		f.ActiveCPUSeconds = fallback.ActiveCPUSeconds
	}
	return f
}

func deviates(expected, observed, delta, ratio float64) bool {
	if observed <= expected {
		return false
	}
	if expected == 0 {
		return observed > delta
	}
	return observed > expected+delta || observed > expected*ratio
}
