package baseline

import (
	"database/sql"
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
	Status            string
	CreatedAt         string
}

type DeviationRecord struct {
	ID                string
	RunID             string
	TemplateName      string
	ProfileID         string
	DeviationType     string
	Status            string
	ExpectedValue     float64
	ObservedValue     float64
	RecommendedAction string
	Payload           string
	CreatedAt         string
}

func Learn(db *sql.DB, templateName, runID string) (Profile, error) {
	if templateName == "" || runID == "" {
		return Profile{}, fmt.Errorf("template and run are required")
	}
	var execCount, networkCount, blockCount int64
	var activeCPU float64
	_ = db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type IN ('exec_start', 'call')`, runID).Scan(&execCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'network_connect'`, runID).Scan(&networkCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM policy_decisions WHERE run_id = ? AND decision != 'allow'`, runID).Scan(&blockCount)
	_ = db.QueryRow(`SELECT COALESCE(SUM(active_cpu_seconds), 0) FROM cost_samples WHERE run_id = ?`, runID).Scan(&activeCPU)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	profile := Profile{
		ID:                ids.New("base"),
		TemplateName:      templateName,
		ExecCount:         execCount,
		NetworkEventCount: networkCount,
		PolicyBlockCount:  blockCount,
		ActiveCPUSeconds:  activeCPU,
		Status:            "ready",
		CreatedAt:         now,
	}
	_, err := db.Exec(`INSERT INTO baseline_profiles (id, template_name, exec_count, network_event_count, policy_block_count, active_cpu_seconds, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, profile.ID, profile.TemplateName, profile.ExecCount, profile.NetworkEventCount, profile.PolicyBlockCount, profile.ActiveCPUSeconds, profile.Status, profile.CreatedAt)
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
	if current.NetworkEventCount > profile.NetworkEventCount+2 {
		deviations = append(deviations, "network_event_count")
		records = append(records, deviationRecord(runID, templateName, profile.ID, "network_event_count", float64(profile.NetworkEventCount), float64(current.NetworkEventCount)))
	}
	if current.PolicyBlockCount > profile.PolicyBlockCount {
		deviations = append(deviations, "policy_block_count")
		records = append(records, deviationRecord(runID, templateName, profile.ID, "policy_block_count", float64(profile.PolicyBlockCount), float64(current.PolicyBlockCount)))
	}
	if profile.ActiveCPUSeconds > 0 && current.ActiveCPUSeconds > profile.ActiveCPUSeconds*2 {
		deviations = append(deviations, "active_cpu_seconds")
		records = append(records, deviationRecord(runID, templateName, profile.ID, "active_cpu_seconds", profile.ActiveCPUSeconds, current.ActiveCPUSeconds))
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

func deviationRecord(runID, templateName, profileID, deviationType string, expected, observed float64) DeviationRecord {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return DeviationRecord{
		ID:                ids.New("dev"),
		RunID:             runID,
		TemplateName:      templateName,
		ProfileID:         profileID,
		DeviationType:     deviationType,
		Status:            "anomalous",
		ExpectedValue:     expected,
		ObservedValue:     observed,
		RecommendedAction: "audit",
		Payload:           fmt.Sprintf(`{"deviation_type":%q,"expected":%.6f,"observed":%.6f}`, deviationType, expected, observed),
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
	}
	return nil
}

func latestProfile(db *sql.DB, templateName string) (Profile, error) {
	var p Profile
	err := db.QueryRow(`SELECT id, template_name, exec_count, network_event_count, policy_block_count, active_cpu_seconds, status, created_at
		FROM baseline_profiles WHERE template_name = ? ORDER BY created_at DESC LIMIT 1`, templateName).
		Scan(&p.ID, &p.TemplateName, &p.ExecCount, &p.NetworkEventCount, &p.PolicyBlockCount, &p.ActiveCPUSeconds, &p.Status, &p.CreatedAt)
	return p, err
}

func currentProfile(db *sql.DB, templateName, runID string) (Profile, error) {
	p := Profile{TemplateName: templateName}
	_ = db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type IN ('exec_start', 'call')`, runID).Scan(&p.ExecCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'network_connect'`, runID).Scan(&p.NetworkEventCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM policy_decisions WHERE run_id = ? AND decision != 'allow'`, runID).Scan(&p.PolicyBlockCount)
	_ = db.QueryRow(`SELECT COALESCE(SUM(active_cpu_seconds), 0) FROM cost_samples WHERE run_id = ?`, runID).Scan(&p.ActiveCPUSeconds)
	return p, nil
}
