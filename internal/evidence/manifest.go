package evidence

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
)

const ManifestSchemaVersion = "agentprovenance.evidence_manifest/v1"

type ManifestOptions struct {
	RunID       string
	ObjectLimit int
}

type MaterializedManifest struct {
	Manifest   Manifest `json:"manifest"`
	ObjectHash string   `json:"object_hash,omitempty"`
	ObjectPath string   `json:"object_path,omitempty"`
}

type Manifest struct {
	SchemaVersion    string                  `json:"schema_version"`
	RunID            string                  `json:"run_id"`
	ResultSetID      string                  `json:"result_set_id"`
	PageHash         string                  `json:"page_hash"`
	QueryRefs        []ManifestQueryRef      `json:"query_refs,omitempty"`
	Summary          observability.Summary   `json:"summary"`
	Timeline         ManifestTimelineRef     `json:"timeline"`
	Objects          ManifestObjectSummary   `json:"objects"`
	Security         ManifestSecuritySummary `json:"security"`
	RecommendedViews []string                `json:"recommended_views"`
}

type ManifestTimelineRef struct {
	SchemaVersion string             `json:"schema_version"`
	EventCount    int                `json:"event_count"`
	ResultSetID   string             `json:"result_set_id"`
	PageHash      string             `json:"page_hash"`
	LaneCounts    map[string]int     `json:"lane_counts,omitempty"`
	QueryRefs     []ManifestQueryRef `json:"query_refs"`
}

type ManifestObjectSummary struct {
	SchemaVersion string              `json:"schema_version"`
	ObjectCount   int                 `json:"object_count"`
	HasMore       bool                `json:"has_more"`
	NextCursor    string              `json:"next_cursor,omitempty"`
	ResultSetID   string              `json:"result_set_id"`
	PageHash      string              `json:"page_hash"`
	TotalBytes    int64               `json:"total_bytes"`
	ByType        map[string]int      `json:"by_type"`
	TopRefs       []ManifestObjectRef `json:"top_refs,omitempty"`
}

type ManifestObjectRef struct {
	Hash      string `json:"hash"`
	Type      string `json:"type"`
	SourceID  string `json:"source_id"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
}

type ManifestSecuritySummary struct {
	RisksResultSetID     string `json:"risks_result_set_id,omitempty"`
	RisksPageHash        string `json:"risks_page_hash,omitempty"`
	RiskCount            int    `json:"risk_count"`
	ResponsesResultSetID string `json:"responses_result_set_id,omitempty"`
	ResponsesPageHash    string `json:"responses_page_hash,omitempty"`
	ResponseCount        int    `json:"response_count"`
}

type ManifestQueryRef struct {
	Kind          string `json:"kind"`
	SchemaVersion string `json:"schema_version,omitempty"`
	Command       string `json:"command"`
	ResultSetID   string `json:"result_set_id,omitempty"`
	PageHash      string `json:"page_hash,omitempty"`
	HasMore       bool   `json:"has_more,omitempty"`
	NextCursor    string `json:"next_cursor,omitempty"`
}

func BuildManifest(db *sql.DB, opts ManifestOptions) (Manifest, error) {
	if db == nil {
		return Manifest{}, fmt.Errorf("database is required")
	}
	if opts.RunID == "" {
		return Manifest{}, fmt.Errorf("run_id is required")
	}
	if opts.ObjectLimit <= 0 {
		opts.ObjectLimit = 25
	}
	summary, err := observability.BuildSummary(db, observability.SummaryOptions{RunID: opts.RunID})
	if err != nil {
		return Manifest{}, err
	}
	timeline, err := provenance.BuildTimeline(db, provenance.TimelineOptions{RunID: opts.RunID})
	if err != nil {
		return Manifest{}, err
	}
	objects, err := provenance.ListObjectsPage(db, provenance.ObjectListOptions{RunID: opts.RunID, Limit: opts.ObjectLimit})
	if err != nil {
		return Manifest{}, err
	}
	risks, err := securitymodel.BuildRiskSignalsReport(db, opts.RunID)
	if err != nil {
		return Manifest{}, err
	}
	responses, err := securitymodel.BuildResponseActionsReport(db, opts.RunID)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion,
		RunID:         opts.RunID,
		Summary:       summary,
		Timeline: ManifestTimelineRef{
			SchemaVersion: timeline.SchemaVersion,
			EventCount:    timeline.EventCount,
			ResultSetID:   timeline.ResultSetID,
			PageHash:      timeline.PageHash,
			LaneCounts:    timeline.Summary.LaneCounts,
			QueryRefs: []ManifestQueryRef{
				queryRef("timeline", timeline.SchemaVersion, "timeline --run "+opts.RunID+" --json", timeline.ResultSetID, timeline.PageHash, timeline.HasMore, timeline.NextCursor),
				{Kind: "causality_timeline", Command: "timeline --run " + opts.RunID + " --view causality --json"},
			},
		},
		Objects:          summarizeObjects(objects),
		Security:         ManifestSecuritySummary{RisksResultSetID: risks.ResultSetID, RisksPageHash: risks.PageHash, RiskCount: risks.Count, ResponsesResultSetID: responses.ResultSetID, ResponsesPageHash: responses.PageHash, ResponseCount: responses.Count},
		RecommendedViews: append([]string{}, summary.RecommendedViews...),
	}
	manifest.QueryRefs = []ManifestQueryRef{
		queryRef("observability_summary", summary.SchemaVersion, "observe summary --run "+opts.RunID+" --json", summary.ResultSetID, summary.PageHash, false, ""),
		queryRef("timeline", timeline.SchemaVersion, "timeline --run "+opts.RunID+" --json", timeline.ResultSetID, timeline.PageHash, timeline.HasMore, timeline.NextCursor),
		queryRef("objects", objects.SchemaVersion, "graph objects --run "+opts.RunID+" --limit "+fmt.Sprint(opts.ObjectLimit)+" --json", objects.ResultSetID, objects.PageHash, objects.HasMore, objects.NextCursor),
		queryRef("security_risks", "agentprovenance.risk_signals/v1", "security risks --run "+opts.RunID+" --json", risks.ResultSetID, risks.PageHash, false, ""),
		queryRef("security_responses", "agentprovenance.response_actions/v1", "security responses --run "+opts.RunID+" --json", responses.ResultSetID, responses.PageHash, false, ""),
	}
	manifest.RecommendedViews = append(manifest.RecommendedViews,
		"evidence manifest --run "+opts.RunID+" --json",
		"graph objects --run "+opts.RunID+" --json",
		"graph verify --run "+opts.RunID+" --json",
	)
	if err := finalizeManifestIntegrity(&manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func queryRef(kind, schemaVersion, command, resultSetID, pageHash string, hasMore bool, nextCursor string) ManifestQueryRef {
	return ManifestQueryRef{
		Kind:          kind,
		SchemaVersion: schemaVersion,
		Command:       command,
		ResultSetID:   resultSetID,
		PageHash:      pageHash,
		HasMore:       hasMore,
		NextCursor:    nextCursor,
	}
}

func summarizeObjects(objects provenance.ObjectListManifest) ManifestObjectSummary {
	summary := ManifestObjectSummary{
		SchemaVersion: objects.SchemaVersion,
		ObjectCount:   objects.ObjectCount,
		HasMore:       objects.HasMore,
		NextCursor:    objects.NextCursor,
		ResultSetID:   objects.ResultSetID,
		PageHash:      objects.PageHash,
		ByType:        map[string]int{},
	}
	for _, object := range objects.Objects {
		summary.ByType[object.Type]++
		summary.TotalBytes += object.SizeBytes
		summary.TopRefs = append(summary.TopRefs, ManifestObjectRef{
			Hash:      object.Hash,
			Type:      object.Type,
			SourceID:  object.SourceID,
			Path:      object.Path,
			SizeBytes: object.SizeBytes,
		})
	}
	return summary
}

func finalizeManifestIntegrity(manifest *Manifest) error {
	if manifest == nil {
		return nil
	}
	resultSetID, err := digestManifest(map[string]any{
		"kind":                    "evidence_manifest_result_set",
		"schema_version":          manifest.SchemaVersion,
		"run_id":                  manifest.RunID,
		"summary_result_set_id":   manifest.Summary.ResultSetID,
		"timeline_result_set_id":  manifest.Timeline.ResultSetID,
		"objects_result_set_id":   manifest.Objects.ResultSetID,
		"risks_result_set_id":     manifest.Security.RisksResultSetID,
		"responses_result_set_id": manifest.Security.ResponsesResultSetID,
		"query_refs":              queryRefIntegrity(manifest.QueryRefs),
	})
	if err != nil {
		return err
	}
	pageHash, err := digestManifest(map[string]any{
		"kind":              "evidence_manifest_page",
		"result_set_id":     resultSetID,
		"run_id":            manifest.RunID,
		"summary_page_hash": manifest.Summary.PageHash,
		"timeline":          manifest.Timeline,
		"objects":           manifest.Objects,
		"security":          manifest.Security,
		"query_refs":        manifest.QueryRefs,
		"views":             sortedStrings(manifest.RecommendedViews),
	})
	if err != nil {
		return err
	}
	manifest.ResultSetID = resultSetID
	manifest.PageHash = pageHash
	return nil
}

func queryRefIntegrity(refs []ManifestQueryRef) []map[string]string {
	out := make([]map[string]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, map[string]string{
			"kind":          ref.Kind,
			"schema":        ref.SchemaVersion,
			"result_set_id": ref.ResultSetID,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i]["kind"] == out[j]["kind"] {
			return out[i]["result_set_id"] < out[j]["result_set_id"]
		}
		return out[i]["kind"] < out[j]["kind"]
	})
	return out
}

func digestManifest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func sortedStrings(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}
