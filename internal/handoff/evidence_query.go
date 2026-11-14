package handoff

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const ExecutionLinksSchema = "agentprovenance.execution_links/v1"

type EvidenceService struct{ DB *sql.DB }

type ExecutionLink struct {
	Identity     ExecutionIdentity `json:"identity"`
	AdmissionRef string            `json:"admission_ref"`
	Admission    *SourceAdmission  `json:"admission,omitempty"`
	DeliveryRef  string            `json:"delivery_ref,omitempty"`
	Manifest     *DeliveryManifest `json:"manifest,omitempty"`
	Receipt      *DeliveryReceipt  `json:"receipt,omitempty"`
	Checkpoint   *Checkpoint       `json:"checkpoint,omitempty"`
	Basis        string            `json:"basis"`
	Issues       []string          `json:"issues"`
}

type ExecutionLinksPage struct {
	SchemaVersion string          `json:"schema_version"`
	RunID         string          `json:"run_id"`
	Direction     string          `json:"direction"`
	Links         []ExecutionLink `json:"links"`
	Scanned       int             `json:"scanned"`
	Limit         int             `json:"limit"`
	HasMore       bool            `json:"has_more"`
	NextCursor    string          `json:"next_cursor,omitempty"`
}

type ExecutionLinksOptions struct {
	RunID, Direction, Harness, SessionID, ToolCallID, Cursor string
	Limit                                                    int
}

type executionLinksCursor struct{ Query, Source, Hash string }
type executionEvidenceRef struct{ source, hash string }

// Links projects immutable admissions and signed deliveries in a read snapshot.
// Each incoming attempt uses its latest saved delivery, not its latest timestamp.
func (s EvidenceService) Links(ctx context.Context, opts ExecutionLinksOptions) (ExecutionLinksPage, error) {
	page := ExecutionLinksPage{SchemaVersion: ExecutionLinksSchema, RunID: opts.RunID, Links: []ExecutionLink{}}
	if opts.Direction == "" {
		opts.Direction = "outgoing"
	}
	if opts.Limit == 0 {
		opts.Limit = 50
	}
	page.Direction, page.Limit = opts.Direction, opts.Limit
	if !validID(opts.RunID) || opts.Limit < 1 || opts.Limit > 100 || (opts.Direction != "outgoing" && opts.Direction != "incoming") {
		return page, fmt.Errorf("%w: run, direction or page limit", ErrInvalid)
	}
	for _, filter := range []string{opts.Harness, opts.SessionID, opts.ToolCallID} {
		if filter != "" && !validID(filter) {
			return page, fmt.Errorf("%w: native identity filter", ErrInvalid)
		}
	}
	fingerprint := digest(ExecutionLinksSchema, opts.RunID, opts.Direction, opts.Harness, opts.SessionID, opts.ToolCallID)
	cursor := executionLinksCursor{Query: fingerprint}
	if opts.Cursor != "" {
		if len(opts.Cursor) > 4096 {
			return page, fmt.Errorf("%w: cursor too long", ErrInvalid)
		}
		raw, err := base64.RawURLEncoding.DecodeString(opts.Cursor)
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Query != fingerprint ||
			len(cursor.Source) > 128 || !strings.HasPrefix(cursor.Hash, "sha256:") || !validDigest(strings.TrimPrefix(cursor.Hash, "sha256:")) {
			return page, fmt.Errorf("%w: cursor does not match query", ErrInvalid)
		}
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	kind := `o.object_type='execution_source_admission'`
	if opts.Direction == "incoming" {
		kind = `o.object_type='execution_delivery_evidence' AND NOT EXISTS (
			SELECT 1 FROM provenance_objects n WHERE n.run_id=o.run_id AND n.object_type='execution_delivery_evidence'
			AND n.source_id>o.source_id AND n.source_id<substr(o.source_id,1,64)||'/~')`
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.source_id,o.hash FROM provenance_objects o WHERE o.run_id=? AND `+kind+`
		AND (o.source_id,o.hash)>(?,?) ORDER BY o.source_id,o.hash LIMIT ?`, opts.RunID, cursor.Source, cursor.Hash, opts.Limit+1)
	if err != nil {
		return page, err
	}
	refs := []executionEvidenceRef{}
	for rows.Next() {
		var ref executionEvidenceRef
		if err := rows.Scan(&ref.source, &ref.hash); err != nil {
			rows.Close()
			return page, err
		}
		refs = append(refs, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	if len(refs) > opts.Limit {
		page.HasMore = true
		refs = refs[:opts.Limit]
	}
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		var link ExecutionLink
		if opts.Direction == "outgoing" {
			link, err = outgoingExecutionLink(ctx, tx, opts.RunID, ref.hash)
		} else {
			link, err = incomingExecutionLink(ctx, tx, opts.RunID, ref.hash)
		}
		if err != nil {
			return page, err
		}
		page.Scanned++
		cursor.Source, cursor.Hash = ref.source, ref.hash
		src := link.Identity.Source
		if (opts.Harness == "" || opts.Harness == src.Harness) && (opts.SessionID == "" || opts.SessionID == src.SessionID) &&
			(opts.ToolCallID == "" || opts.ToolCallID == src.ToolCallID) {
			page.Links = append(page.Links, link)
		}
	}
	if page.HasMore {
		raw, _ := json.Marshal(cursor)
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, tx.Commit()
}

func outgoingExecutionLink(ctx context.Context, tx *sql.Tx, run, ref string) (ExecutionLink, error) {
	a, err := readSourceAdmission(ctx, tx, run, ref)
	if err != nil {
		return ExecutionLink{}, err
	}
	link := ExecutionLink{Identity: a.Identity, AdmissionRef: ref, Admission: &a, Basis: "authenticated_admission", Issues: []string{}}
	prefix := strings.TrimPrefix(ref, "sha256:") + "/"
	var proofRef string
	err = tx.QueryRowContext(ctx, `SELECT hash FROM provenance_objects WHERE run_id=? AND object_type='execution_delivery_evidence'
		AND source_id>=? AND source_id<? ORDER BY source_id DESC,hash LIMIT 1`, a.Identity.LocalRunID, prefix, prefix+"~").Scan(&proofRef)
	if errors.Is(err, sql.ErrNoRows) {
		link.Issues = append(link.Issues, "delivery_evidence_not_recorded")
		return link, nil
	}
	if err != nil {
		return link, err
	}
	return incomingExecutionLink(ctx, tx, a.Identity.LocalRunID, proofRef)
}

func incomingExecutionLink(ctx context.Context, tx *sql.Tx, run, ref string) (ExecutionLink, error) {
	link := ExecutionLink{DeliveryRef: ref, Issues: []string{}}
	var p DeliveryEvidence
	if err := provenance.ReadObjectPayload(tx, run, ref, &p); err != nil {
		return link, err
	}
	m, r, err := p.verify()
	if err != nil {
		return link, err
	}
	if m.Identity.LocalRunID != run {
		return link, fmt.Errorf("%w: delivery evidence run mismatch", ErrConflict)
	}
	var kind, source string
	if err := tx.QueryRowContext(ctx, `SELECT object_type,source_id FROM provenance_objects WHERE run_id=? AND hash=?`, run, ref).Scan(&kind, &source); err != nil {
		return link, err
	}
	if kind != deliveryEvidenceType || source != deliveryEvidenceID(p.AdmissionRef, m.PackageVersion) {
		return link, fmt.Errorf("%w: delivery evidence index mismatch", ErrConflict)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='execution_delivery_evidence' AND source_id=?`, run, source).Scan(&count); err != nil {
		return link, err
	}
	if count != 1 {
		return link, fmt.Errorf("%w: conflicting delivery evidence", ErrConflict)
	}
	link.Identity, link.AdmissionRef, link.Manifest, link.Receipt = m.Identity, p.AdmissionRef, &m, &r
	a, err := readSourceAdmission(ctx, tx, m.Identity.Source.RunID, p.AdmissionRef)
	if errors.Is(err, sql.ErrNoRows) {
		link.Basis = "unanchored_delivery"
		link.Issues = append(link.Issues, "source_admission_not_included")
	} else if err != nil {
		return link, err
	} else {
		if !p.matchesAdmission(a, m) {
			return link, fmt.Errorf("%w: delivery does not match source admission", ErrConflict)
		}
		link.Admission, link.Basis = &a, "authenticated_delivery"
	}
	var checkpoint Checkpoint
	if err := provenance.ReadObjectPayload(tx, run, m.CheckpointRef, &checkpoint); errors.Is(err, sql.ErrNoRows) {
		link.Issues = append(link.Issues, "checkpoint_not_included")
	} else if err != nil {
		return link, err
	} else {
		if !checkpointMatchesManifest(checkpoint, m) {
			return link, fmt.Errorf("%w: checkpoint does not match delivery", ErrConflict)
		}
		link.Checkpoint = &checkpoint
	}
	return link, ctx.Err()
}

func checkpointMatchesManifest(c Checkpoint, m DeliveryManifest) bool {
	return c.SchemaVersion == SchemaVersion && c.Source == m.Identity.Source && c.Target == m.Identity.Target &&
		c.AttemptID == m.Identity.AttemptID && c.DispatchID == m.Identity.DispatchID && c.RequestHash == m.Identity.RequestHash &&
		c.DigestVersion == m.Identity.DigestVersion && c.Revision >= 1 && c.Revision <= m.AttemptRevision &&
		c.State.Execution == m.State.Execution && c.State.Capture == m.State.Capture
}
