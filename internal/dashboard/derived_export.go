package dashboard

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/derivedview"
)

const replayProjectionRule = "agentprov.offline_replay/v1"

type ReplaySignature struct {
	Kind       string `json:"kind"`
	ExporterID string `json:"exporter_id"`
	KeyID      string `json:"key_id"`
}

// ReplaySigner is operator configuration, never decoded from a browser request.
type ReplaySigner struct {
	ExporterID           string
	Key                  ed25519.PrivateKey
	ImplementationSHA256 string
}

// PrepareSignedOfflineReplaySet reuses the same frozen selection and reader as
// unsigned exports. Its source commitment carries no source database or key.
func (s Server) PrepareSignedOfflineReplaySet(ctx context.Context, inputs []ReplaySelection, signer ReplaySigner) (_ *PreparedReplay, err error) {
	if signer.ExporterID == "" || len(signer.Key) != ed25519.PrivateKeySize || len(signer.ImplementationSHA256) != 64 {
		return nil, fmt.Errorf("derived export requires an exporter ID, Ed25519 key and implementation SHA256")
	}
	inputs, err = normalizeReplaySelections(inputs)
	if err != nil {
		return nil, err
	}
	snapshot, err := s.freezeReplaySource(ctx)
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	source, err := ReplayImplementationDigest(ctx, filepath.Join(snapshot.root, "snapshot.db"))
	if err != nil {
		return nil, err
	}
	p, err := s.prepareReplaySet(ctx, snapshot, inputs)
	if err != nil {
		return nil, err
	}
	if err := p.signDerived(ctx, source, signer); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

// ReplayImplementationDigest hashes a fixed file with bounded memory. The CLI
// uses its running executable; export preparation also uses it for the snapshot.
func ReplayImplementationDigest(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.Read(buf)
		if n != 0 {
			_, _ = h.Write(buf[:n])
		}
		if err == io.EOF {
			return hex.EncodeToString(h.Sum(nil)), nil
		}
		if err != nil {
			return "", err
		}
	}
}

func (p *PreparedReplay) signDerived(ctx context.Context, source string, signer ReplaySigner) error {
	if signer.ExporterID == "" || len(signer.Key) != ed25519.PrivateKeySize || len(signer.ImplementationSHA256) != 64 {
		return fmt.Errorf("derived export requires an exporter ID, Ed25519 key and implementation SHA256")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var inventory ReplayInventory
	if err := json.Unmarshal(p.inventory, &inventory); err != nil {
		return err
	}
	pub := signer.Key.Public().(ed25519.PublicKey)
	inventory.Signed = true
	if inventory.DeliveryMode != DeliveryOriginals {
		inventory.DeliveryMode = DeliveryDerived
	}
	inventory.Signature = &ReplaySignature{Kind: "derived_view", ExporterID: signer.ExporterID, KeyID: attest.KeyID(pub)}
	raw, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}
	m := derivedview.Manifest{
		Sources:   []derivedview.Source{{ID: "frozen-source", Kind: "sqlite_snapshot_commitment", Digest: derivedview.Reference{SHA256: source}}},
		Selection: derivedview.Reference{Path: inventory.Selection.Path, SHA256: inventory.Selection.SHA256},
		Projection: derivedview.Rules{Version: replayProjectionRule,
			SHA256:               attest.DigestSHA256([]byte("frozen_sqlite_selection;selected_reader_indexes;retained_content_only;no_implicit_related_runs/v1")),
			ImplementationSHA256: signer.ImplementationSHA256},
		Coverage: derivedview.Coverage{State: derivedview.CoverageUnknown, Scope: inventory.Scope},
		Exporter: derivedview.Exporter{ID: signer.ExporterID}, CreatedAt: inventory.CreatedAt,
	}
	if p.coverage.State != "" {
		m.Coverage = p.coverage
		m.Coverage.Scope = inventory.Scope
	}
	for _, original := range inventory.Originals {
		m.Sources = append(m.Sources, derivedview.Source{ID: original.ID, Kind: "forensics_bundle",
			Digest:    derivedview.Reference{Path: original.Bundle.Path, SHA256: original.Bundle.SHA256},
			Signature: &derivedview.Reference{Path: original.Attestation.Path, SHA256: original.Attestation.SHA256}})
	}
	for _, f := range inventory.Files {
		m.Files = append(m.Files, derivedview.File{Path: f.Path, SHA256: f.SHA256, Bytes: f.Bytes})
	}
	m.Files = append(m.Files, derivedview.File{Path: "export-inventory.json", SHA256: replayDigest(raw), Bytes: int64(len(raw))})
	reasons := map[string]int{}
	add := func(s ReplaySelectionSummary) {
		for reason, count := range s.Reasons {
			reasons[reason] += count
		}
	}
	if inventory.SelectionSummary != nil {
		add(*inventory.SelectionSummary)
	}
	for _, run := range inventory.Runs {
		add(run.SelectionSummary)
	}
	for reason, count := range reasons {
		m.Exclusions = append(m.Exclusions, derivedview.Gap{Category: "records", Reason: reason, Count: int64(count)})
	}
	sort.Slice(m.Exclusions, func(i, j int) bool { return m.Exclusions[i].Reason < m.Exclusions[j].Reason })
	manifest, signature, err := derivedview.Sign(m, signer.Key)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		raw  []byte
	}{
		{"export-inventory.json", raw}, {derivedview.ManifestPath, manifest}, {derivedview.SignaturePath, signature},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(p.root, f.name), f.raw, 0600); err != nil {
			return err
		}
		if f.name != "export-inventory.json" {
			p.signatureFiles = append(p.signatureFiles, ReplayFile{Path: f.name, SHA256: replayDigest(f.raw), Bytes: int64(len(f.raw))})
		}
	}
	p.Inventory, p.inventory, p.InventorySHA256 = inventory, raw, replayDigest(raw)
	return nil
}
