package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const (
	DeliveryReading   = "reading"
	DeliveryDerived   = "derived"
	DeliveryOriginals = "originals"
)

type ReplayDelivery struct {
	Mode                 string   `json:"mode,omitempty"`
	OriginalBundleIDs    []string `json:"original_bundle_ids,omitempty"`
	ConfirmOriginalScope bool     `json:"confirm_original_scope,omitempty"`
}

type ReplayOriginal struct {
	ID          string     `json:"id"`
	RunID       string     `json:"run_id"`
	Bundle      ReplayFile `json:"bundle"`
	Attestation ReplayFile `json:"attestation"`
}

func (d ReplayDelivery) normalized(signer *ReplaySigner) (ReplayDelivery, error) {
	invalid := func(message string) (ReplayDelivery, error) {
		return d, fmt.Errorf("%w: %s", agentcontext.ErrInvalidArgument, message)
	}
	if d.Mode == "" {
		d.Mode = DeliveryReading
		if signer != nil {
			d.Mode = DeliveryDerived
		}
	}
	if d.Mode != DeliveryReading && d.Mode != DeliveryDerived && d.Mode != DeliveryOriginals {
		return invalid("delivery mode must be reading, derived or originals")
	}
	if d.Mode != DeliveryReading && signer == nil {
		return invalid("this delivery mode requires an operator exporter key")
	}
	if d.Mode != DeliveryOriginals {
		if len(d.OriginalBundleIDs) != 0 || d.ConfirmOriginalScope {
			return invalid("original bundles require originals delivery mode")
		}
		return d, nil
	}
	if !d.ConfirmOriginalScope || len(d.OriginalBundleIDs) == 0 || len(d.OriginalBundleIDs) > maxReplayRuns {
		return invalid("select original bundle IDs and explicitly confirm their full content scope")
	}
	seen := map[string]bool{}
	for _, id := range d.OriginalBundleIDs {
		if id == "" || len(id) > 512 || seen[id] {
			return invalid("original bundle IDs must be nonempty and unique")
		}
		seen[id] = true
	}
	return d, nil
}

// Original readers are projected from the explicitly selected, frozen bundles,
// not a live run that may have collected more evidence since those were signed.
func (s Server) prepareOriginalReplay(ctx context.Context, inputs []ReplaySelection, delivery ReplayDelivery) (_ *PreparedReplay, err error) {
	inputs, err = normalizeReplaySelections(inputs)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, input := range inputs {
		if (&replaySelectionPlan{Selection: input}).partial() {
			return nil, fmt.Errorf("%w: originals delivery requires whole runs without exclusions; use derived for a selection", agentcontext.ErrInvalidArgument)
		}
		wanted[input.RunID] = true
	}
	if len(inputs) != len(delivery.OriginalBundleIDs) {
		return nil, fmt.Errorf("%w: select exactly one original bundle for each run", agentcontext.ErrInvalidArgument)
	}
	registered, err := s.freezeReplaySource(ctx)
	if err != nil {
		return nil, err
	}
	defer registered.Close()
	root, err := os.MkdirTemp("", "agentprov-original-reader-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	paths, err := store.Init(filepath.Join(root, "store"))
	if err != nil {
		return nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var originals []ReplayOriginal
	var total int64
	for _, id := range delivery.OriginalBundleIDs {
		var path, run, digest, status string
		var size int64
		err := registered.DB.QueryRowContext(ctx, `SELECT path,run_id,sha256,size_bytes,status FROM forensics_bundles WHERE id=?`, id).Scan(&path, &run, &digest, &size, &status)
		if err != nil {
			return nil, fmt.Errorf("original bundle %q: %w", id, err)
		}
		digestBytes, digestErr := hex.DecodeString(digest)
		if !wanted[run] || status != "ready" || digestErr != nil || len(digestBytes) != 32 || strings.ToLower(digest) != digest || size < 1 || size > forensics.MaxStrictBundleBytes || !strings.HasSuffix(path, ".json") {
			return nil, fmt.Errorf("%w: original bundle is unavailable or outside the selected run set", agentcontext.ErrInvalidArgument)
		}
		delete(wanted, run)
		bundleName := "originals/" + digest + ".json"
		bundle, err := copyReplayOriginal(ctx, path, root, bundleName, forensics.MaxStrictBundleBytes)
		if err != nil {
			return nil, err
		}
		if bundle.SHA256 != digest || bundle.Bytes != size {
			return nil, fmt.Errorf("original bundle changed after registration")
		}
		attPath := strings.TrimSuffix(path, ".json") + ".dsse.json"
		signature, err := copyReplayOriginal(ctx, attPath, root, "originals/"+digest+".dsse.json", 64<<10)
		if err != nil {
			return nil, fmt.Errorf("original attestation: %w", err)
		}
		if err := originalStatement(filepath.Join(root, signature.Path), run, digest); err != nil {
			return nil, err
		}
		total += bundle.Bytes + signature.Bytes
		if total > 900<<20 {
			return nil, fmt.Errorf("original bundles exceed 900 MiB; select fewer runs")
		}
		// Imports only into this private, throw-away store. It validates bundle
		// scope, content hashes and stored paths; it does not execute evidence.
		if _, err := (forensics.Service{DB: db, Paths: paths}).ImportBundleStrict(ctx, filepath.Join(root, bundle.Path), run); err != nil {
			return nil, fmt.Errorf("original bundle projection: %w", err)
		}
		originals = append(originals, ReplayOriginal{ID: id, RunID: run, Bundle: bundle, Attestation: signature})
	}
	if len(wanted) != 0 {
		return nil, fmt.Errorf("original run set is incomplete")
	}
	frozen := Server{DB: db, RunLabels: s.RunLabels}
	snapshot, err := frozen.freezeReplaySource(ctx)
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	p, err := frozen.prepareReplaySet(ctx, snapshot, inputs)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	for _, original := range originals {
		for _, expected := range []ReplayFile{original.Bundle, original.Attestation} {
			file, err := copyReplayOriginal(ctx, filepath.Join(root, expected.Path), p.root, expected.Path, expected.Bytes)
			if err != nil {
				return nil, err
			}
			if file != expected {
				return nil, fmt.Errorf("frozen original changed during delivery")
			}
			p.Inventory.Files = append(p.Inventory.Files, file)
			p.Inventory.Bytes += file.Bytes
		}
	}
	if p.Inventory.Bytes > 1280<<20 {
		return nil, fmt.Errorf("offline delivery exceeds 1280 MiB")
	}
	p.Inventory.DeliveryMode, p.Inventory.Originals = DeliveryOriginals, originals
	sort.Slice(p.Inventory.Files, func(i, j int) bool { return p.Inventory.Files[i].Path < p.Inventory.Files[j].Path })
	if err = p.saveInventory(); err != nil {
		return nil, err
	}
	source, err := ReplayImplementationDigest(ctx, filepath.Join(snapshot.root, "snapshot.db"))
	if err != nil {
		return nil, err
	}
	if err = p.signDerived(ctx, source, *s.ReplaySigner); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *PreparedReplay) saveInventory() error {
	raw, err := json.MarshalIndent(p.Inventory, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(p.root, "export-inventory.json"), raw, 0600); err != nil {
		return err
	}
	p.inventory, p.InventorySHA256 = raw, replayDigest(raw)
	return nil
}

func copyReplayOriginal(ctx context.Context, source, root, name string, limit int64) (ReplayFile, error) {
	result := ReplayFile{Path: name}
	info, err := os.Lstat(source)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return result, fmt.Errorf("original must be a regular file within its size limit")
	}
	in, err := os.Open(source)
	if err != nil {
		return result, err
	}
	defer in.Close()
	current, err := in.Stat()
	if err != nil || !os.SameFile(info, current) {
		return result, fmt.Errorf("original file identity changed")
	}
	target := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return result, err
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, err
	}
	defer out.Close()
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := in.Read(buffer)
		if int64(n) > limit-result.Bytes {
			return result, fmt.Errorf("original grew beyond size limit")
		}
		if n > 0 {
			if _, err := out.Write(buffer[:n]); err != nil {
				return result, err
			}
			_, _ = hash.Write(buffer[:n])
			result.Bytes += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	if result.Bytes != info.Size() {
		return result, fmt.Errorf("original size changed")
	}
	if err := out.Close(); err != nil {
		return result, err
	}
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, nil
}

// Signature trust is checked independently by the recipient. Admission checks
// that the delivered attestation actually names the selected original bytes.
func originalStatement(path, run, digest string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.PayloadType != "application/vnd.in-toto+json" || len(envelope.Signatures) == 0 || len(envelope.Signatures) > 16 {
		return fmt.Errorf("original attestation has an invalid type or signature count")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return err
	}
	var statement attest.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return err
	}
	if statement.Type != attest.StatementType || statement.PredicateType != attest.DefaultPredicateType || len(statement.Subject) != 1 ||
		statement.Subject[0].Name != "forensics/"+run || statement.Subject[0].Digest["sha256"] != digest {
		return fmt.Errorf("original attestation does not name the selected bundle and run")
	}
	return nil
}
