package handoff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errPublicationBusy = errors.New("delivery publication is active")

type publicationLease struct {
	dir, lock *os.File
}

func (p *publicationLease) Close() error {
	return errors.Join(p.lock.Close(), p.dir.Close())
}

type PublicationCleanup struct {
	Scanned        int   `json:"scanned"`
	Removed        int   `json:"removed"`
	Failed         int   `json:"failed"`
	Busy           bool  `json:"busy"`
	ReclaimedBytes int64 `json:"reclaimed_bytes"`
}

// ReconcilePublications removes abandoned sender staging and unreferenced
// packages. A shared publication lease spans staging through SQL commit; this
// exclusive lease waits for neither an active publisher nor a receipt.
func (s *DeliveryService) ReconcilePublications(ctx context.Context, limit int) (PublicationCleanup, error) {
	var result PublicationCleanup
	if err := s.validate(); err != nil {
		return result, err
	}
	if limit < 1 || limit > 1000 {
		return result, fmt.Errorf("publication cleanup limit must be between 1 and 1000")
	}
	root := filepath.Join(s.Paths.Artifacts, "execution-deliveries")
	lease, err := acquirePublication(ctx, root, true)
	if errors.Is(err, os.ErrNotExist) {
		return result, ctx.Err()
	}
	if errors.Is(err, errPublicationBusy) {
		result.Busy = true
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer lease.Close()
	var failures []error
	for {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		entries, readErr := lease.dir.ReadDir(64)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return result, errors.Join(append(failures, readErr)...)
		}
		for _, entry := range entries {
			name := entry.Name()
			staging := strings.HasPrefix(name, ".prepare-") && name != ".prepare-"
			if !staging && !(strings.HasPrefix(name, "package-") && name != "package-") {
				continue
			}
			result.Scanned++
			dir := filepath.Join(root, name)
			// Check every registered path, including other receivers/generations.
			// The range uses the path index and also protects nested staging paths.
			var referenced bool
			if err := s.Ledger.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM execution_deliveries
				WHERE bundle_path>=? AND bundle_path<?)`, dir+"/", dir+"0").Scan(&referenced); err != nil {
				return result, errors.Join(append(failures, err)...)
			}
			if referenced {
				continue
			}
			var removed int64
			if staging {
				removed, err = removePublicationStaging(ctx, lease.dir, name)
			} else {
				removed, err = removeDeliveryPackageAt(ctx, lease.dir, name)
			}
			result.ReclaimedBytes += removed
			if err != nil {
				result.Failed++
				// Keep error reporting bounded even when many abandoned entries are
				// damaged. Continue so one bad directory does not starve later work.
				if len(failures) < 8 {
					failures = append(failures, fmt.Errorf("publication %s: %w", name, err))
				}
			} else {
				result.Removed++
				if result.Removed == limit {
					return result, errors.Join(failures...)
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			return result, errors.Join(failures...)
		}
	}
}
