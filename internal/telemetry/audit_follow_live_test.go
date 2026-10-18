//go:build linux

package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveAuditFileFollow(t *testing.T) {
	path := os.Getenv("AGENTPROV_AUDIT_FOLLOW_INPUT")
	if path == "" {
		t.Skip("set AGENTPROV_AUDIT_FOLLOW_INPUT to previously captured live journal JSON")
	}
	input, err := os.ReadFile(path)
	if err != nil || len(input) == 0 || len(input) > 2<<20 || input[len(input)-1] != '\n' {
		t.Fatalf("invalid live input: bytes=%d err=%v", len(input), err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 4096), MaxAuditLineBytes)
	records := map[string]bool{}
	lines := 0
	for scanner.Scan() {
		r, ok, err := ParseAuditLine(scanner.Bytes(), AuditSource{})
		if err != nil || !ok || r.RecordID == "" || r.SourceFormat != "journal_json" {
			t.Fatalf("expected independently identified journal audit record: %+v %v", r, err)
		}
		records[r.RecordID] = true
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	// Split inside a record, then append while the follower is waiting.
	split := strings.IndexByte(string(input), '\n') / 2
	db, paths, opts := auditFollowFixture(t, string(input[:split]))
	opts.Source, opts.RetainRaw, opts.Once, opts.PollInterval = AuditSource{}, true, false, 50*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	appended := false
	status, err := FollowAuditFile(ctx, db, paths, opts, func(s AuditFollowStatus) error {
		if s.Reader.Status == "waiting" && s.Reader.Reason == "partial_record" && !appended {
			appended = true
			appendAuditFixture(t, opts.Path, string(input[split:]))
		}
		if s.Reader.Read == lines {
			cancel()
		}
		return nil
	})
	if err != nil || !appended || status.Reader.Read != lines || status.Reader.Ingested != len(records) || status.Reader.IdentityIncomplete != 0 || status.Reader.CommittedOffset != int64(len(input)) {
		t.Fatalf("live append follow: %+v %v", status, err)
	}
	opts.Once = true
	resumed := followAuditOnce(t, db, paths, opts)
	if resumed.Reader.Read != status.Reader.Read || resumed.Reader.Batches != status.Reader.Batches {
		t.Fatalf("restart replayed consumed journal input: %+v", resumed)
	}
	if err := os.Rename(opts.Path, opts.Path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.Path, input, 0600); err != nil {
		t.Fatal(err)
	}
	rotated, err := FollowAuditFile(context.Background(), db, paths, opts, nil)
	if err == nil || rotated.Reader.Reason != "source_replaced" || rotated.Reader.CommittedOffset != status.Reader.CommittedOffset {
		t.Fatalf("rotation changed source checkpoint: %+v %v", rotated, err)
	}
	data, err := json.MarshalIndent(map[string]any{"source": path, "captured_records": len(records), "follow": status, "resumed": resumed, "rotation": rotated}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	saveLiveAuditFixture(t, "audit-file-follow.json", data)
	t.Logf("followed %d actual journal records; partial append, restart and rotation diagnostics passed", len(records))
}
