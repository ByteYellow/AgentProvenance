package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/spf13/cobra"
)

func TestRecordJSONKeepsChildOutputSeparate(t *testing.T) {
	root := NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", t.TempDir(), "record", "--json", "--workdir", t.TempDir(), "--post-root-grace-ms", "1", "--", "sh", "-c", "printf 'CHILD-OUTPUT\n'; printf 'saved\n' > report.txt"})
	if err := root.Execute(); err != nil {
		t.Fatalf("record command: %v %s", err, stderr.String())
	}
	var got struct {
		ArtifactCapture record.ArtifactCaptureReport `json:"artifact_capture"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil || got.ArtifactCapture.Status != "ok" || got.ArtifactCapture.Stored != 1 {
		t.Fatalf("invalid machine result: %s (%v)", stdout.String(), err)
	}
	if !strings.Contains(stderr.String(), "CHILD-OUTPUT") {
		t.Fatal("child output was discarded instead of redirected")
	}
}

func TestRecordJSONPreservesArtifactCaptureState(t *testing.T) {
	zero := 0
	for _, report := range []record.ArtifactCaptureReport{
		{SchemaVersion: "agentprovenance.artifact_capture/v1", Status: "disabled"},
		{SchemaVersion: "agentprovenance.artifact_capture/v1", Status: "empty", Candidates: &zero},
		{SchemaVersion: "agentprovenance.artifact_capture/v1", Status: "failed", Issues: []string{"command_start_failed"}},
	} {
		t.Run(report.Status, func(t *testing.T) {
			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			if err := printRecordJSON(cmd, record.Result{RunID: "run", ArtifactCapture: report}); err != nil {
				t.Fatal(err)
			}
			var got struct {
				ArtifactCapture record.ArtifactCaptureReport `json:"artifact_capture"`
			}
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.ArtifactCapture.Status != report.Status || (got.ArtifactCapture.Candidates == nil) != (report.Candidates == nil) {
				t.Fatalf("capture state lost in CLI JSON: %s", out.String())
			}
		})
	}
}
