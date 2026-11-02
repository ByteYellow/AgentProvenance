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

// TestRecordLocalInheritsFullEnvironment pins the local CLI record path to the
// pre-hardening behavior: the recorded child keeps the caller's full
// environment (model API keys, proxy settings, virtualenvs). The strict
// allow-list env policy must stay confined to the daemon HTTP path.
func TestRecordLocalInheritsFullEnvironment(t *testing.T) {
	t.Setenv("AGENTPROV_ENV_MARKER", "passed-through")
	root := NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", t.TempDir(), "record", "--json", "--workdir", t.TempDir(), "--post-root-grace-ms", "1", "--", "sh", "-c", `printf 'MARKER=%s\n' "$AGENTPROV_ENV_MARKER"`})
	if err := root.Execute(); err != nil {
		t.Fatalf("record command: %v %s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "MARKER=passed-through") {
		t.Fatalf("recorded child lost the caller environment: %s", stderr.String())
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
