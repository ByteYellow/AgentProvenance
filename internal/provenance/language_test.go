package provenance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func TestLocalizedDiffKeepsOriginalPatch(t *testing.T) {
	m := FileDiffManifest{RunID: "Copy", File: "Run", Attempts: []FileDiffAttempt{{AttemptID: "Search", Changed: true, UnifiedDiff: []string{"-Ready", "+Copy"}}}}
	before, _ := json.Marshal(m)
	var out bytes.Buffer
	PrintDiffFile(&out, m, i18n.Chinese)
	for _, text := range []string{"执行=Copy", "差异：", "  --- base/Run\n", "  +++ attempt/Search/Run\n", "  -Ready\n", "  +Copy\n"} {
		if !strings.Contains(out.String(), text) {
			t.Errorf("lost %q in %s", text, out.String())
		}
	}
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("manifest changed")
	}
}

func TestLocalizedNestedReplayKeepsCommandsAndPayloads(t *testing.T) {
	m := ReplayManifest{RunID: "Copy", Rollouts: []ReplayRollout{{ID: "Run", BaseSnapshot: &ReplaySnapshot{Name: "Ready"}, Attempts: []ReplayAttemptPlan{{ID: "Search", Command: "echo Copy", ToolCall: &ReplayToolCall{ID: "Ready", Command: "echo Search"}, Events: []ReplayEvent{{ID: "Run", Payload: `{"message":"Ready"}`}}}}}}}
	before, _ := json.Marshal(m)
	var out bytes.Buffer
	PrintReplayManifest(&out, m, i18n.Chinese)
	for _, text := range []string{"回放执行=Copy", "基础状态 名称=Ready", "执行范围=Search", "工具调用=Ready", "echo Copy", "echo Search", `{"message":"Ready"}`} {
		if !strings.Contains(out.String(), text) {
			t.Errorf("lost %q in %s", text, out.String())
		}
	}
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("manifest changed")
	}
	if strings.Contains(out.String(), "%!") {
		t.Fatal("bad format")
	}
}

func TestLocalizedTrajectoryDoesNotRequireOriginalWorkspace(t *testing.T) {
	m := TrajectoryManifest{RunID: "Copy"}
	var out bytes.Buffer
	PrintTrajectoryManifest(&out, m, i18n.Chinese)
	if !strings.Contains(out.String(), "轨迹所属执行=Copy") {
		t.Fatal(out.String())
	}
}

func TestSummaryTranslationKeepsUnrecognizedText(t *testing.T) {
	m := GraphLensManifest{Lens: "default", Summary: []string{"lens=default layout=", "Copy"}}
	before, _ := json.Marshal(m)
	got := graphLensDisplaySummary(m, i18n.Chinese)
	if len(got) != 2 || got[0] != "视图=default 布局=" || got[1] != "Copy" {
		t.Fatalf("unexpected summary: %v", got)
	}
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("manifest changed")
	}
}
