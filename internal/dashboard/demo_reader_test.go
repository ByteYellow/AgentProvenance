package dashboard

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestGalleryReaderKeepsFrozenSelectionAndSingleAssets(t *testing.T) {
	summary := ReplaySelectionSummary{Selection: ReplaySelection{RunID: "a", Scope: "session", Harness: "codex", SessionID: "s"}}
	inv := ReplayInventory{RunID: "a", Scope: "session", SelectionSummary: &summary, AnalysisOmissions: map[string]int{"outside_selection": 1}}
	files, err := DemoReaderFiles(context.Background(), inv, "a", true)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DemoReaderFiles(context.Background(), inv, "a", true)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		if !bytes.Equal(b, again[name]) {
			t.Fatalf("non-repeatable reader file %s", name)
		}
	}
	for _, lang := range []string{"en", "zh-CN"} {
		page := string(files[lang+"/index.html"])
		for _, value := range []string{`src="../assets/reader.js"`, `src="../assets/evidence.js"`, `href="../assets/evidence.css"`, `name="agentprov-replay-selection" content="partial"`, `class="offline-replay-bar"`, `href="https://github.com/ByteYellow/AgentProvenance/releases/latest"`, `codex / s`} {
			if strings.Count(page, value) != 1 {
				t.Fatalf("%s expected exactly one %s", lang, value)
			}
		}
		if strings.Index(page, `name="agentprov-default-run"`) > strings.Index(page, `src="../assets/offline.js"`) {
			t.Fatal("default run arrived after the offline reader")
		}
	}
	if !strings.Contains(string(files["en/index.html"]), "some analyses omitted") {
		t.Fatal("lost analysis omission")
	}
	if _, err := DemoReaderFiles(context.Background(), inv, "outside", true); err == nil {
		t.Fatal("accepted out-of-selection run")
	}
	inv.Signed = true
	if _, err := DemoReaderFiles(context.Background(), inv, "a", true); err == nil {
		t.Fatal("accepted signed original")
	}
}
