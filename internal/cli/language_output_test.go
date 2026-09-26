package cli

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/demo"
	"github.com/byteyellow/agentprovenance/internal/adapter"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/signal"
)

func TestDemoListLocalizesOnlyPresentation(t *testing.T) {
	for _, locale := range []i18n.Locale{i18n.English, i18n.Chinese} {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"--lang", string(locale), "demo", "--list"})
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		for _, entry := range demo.Catalog() {
			kind := "signed replay"
			if entry.Run == "" {
				kind = "setup guide"
			}
			want := entry.ID + "\t" + i18n.T(locale, kind) + "\t" + i18n.T(locale, entry.Title) + "\n"
			if !strings.Contains(out.String(), want) {
				t.Errorf("missing %q in %s", want, out.String())
			}
			if !i18n.HasChinese(entry.Title) {
				t.Errorf("missing title translation: %s", entry.Title)
			}
		}
	}
}

func TestSignalPresentationPreservesEvidence(t *testing.T) {
	// These payload values deliberately collide with UI catalog keys.
	report := signal.EvalReport{RunID: "Copy", Signals: []signal.EvalSignal{{ID: "Search", Name: "Run", Reason: "No evidence available", Label: "Ready"}}}
	before, _ := json.Marshal(report)
	var en, zh bytes.Buffer
	if err := printSignalReport(&en, report, i18n.English); err != nil {
		t.Fatal(err)
	}
	if err := printSignalReport(&zh, report, i18n.Chinese); err != nil {
		t.Fatal(err)
	}
	if en.String() == zh.String() || strings.Contains(zh.String(), "DECISION_OWNER") || !strings.Contains(zh.String(), "原因") {
		t.Fatalf("not localized: %s", zh.String())
	}
	for _, raw := range []string{"Copy", "Search", "Run", "No evidence available", "Ready"} {
		if !strings.Contains(zh.String(), raw) {
			t.Errorf("evidence translated: %s", raw)
		}
	}
	after, _ := json.Marshal(report)
	if !bytes.Equal(before, after) {
		t.Fatal("report mutated")
	}
	if strings.Contains(zh.String(), "%!") {
		t.Fatal("broken formatting")
	}
}

func TestTerminalErrorsPreserveProgrammaticError(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--lang", "zh-CN", "evidence", "manifest"})
	err := root.Execute()
	if err == nil || err.Error() != "--run is required" {
		t.Fatalf("unexpected original error: %v", err)
	}
	text := ErrorText(root, err)
	if text == err.Error() || !strings.Contains(text, "--run") {
		t.Fatalf("not localized: %s", text)
	}
	if strings.Contains(out.String(), "Error:") {
		t.Fatal("Cobra printed a duplicate untranslated error")
	}
}

func TestCommandURLPreservesBrowserChoiceByDefault(t *testing.T) {
	raw := "http://127.0.0.1:7396/?run=Copy&lens=data-flow-taint#original"
	root := NewRootCommand()
	if got := commandURL(root, raw); got != raw {
		t.Fatalf("default overrode browser preference: %s", got)
	}
	if err := root.PersistentFlags().Set("lang", "zh-CN"); err != nil {
		t.Fatal(err)
	}
	got, _ := url.Parse(commandURL(root, raw))
	want, _ := url.Parse(raw)
	if got.Scheme != want.Scheme || got.Host != want.Host || got.Path != want.Path || got.Fragment != want.Fragment || got.Query().Get("lang") != "zh-CN" {
		t.Fatalf("bad localized URL: %s", got)
	}
	q := got.Query()
	q.Del("lang")
	if !reflect.DeepEqual(q, want.Query()) {
		t.Fatal("original query changed")
	}
}

func TestBuiltinDescriptionsAreTranslatedAndCustomCopyIsPreserved(t *testing.T) {
	for _, item := range adapter.List() {
		values := []string{item.Boundary, item.Notes}
		values = append(values, item.QBSImpact...)
		for _, cap := range item.Capabilities {
			values = append(values, cap.Notes)
		}
		for _, value := range values {
			if value != "" && !i18n.HasChinese(value) {
				t.Errorf("%s missing Chinese: %s", item.Name, value)
			}
		}
	}
	for source := range complianceCopy {
		if !i18n.HasChinese(source) {
			t.Errorf("missing compliance copy: %s", source)
		}
	}
	root := NewRootCommand()
	if err := root.PersistentFlags().Set("lang", "zh-CN"); err != nil {
		t.Fatal(err)
	}
	for _, custom := range []string{"Copy", "Ready", "Custom policy: keep English"} {
		if got := complianceText(root, custom); got != custom {
			t.Errorf("custom text rewritten: %s", got)
		}
	}
}

func TestSignedReplayCLIViewsInBothLanguages(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "state")
	entry := demo.Catalog()[0]
	if _, err := prepareDemo(dir, dataDir, entry, demo.Files); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		args    []string
		chinese string
		json    bool
	}{
		{[]string{"graph", "trace"}, "执行 ID", false},
		{[]string{"graph", "refs"}, "引用：", false},
		{[]string{"graph", "log"}, "执行日志：", false},
		{[]string{"graph", "objects"}, "对象数", true},
		{[]string{"graph", "lens"}, "证据图", true},
		{[]string{"graph", "verify"}, "错误数", true},
		{[]string{"graph", "replay"}, "回放执行", true},
		{[]string{"timeline"}, "事件数", true},
		{[]string{"evidence", "manifest"}, "执行记录", true},
	}
	execute := func(t *testing.T, args []string, lang string) string {
		t.Helper()
		root := NewRootCommand()
		var out, stderr bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&stderr)
		root.SetArgs(append([]string{"--data-dir", dataDir, "--lang", lang}, args...))
		if err := root.Execute(); err != nil {
			t.Fatalf("%s %v: %v\n%s", lang, args, err, stderr.String())
		}
		if strings.Contains(out.String(), "%!") {
			t.Fatalf("invalid formatting for %v", args)
		}
		return out.String()
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			args := append(append([]string{}, tc.args...), "--run", entry.Run)
			en, zh := execute(t, args, "en"), execute(t, args, "zh-CN")
			if en == zh || !strings.Contains(zh, tc.chinese) || !strings.Contains(zh, entry.Run) {
				t.Fatalf("missing Chinese heading or changed run identity:\n%s", zh)
			}
			if tc.json {
				enJSON, zhJSON := execute(t, append(args, "--json"), "en"), execute(t, append(args, "--json"), "zh-CN")
				var a, b any
				if err := json.Unmarshal([]byte(enJSON), &a); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(zhJSON), &b); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(a, b) {
					t.Fatalf("JSON changed with language for %v", args)
				}
			}
		})
	}
}
