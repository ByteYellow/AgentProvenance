package cli

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/demo"
	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func TestStaticDemoURLsUnderProjectSubpath(t *testing.T) {
	cases := []struct{ input, file, want string }{
		{"/?run=recorded&lang=zh-CN", "en/demos/example.html", "../../zh-CN/replay.html?live=0&run=recorded"},
		{"/assets/i18n.js?lang=en", "en/replay.html", "../assets/i18n.en.js"},
		{"/demos/guide/start?lang=zh-CN#language", "en/demos/example.html", "../../zh-CN/guides/start.html#language"},
		{"https://github.com/ByteYellow/AgentProvenance", "en/index.html", "https://github.com/ByteYellow/AgentProvenance"},
	}
	for _, c := range cases {
		if got := staticDemoURL(c.input, c.file, i18n.English); got != c.want {
			t.Errorf("%s -> %s; want %s", c.input, got, c.want)
		}
	}
}

func TestStaticReplayInstallsReaderBeforeDashboard(t *testing.T) {
	raw := []byte(`<!doctype html><html><head><script src="/assets/i18n.js?lang=en"></script></head><body><script>bootDashboard()</script></body></html>`)
	out, err := staticDemoHTML(raw, "en/replay.html", i18n.English, true)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	reader, boot := strings.Index(s, "../assets/replay.js"), strings.Index(s, "bootDashboard()")
	if reader < 0 || reader > boot || !strings.Contains(s, `name="agentprov-site-root" content="../"`) {
		t.Fatal(s)
	}
}

func TestDemoExportCannotUsePrivateStores(t *testing.T) {
	for _, flag := range []string{"--data-dir", "--daemon-url"} {
		cmd := NewRootCommand()
		cmd.SetArgs([]string{flag, "private-location", "demo", "export", "--output", t.TempDir() + "/site"})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "bundled public examples") {
			t.Fatalf("%s: %v", flag, err)
		}
	}
}

func TestCompleteDocumentationKeepsOverviewAndReference(t *testing.T) {
	h := demoGallery(demo.Catalog())
	for _, c := range []struct {
		route string
		need  []string
	}{
		{"/demos/guide/start?lang=en", []string{"Agent session", "Runtime capture", "Features and docs", "agentprovenance-cover-en.png", "three-axis-observability.svg", "online-demo-button.svg", "/demos/guide/capabilities?lang=en"}},
		{"/demos/guide/capabilities?lang=zh-CN", []string{"核心模型", "部署模式", "外部评估器协议", "架构", "evidence-dag-zh-CN.svg"}},
	} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("GET", c.route, nil))
		if w.Code != 200 {
			t.Fatal(c.route, w.Code)
		}
		for _, need := range c.need {
			if !strings.Contains(w.Body.String(), need) {
				t.Errorf("%s missing %s", c.route, need)
			}
		}
		if strings.Contains(w.Body.String(), `src="https://img.shields.io`) {
			t.Fatal("offline docs load remote badges")
		}
	}
}
func TestProjectPresentationDoesNotAlterCodeOrEnableScripts(t *testing.T) {
	code := "```html\n<div align=\"center\">\n<p align=\"center\"><img src=\"example.png\"></p>\n</div>\n```\n"
	if string(projectMarkdown([]byte(code))) != code {
		t.Fatal("code example was rewritten")
	}
	source := []byte(`<p align="center"><img src="image.png" onerror="alert(1)" alt="diagram"></p>` + "\n\n" + `<script>alert(2)</script>`)
	result, _, err := renderLocalizedDemoGuide(demo.Entry{}, nil, source, i18n.English, "README.md")
	if err != nil || strings.Contains(string(result), "onerror") || strings.Contains(string(result), "<script>") || !strings.Contains(string(result), "<img ") {
		t.Fatalf("%s %v", result, err)
	}
}
