package cli

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/demo"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
)

func TestPublicReplayCatalogPreservesIndependentRunIndexes(t *testing.T) {
	writer := &staticdata.Writer{Root: t.TempDir()}
	frameworks, err := writer.JSON([]map[string]string{{"id": "built-in"}})
	if err != nil {
		t.Fatal(err)
	}
	var snapshot dashboard.ReplayRun
	if err := json.Unmarshal([]byte(`{"api":{},"event_refs":{"runtime_process/one":["event-1"]},"sessions":{"[\"codex\",\"root\"]":{"event_ids":["event-1"]}}}`), &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.API["frameworks"] = frameworks
	manifest := publicReplayManifest{
		SchemaVersion: "agentprovenance.static_replay/v1", Commit: "source-sha",
		Summaries: json.RawMessage(`[{"run":"one"},{"run":"other/instance"}]`),
		Runs:      map[string]dashboard.ReplayRun{"one": snapshot, "other/instance": snapshot},
	}
	before, _ := json.Marshal(manifest)
	catalog, err := buildPublicReplayCatalog(manifest, writer)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.SchemaVersion != "agentprovenance.static_catalog/v1" || catalog.Commit != manifest.Commit || !bytes.Equal(catalog.Summaries, manifest.Summaries) || len(catalog.RunIndexes) != len(manifest.Runs) {
		t.Fatalf("catalog metadata changed: %+v", catalog)
	}
	if catalog.Frameworks == nil || *catalog.Frameworks != frameworks {
		t.Fatal("global framework lookup must not require a run index")
	}
	if catalog.RunIndexes["one"].SHA256 == catalog.RunIndexes["other/instance"].SHA256 {
		t.Fatal("same-shaped runs must keep independent identities")
	}
	for id, ref := range catalog.RunIndexes {
		compressed, err := os.ReadFile(filepath.Join(writer.Root, ref.Path))
		if err != nil {
			t.Fatal(err)
		}
		z, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(z)
		z.Close()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if len(data) != ref.Bytes || hex.EncodeToString(digest[:]) != ref.SHA256 || ref.Path != "data/"+ref.SHA256+".json.gz" {
			t.Fatal("run index failed its recorded integrity check")
		}
		var index publicReplayRunIndex
		if err := json.Unmarshal(data, &index); err != nil {
			t.Fatal(err)
		}
		if index.SchemaVersion != "agentprovenance.replay_run/v1" || index.RunID != id {
			t.Fatalf("index lost its run identity: %+v", index)
		}
		got, _ := json.Marshal(index.Run)
		want, _ := json.Marshal(manifest.Runs[id])
		if !bytes.Equal(got, want) {
			t.Fatalf("run %s changed during catalog splitting", id)
		}
	}
	if after, _ := json.Marshal(manifest); !bytes.Equal(before, after) {
		t.Fatal("legacy manifest was modified")
	}
	written := writer.Bytes
	if _, err := buildPublicReplayCatalog(manifest, writer); err != nil || writer.Bytes != written {
		t.Fatalf("identical indexes were not reused: %v", err)
	}
}

func TestPublicReplayCatalogPropagatesWriteFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(root, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := publicReplayManifest{Runs: map[string]dashboard.ReplayRun{"one": {}}}
	if _, err := buildPublicReplayCatalog(manifest, &staticdata.Writer{Root: root}); err == nil {
		t.Fatal("failed index publication must abort the export")
	}
}

func TestPublicReplayCatalogRejectsConflictingFrameworks(t *testing.T) {
	manifest := publicReplayManifest{Runs: map[string]dashboard.ReplayRun{
		"a": {API: map[string]staticdata.Ref{"frameworks": {SHA256: "first"}}},
		"b": {API: map[string]staticdata.Ref{"frameworks": {SHA256: "second"}}},
	}}
	if _, err := buildPublicReplayCatalog(manifest, &staticdata.Writer{Root: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "framework catalog differs") {
		t.Fatalf("conflicting global catalog: %v", err)
	}
}

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
		{"/demos/guide/start?lang=en", []string{"Agent session", "Runtime capture", "Features and docs", "agentprovenance-cover-en.png", "three-axis-observability.svg", "Browse demos", "/demos/guide/capabilities?lang=en", "Remote commands, Browser and Notebook", "/demos/guide/execution-handoff?lang=en", "/demos/guide/browser-context?lang=en", "/demos/guide/notebook-context?lang=en", "/demos/guide/deployment?lang=en#where-the-agent-and-its-tools-run"}},
		{"/demos/guide/start?lang=zh-CN", []string{"远端命令、浏览器与 Notebook", "/demos/guide/execution-handoff?lang=zh-CN", "/demos/guide/browser-context?lang=zh-CN", "/demos/guide/notebook-context?lang=zh-CN", "/demos/guide/deployment?lang=zh-CN#" + url.PathEscape("先看-agent-和工具在哪里运行")}},
		{"/demos/guide/deployment?lang=en", []string{"Where the Agent and its tools run", "Choose collection by kernel boundary", "Choose a capture entry", "v0.10.1", "/demos/guide/release-notes?lang=en", "/demos/guide/gvisor-seccheck?lang=en", "ARM64 and amd64 systrap", "signed delivery and retirement accepted", "Workload and platform scope", "RuntimeClass"}},
		{"/demos/guide/deployment?lang=zh-CN", []string{"先看 Agent 和工具在哪里运行", "再按内核边界选择采集器", "<strong>原生 Linux 与普通容器</strong>", "选择采集入口", "v0.10.1", "/demos/guide/release-notes?lang=zh-CN", "/demos/guide/gvisor-seccheck?lang=zh-CN", "ARM64、amd64 systrap", "签名交付和回收已验收", "业务场景与平台范围", "RuntimeClass"}},
		{"/demos/guide/execution-handoff?lang=en", []string{"Follow one command across the boundary", "boot_tested: false", "actual Firecracker v1.18.0 boot", "receipt-gated retirement"}},
		{"/demos/guide/execution-handoff?lang=zh-CN", []string{"一条命令如何跨越沙箱边界", "boot_tested", "实际启动 guest", "回执齐全后回收"}},
		{"/demos/guide/browser-context?lang=en", []string{"Why record browser context", "/demos/guide/deployment?lang=en#choose-collection-by-kernel-boundary"}},
		{"/demos/guide/browser-context?lang=zh-CN", []string{"为什么需要浏览器上下文", "/demos/guide/deployment?lang=zh-CN#" + url.PathEscape("再按内核边界选择采集器")}},
		{"/demos/guide/notebook-context?lang=en", []string{"Why record requests rather than only processes", "/demos/guide/deployment?lang=en#choose-collection-by-kernel-boundary"}},
		{"/demos/guide/notebook-context?lang=zh-CN", []string{"为什么记录请求，而不只记录进程", "/demos/guide/deployment?lang=zh-CN#" + url.PathEscape("再按内核边界选择采集器")}},
		{"/demos/guide/demo-library?lang=en", []string{"Read the v1.0 candidate examples", "What happened", "What to inspect", "synthetic"}},
		{"/demos/guide/demo-library?lang=zh-CN", []string{"v1.0 候选示例看什么", "案例经过", "阅读顺序", "合成样本"}},
		{"/demos/guide/release-v1.0.0-preview?lang=en", []string{"Why this version extends the evidence path", "/demos/guide/demo-library?lang=en#read-the-v10-candidate-examples"}},
		{"/demos/guide/release-v1.0.0-preview?lang=zh-CN", []string{"为什么扩展这条证据链", "<strong>跨环境</strong>", "/demos/guide/demo-library?lang=zh-CN#" + url.PathEscape("v10-候选示例看什么")}},
		{"/demos/guide/gvisor-seccheck?lang=en", []string{"exercised on\nARM64 and amd64", "original receive, fault-recovery and restore/two-clone results"}},
		{"/demos/guide/gvisor-seccheck?lang=zh-CN", []string{"已在 ARM64 和 amd64 实测", "原始结果及程序哈希"}},
		{"/demos/guide/capabilities?lang=zh-CN", []string{"核心模型", "部署模式", "外部评估器协议", "架构", "evidence-dag-zh-CN.svg"}},
		{"/demos/guide/upgrade-v0.10.1?lang=en", []string{"Upgrading to v0.10.1", "record-timeout", "/demos/guide/release-notes?lang=en", "changed defaults in v0.10.1"}},
		{"/demos/guide/upgrade-v0.10.1?lang=zh-CN", []string{"升级到 v0.10.1", "record-timeout", "/demos/guide/release-notes?lang=zh-CN"}},
		{"/demos/guide/release-v0.10.1?lang=en", []string{"Released on November 9, 2026", "/demos/guide/upgrade-v0.10.1?lang=en"}},
		{"/demos/guide/release-v0.10.1?lang=zh-CN", []string{"发布日期：2026 年 11 月 9 日", "/demos/guide/upgrade-v0.10.1?lang=zh-CN"}},
		{"/demos/guide/release-notes?lang=en", []string{"v0.10.1", "Explore the updated examples", "/demos/docs/evidence-attribution?lang=en"}},
		{"/demos/guide/release-notes?lang=zh-CN", []string{"v0.10.1", "/demos/docs/endpoint-attribution?lang=zh-CN"}},
		{"/demos/guide/release-v0.10.0?lang=en", []string{"v0.10.0"}},
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

func TestDemoIncludesLinkedAPIContracts(t *testing.T) {
	h := demoGallery(demo.Catalog())
	for _, file := range []string{"audit-associations-api.yaml", "replay-export-api.yaml", "execution-handoff-api.yaml", "capture-manifest-api.yaml", "zh-CN/audit-associations-api.yaml"} {
		route := "/demos/assets/docs/" + file
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("GET", route, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "openapi:") {
			t.Fatalf("missing API contract %s: status %d", file, w.Code)
		}
		if got := projectDocLink("docs/agent-context.md", file); got != route {
			t.Errorf("contract link %s = %s; want %s", file, got, route)
		}
	}
}

func TestPortableEvidenceGuidesKeepLocalBilingualLinks(t *testing.T) {
	h := demoGallery(demo.Catalog())
	for _, tc := range []struct {
		id, source, title, chineseSource, chineseTitle string
	}{
		{"demo-library", "docs/demo-library.md", "Choose an investigation", "docs/zh-CN/demo-library.md", "按问题选择示例"},
		{"execution-handoff", "docs/execution-handoff.md", "Execution handoff protocol", "docs/zh-CN/execution-handoff.md", "执行交接协议"},
		{"gvisor-seccheck", "docs/gvisor-seccheck.md", "gVisor SecCheck Receiver", "docs/zh-CN/gvisor-seccheck.md", "gVisor SecCheck"},
		{"notebook-context", "docs/notebook-context.md", "Jupyter request and output context", "docs/zh-CN/notebook-context.md", "Jupyter"},
		{"browser-context", "docs/browser-context.md", "Browser context", "docs/browser-context.zh-CN.md", "浏览器上下文"},
		{"derived-evidence", "docs/derived-evidence.md", "Evidence Delivery and Verification", "docs/zh-CN/derived-evidence.md", "证据交付与独立验证"},
		{"workspace", "docs/workspace.md", "Controlled Remote Workspace", "docs/zh-CN/workspace.md", "受控远端工作区"},
		{"runtime-adapters", "docs/runtime-adapters.md", "Runtime Adapters", "docs/zh-CN/runtime-adapters.md", "运行时适配"},
		{"release-v1.0.0-preview", "docs/releases/v1.0.0-preview.md", "v1.0 Source Preview", "docs/zh-CN/releases/v1.0.0-preview.md", "v1.0 源码预览"},
	} {
		for _, chinese := range []bool{false, true} {
			lang, source, title := i18n.English, tc.source, tc.title
			if chinese {
				lang, source, title = i18n.Chinese, tc.chineseSource, tc.chineseTitle
			}
			t.Run(tc.id+"/"+string(lang), func(t *testing.T) {
				route := "/demos/guide/" + tc.id + "?lang=" + string(lang)
				w := httptest.NewRecorder()
				h(w, httptest.NewRequest("GET", route, nil))
				if w.Code != 200 || !strings.Contains(w.Body.String(), title) {
					t.Fatalf("guide %s: status %d, missing %q", route, w.Code, title)
				}
				if got := projectDocLink("README.md", source); got != route {
					t.Fatalf("guide link %s: %s", source, got)
				}
				static, err := staticDemoHTML(w.Body.Bytes(), string(lang)+"/guides/"+tc.id+".html", lang, false)
				if err != nil {
					t.Fatal(err)
				}
				other := "en"
				if lang == i18n.English {
					other = "zh-CN"
				}
				if !strings.Contains(string(static), "../../"+other+"/guides/"+tc.id+".html") {
					t.Fatal("static guide language switch no longer stays local")
				}
			})
		}
	}
}

func TestDemoLibraryPreservesEveryEntry(t *testing.T) {
	h := demoGallery(demo.Catalog())
	for _, lang := range []i18n.Locale{i18n.English, i18n.Chinese} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("GET", "/demos/guide/demo-library?lang="+string(lang), nil))
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		for _, entry := range demo.Catalog() {
			if !strings.Contains(w.Body.String(), "<code>"+entry.ID+"</code>") {
				t.Errorf("%s inventory omits %s", lang, entry.ID)
			}
		}
		for _, id := range []string{"browser-context", "notebook-context", "execution-handoff", "gvisor-seccheck"} {
			if !strings.Contains(w.Body.String(), "/demos/guide/"+id+"?lang="+string(lang)) {
				t.Errorf("%s inventory loses local link to %s", lang, id)
			}
		}
	}
}

func TestDemoNavigationIncludesPortableEvidenceGuides(t *testing.T) {
	h := demoGallery(demo.Catalog())
	for _, lang := range []i18n.Locale{i18n.English, i18n.Chinese} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("GET", "/demos/?lang="+string(lang), nil))
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		static, err := staticDemoHTML(w.Body.Bytes(), string(lang)+"/index.html", lang, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"demo-library", "execution-handoff", "gvisor-seccheck", "notebook-context", "browser-context"} {
			if !strings.Contains(w.Body.String(), `href="/demos/guide/`+id+`?lang=`+string(lang)+`"`) {
				t.Errorf("%s homepage omits guide %s", lang, id)
			}
			if !strings.Contains(string(static), `href="guides/`+id+`.html"`) {
				t.Errorf("%s static homepage omits guide %s", lang, id)
			}
		}
	}
}
