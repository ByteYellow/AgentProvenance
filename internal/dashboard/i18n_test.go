package dashboard

import (
	"encoding/json"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestDashboardLanguageKeepsMachineIdentifiers(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN"} {
		r := httptest.NewRequest(http.MethodGet, "/?run=original-run&lens=security&lang="+lang, nil)
		w := httptest.NewRecorder()
		Server{}.Handler().ServeHTTP(w, r)
		body := w.Body.String()
		if w.Code != 200 {
			t.Fatalf("page failed for %s: %d %s", lang, w.Code, body)
		}
		for _, want := range []string{`<html lang="` + lang + `">`, `<option value="summary">`, `<option value="expanded">`, `<option value="raw">`, `data-ov="risk"`, `id="runsel"`, `/assets/i18n.js?lang=` + lang, `</html>`} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %s", want)
			}
		}
		if strings.Contains(body, "#ZgotmplZ") {
			t.Fatal("template rejected a presentation value")
		}
		heading := "Run Overview"
		if lang == "zh-CN" {
			heading = "执行概览"
		}
		if !strings.Contains(body, "<h2>"+heading) {
			t.Errorf("wrong heading for %s", lang)
		}
		if !strings.Contains(body, "lens=security") || !strings.Contains(body, "run=original-run") {
			t.Error("language link lost replay selection")
		}
	}
}

func TestDashboardCopyHasChineseCatalogEntries(t *testing.T) {
	// New copy must have a translation. Browser checks separately verify that
	// these lookups are actually used in rendered controls and error states.
	patterns := []string{`\{\{tr \.Lang "([^"]+)"`, `\b(?:tr|tx)\(\s*"([^"\\]*(?:\\.[^"\\]*)*)"`, `\b(?:tr|tx)\(\s*'([^'\\]*(?:\\.[^'\\]*)*)'`}
	for _, pattern := range patterns {
		for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(string(indexHTML), -1) {
			source := strings.ReplaceAll(m[1], `\'`, `'`)
			if !i18n.HasChinese(source) {
				t.Errorf("missing Chinese copy: %q", source)
			}
		}
	}
}

func TestDashboardLensDescriptionsHaveChinese(t *testing.T) {
	db := newDashboardTestDB(t)
	h := Server{DB: db}.Handler()
	get := func(lens string) provenance.GraphLensManifest {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/lens?run=run-dash&lens="+lens, nil))
		var manifest provenance.GraphLensManifest
		if err := json.Unmarshal(w.Body.Bytes(), &manifest); err != nil || w.Code != 200 {
			t.Fatalf("lens failed: %d %s", w.Code, w.Body.String())
		}
		return manifest
	}
	for _, lens := range get("default").AvailableLenses {
		m := get(lens)
		for _, source := range append(m.Query.LensRules, m.Query.LayoutHint) {
			if !i18n.HasChinese(source) {
				t.Errorf("%s lacks translation: %s", lens, source)
			}
		}
	}
}

func TestPreviewLanguageDoesNotChangeEvidence(t *testing.T) {
	db := newDashboardTestDB(t)
	payload := `{"command":"echo risk; cat '/tmp/no runs'","note":"Copy","path":"/tmp/secret"}`
	insertDashboardEvent(t, db, "original-event", "execve", payload)
	h := Server{DB: db}.Handler()
	get := func(extra string) artifactResp {
		r := httptest.NewRequest("GET", "/api/artifact?run=run-dash&node=runtime_event/original-event"+extra, nil)
		r.Header.Set("Accept-Language", "zh-CN")
		r.AddCookie(&http.Cookie{Name: "agentprov_language", Value: "zh-CN"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out artifactResp
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 {
			t.Fatalf("preview failed: %d %s", w.Code, w.Body.String())
		}
		return out
	}
	en, zh := get("&lang=zh-CN"), get("&view_lang=zh-CN")
	if !strings.HasPrefix(en.Content, "event: execve\n\n") || !strings.HasPrefix(zh.Content, "事件：execve\n\n") {
		t.Fatalf("wrong preview language: en=%q zh=%q", en.Content, zh.Content)
	}
	if strings.SplitN(en.Content, "\n\n", 2)[1] != strings.SplitN(zh.Content, "\n\n", 2)[1] {
		t.Fatal("localized preview altered original body")
	}
	var stored string
	if err := db.QueryRow("SELECT payload FROM events WHERE id = 'original-event'").Scan(&stored); err != nil || stored != payload {
		t.Fatal("preview changed stored evidence")
	}
}

func TestLLMPreviewTranslatesHeadingsOnly(t *testing.T) {
	input := []byte(`{"type":"llm_message","payload":{"direction":"response","model":"model-original","content":"{\"message\":\"stop reason: Copy; risk; no runs\"}","semantics":{"tool_calls":["bash"],"tool_commands":["echo 'Copy'"],"stop_reason":"tool_use"}}}`)
	en, ok := renderLLMMessage(input)
	if !ok {
		t.Fatal("fixture not recognized")
	}
	zh, ok := renderLLMMessageLocale(input, i18n.Chinese)
	if !ok || !strings.Contains(string(zh), "选用命令：echo 'Copy'") || !strings.Contains(string(zh), "停止原因：tool_use") {
		t.Fatalf("missing localized headings or changed values: %s", zh)
	}
	bodyEN := strings.SplitN(string(en), "─────────── body ───────────\n", 2)
	bodyZH := strings.SplitN(string(zh), "─────────── 原始正文 ───────────\n", 2)
	if len(bodyEN) != 2 || len(bodyZH) != 2 || bodyEN[1] != bodyZH[1] {
		t.Fatalf("original body changed: en=%s zh=%s", en, zh)
	}
}
