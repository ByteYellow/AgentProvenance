package cli

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/byteyellow/agentprovenance/demo"
	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func TestAllDemoGuidesInBothLanguages(t *testing.T) {
	entries := demo.Catalog()
	h := demoGallery(entries)
	for _, lang := range []i18n.Locale{i18n.English, i18n.Chinese} {
		for _, entry := range entries {
			t.Run(entry.ID+"/"+string(lang), func(t *testing.T) {
				w := httptest.NewRecorder()
				h(w, httptest.NewRequest(http.MethodGet, "/demos/docs/"+entry.ID+"?lang="+string(lang), nil))
				body := w.Body.String()
				if w.Code != http.StatusOK {
					t.Fatalf("guide failed: %d %s", w.Code, body)
				}
				for _, want := range []string{`<html lang="` + string(lang) + `">`, `class="document"><h1`, `class="page-nav"`, `i18n.js?lang=` + string(lang)} {
					if !strings.Contains(body, want) {
						t.Errorf("missing %s", want)
					}
				}
				if lang == i18n.Chinese {
					if !strings.Contains(body, "本页目录") || !strings.Contains(body, "证据") {
						t.Error("Chinese guide not rendered")
					}
					if !strings.Contains(body, "/demos/docs/"+entry.ID+"?lang=en") {
						t.Error("cannot switch guide to English")
					}
				}
				if entry.Run != "" && !strings.Contains(body, "run="+entry.Run) {
					t.Error("replay run identifier changed")
				}
			})
		}
	}
}

func TestGalleryLocaleDoesNotLeakBetweenRequests(t *testing.T) {
	h := demoGallery(demo.Catalog())
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			lang := i18n.English
			if n%2 == 0 {
				lang = i18n.Chinese
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/demos/?lang="+string(lang), nil)
			h(w, r)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "<h2>"+i18n.T(lang, "Demo library")+"</h2>") {
				t.Errorf("locale leaked for %s", lang)
			}
		}(n)
	}
	wg.Wait()
}

func TestDemoCopyHasChineseCatalogEntries(t *testing.T) {
	// Catch new static template/JS copy and catalog cards missing translations.
	patterns := []struct{ source, pattern string }{
		{demoGalleryHTML, `\{\{tr \$?\.Lang "([^"]+)"`},
		{demoGuideHTML, `\{\{tr \$?\.Lang "([^"]+)"`},
		{string(demoGuideJS), `\bt\('([^']+)'\)`},
	}
	for _, p := range patterns {
		for _, m := range regexp.MustCompile(p.pattern).FindAllStringSubmatch(p.source, -1) {
			if !i18n.HasChinese(m[1]) {
				t.Errorf("missing Chinese: %q", m[1])
			}
		}
	}
	for _, entry := range demo.Catalog() {
		for _, s := range []string{entry.Title, entry.Description, entry.Requirements, demoCategory(entry)} {
			if !i18n.HasChinese(s) {
				t.Errorf("missing Chinese: %q", s)
			}
		}
	}
}

func TestLocalizedGuideLinksKeepExplicitLanguage(t *testing.T) {
	entries := demo.Catalog()
	entry := entries[0]
	source := []byte("# 指南\n\n[English](README.md)\n\n[中文](README.zh-CN.md)\n\n[团队](../multiagent-provenance)\n\n[外部](https://example.com/README.md)\n")
	html, _, err := renderLocalizedDemoGuide(entry, entries, source, i18n.Chinese)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`/demos/docs/snake-supply-chain?lang=en`,
		`/demos/docs/snake-supply-chain?lang=zh-CN`,
		`/demos/docs/multiagent-provenance?lang=zh-CN`,
		`href="https://example.com/README.md"`,
	} {
		if !strings.Contains(string(html), want) {
			t.Errorf("missing link %s in %s", want, html)
		}
	}
}

func TestChineseHeadingAnchors(t *testing.T) {
	entries := demo.Catalog()
	source := []byte("# 中文指南\n\n[跳转](#证据范围)\n\n## 证据范围\n\n内容\n\n## 证据范围\n\n第二段\n\n## 证据范围-1\n")
	rendered, headings, err := renderLocalizedDemoGuide(entries[0], entries, source, i18n.Chinese)
	if err != nil {
		t.Fatal(err)
	}
	if len(headings) != 3 {
		t.Fatalf("outline length: %d", len(headings))
	}
	for n, want := range []string{"证据范围", "证据范围-1", "证据范围-1-1"} {
		if headings[n].ID != want || !strings.Contains(string(rendered), `id="`+want+`"`) {
			t.Errorf("missing unique anchor %s: %s", want, rendered)
		}
	}
}

func TestLocalizedDemoErrors(t *testing.T) {
	h := demoGallery(demo.Catalog())
	for _, tc := range []struct {
		method, path string
		code         int
		message      string
	}{
		{"GET", "/demos/docs/missing?lang=zh-CN", 404, "页面或资源不存在"},
		{"GET", "/demos/assets/missing.png?lang=zh-CN", 404, "页面或资源不存在"},
		{"POST", "/demos/?lang=zh-CN", 405, "不支持此请求方法"},
	} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.message) {
			t.Errorf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}

func TestSharedGuideKeepsSelectedCapture(t *testing.T) {
	entries := demo.Catalog()
	var current demo.Entry
	for _, entry := range entries {
		if entry.ID == "grok-3routes" {
			current = entry
		}
	}
	for _, file := range []string{"README.md", "README.zh-CN.md"} {
		if got := demoGuideLink(current, entries, file); got != "/demos/docs/grok-3routes" {
			t.Errorf("capture changed for %s: %s", file, got)
		}
	}
}
