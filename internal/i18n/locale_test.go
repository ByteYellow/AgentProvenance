package i18n

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLanguagePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, query, cookie, browser string
		want                         Locale
	}{
		{"no preference", "", "", "", English},
		{"Chinese browser", "", "", "zh-CN,zh;q=0.9,en;q=0.8", Chinese},
		{"English browser", "", "", "en-US,en;q=0.9,zh;q=0.8", English},
		{"Chinese region", "", "", "zh-TW,zh;q=0.9", Chinese},
		{"unsupported browser", "", "", "fr-FR,de;q=0.8", English},
		{"supported second preference", "", "", "fr-FR,zh-CN;q=0.9,en;q=0.8", Chinese},
		{"quality order", "", "", "en;q=0.1,zh;q=0.9", Chinese},
		{"excluded Chinese", "", "", "zh;q=0,en;q=0.9", English},
		{"malformed browser", "", "", "zh;q=wrong", English},
		{"saved English beats Chinese browser", "", "en", "zh-CN", English},
		{"saved Chinese beats English browser", "", "zh-CN", "en-US", Chinese},
		{"explicit English beats saved Chinese", "en", "zh-CN", "zh-CN", English},
		{"explicit Chinese beats saved English", "zh-CN", "en", "en-US", Chinese},
		{"invalid query keeps saved choice", "bad", "zh-CN", "en-US", Chinese},
		{"invalid cookie uses browser", "", "bad", "zh-CN", Chinese},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/demos/?lang="+tc.query, nil)
			r.Header.Set("Accept-Language", tc.browser)
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: cookieName, Value: tc.cookie})
			}
			if got := FromRequest(r); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRememberOnlyExplicitSelection(t *testing.T) {
	for _, query := range []string{"", "?lang=unknown", "?lang=zh-CN", "?lang=en"} {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/demos/"+query, nil)
		r.Header.Set("Accept-Language", "zh-CN")
		w := httptest.NewRecorder()
		Remember(w, r)
		cookies := w.Result().Cookies()
		want := query == "?lang=zh-CN" || query == "?lang=en"
		if !want {
			if len(cookies) != 0 {
				t.Errorf("saved an implicit choice: %s", query)
			}
			continue
		}
		if len(cookies) != 1 {
			t.Fatalf("missing cookie: %s", query)
		}
		c := cookies[0]
		if c.Path != "/" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge <= 0 {
			t.Fatalf("bad cookie: %+v", c)
		}
		next := httptest.NewRequest(http.MethodGet, "/demos/", nil)
		next.AddCookie(c)
		if got := FromRequest(next); string(got) != c.Value {
			t.Fatalf("choice lost: %s", got)
		}
	}
}

func TestURLPreservesReplaySelection(t *testing.T) {
	got := URL("/?run=run-double-attempt&lens=orchestration&replay=1#node-7", Chinese)
	want := "/?lang=zh-CN&lens=orchestration&replay=1&run=run-double-attempt#node-7"
	if got != want {
		t.Fatalf("got %s", got)
	}
	for _, external := range []string{"https://example.com/docs?a=1#part", "//example.com/docs"} {
		if URL(external, Chinese) != external {
			t.Errorf("external link changed: %s", external)
		}
	}
}

func TestScriptUsesExplicitLanguageAndSafeJSON(t *testing.T) {
	for _, lang := range []Locale{English, Chinese} {
		r := httptest.NewRequest(http.MethodGet, "/assets/i18n.js?lang="+string(lang), nil)
		r.Header.Set("Accept-Language", "zh-CN")
		w := httptest.NewRecorder()
		Script(w, r)
		body := w.Body.String()
		if !strings.Contains(body, `"locale":"`+string(lang)+`"`) {
			t.Fatalf("wrong script locale: %s", lang)
		}
		if strings.Contains(body, "示例库") != (lang == Chinese) {
			t.Errorf("wrong catalog: %s", lang)
		}
		if w.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal("language script must not be shared across users")
		}
	}
}
