// Package i18n localizes presentation text without changing stored evidence or
// machine-readable identifiers. English source strings are stable catalog keys.
package i18n

import (
	"embed"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/text/language"
)

type Locale string

const (
	Chinese    Locale = "zh-CN"
	English    Locale = "en"
	Default           = English
	cookieName        = "agentprov_language"
)

//go:embed zh-CN.json
var catalogs embed.FS

var chinese = func() map[string]string {
	data, err := catalogs.ReadFile("zh-CN.json")
	if err != nil {
		panic(err)
	}
	var messages map[string]string
	if err := json.Unmarshal(data, &messages); err != nil {
		panic(err)
	}
	return messages
}()

func Parse(value string) (Locale, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "zh", "zh-cn", "zh-hans":
		return Chinese, true
	case "en", "en-us", "en-gb":
		return English, true
	default:
		return Default, false
	}
}

func FromRequest(r *http.Request) Locale {
	if lang, ok := Parse(r.URL.Query().Get("lang")); ok {
		return lang
	}
	if c, err := r.Cookie(cookieName); err == nil {
		if lang, ok := Parse(c.Value); ok {
			return lang
		}
	}
	// Respect the browser's ordered preferences only before the user makes an
	// explicit choice. Unsupported languages fall back to the English source.
	if tags, _, err := language.ParseAcceptLanguage(r.Header.Get("Accept-Language")); err == nil {
		for _, tag := range tags {
			base, _ := tag.Base()
			switch base.String() {
			case "zh":
				return Chinese
			case "en":
				return English
			}
		}
	}
	return Default
}

// Remember applies only an explicit, supported selection. The preference does
// not control API content and never changes the recorded evidence language.
func Remember(w http.ResponseWriter, r *http.Request) {
	if lang, ok := Parse(r.URL.Query().Get("lang")); ok {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: string(lang), Path: "/", MaxAge: 31536000, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	}
}

func T(lang Locale, source string) string {
	if lang == Chinese {
		if translated, ok := chinese[source]; ok {
			return translated
		}
	}
	return source
}

func HasChinese(source string) bool { _, ok := chinese[source]; return ok }

// URL adds an explicit language to a local presentation URL. Its query values
// and fragment (including Run/lens selections) are preserved.
func URL(raw string, lang Locale) string {
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
		return raw
	}
	q := u.Query()
	q.Set("lang", string(lang))
	u.RawQuery = q.Encode()
	return u.String()
}

func GuideFilename(lang Locale) string {
	if lang == Chinese {
		return "README.zh-CN.md"
	}
	return "README.md"
}
