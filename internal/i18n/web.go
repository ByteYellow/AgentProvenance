package i18n

import (
	"encoding/json"
	"net/http"
)

// Script installs explicit string lookup, not a DOM text replacement pass.
// Callers must use it for interface copy, never for original evidence payloads.
func Script(w http.ResponseWriter, r *http.Request) {
	lang := FromRequest(r)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	payload := struct {
		Locale   Locale            `json:"locale"`
		Messages map[string]string `json:"messages"`
	}{Locale: lang}
	if lang == Chinese {
		payload.Messages = chinese
	}
	data, _ := json.Marshal(payload)
	_, _ = w.Write([]byte("'use strict';\nwindow.AgentProvI18n = (() => { const data = "))
	_, _ = w.Write(data)
	_, _ = w.Write([]byte(`;
 return Object.freeze({
  locale: data.locale,
  t: (source) => Object.prototype.hasOwnProperty.call(data.messages || {}, source) ? data.messages[source] : source,
  url: (value, locale = data.locale) => {
   const result = new URL(value, location.href);
   if (result.origin === location.origin) result.searchParams.set('lang', locale);
   return result.href;
  }
 });
})();
`))
}
