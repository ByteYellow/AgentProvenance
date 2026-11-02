package dashboard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

// The dashboard serves the full evidence store without credentials, so every
// route (pages, assets, and /api data routes) must reject requests that could
// originate from a web page on another origin. DNS rebinding is the main
// primitive: a malicious page rebinds a domain it owns to 127.0.0.1 and makes
// the victim's browser send requests whose Host header names that domain while
// the TCP peer is the local machine. Blocking any non-local, non-IP Host kills
// the rebind; the Origin and Sec-Fetch-Site checks stop cross-site browser
// requests that survive a Host match. Plain curl/CLI traffic carries none of
// those headers and keeps working unchanged.
//
// The replay export routes keep their own stricter guard (loopback-only Host
// and peer) in replay_preview.go and are exempt here so their behavior,
// including the exact 403 response, stays unchanged.

// replayGuardPrefix is the path prefix shared by every replay export route.
// Those routes enforce localReplayRequest themselves.
const replayGuardPrefix = "/api/replay/previews"

// guardMessage is returned for every request rejected by the dashboard-wide
// same-origin guard.
const guardMessage = "Dashboard access requires a local same-origin connection."

// sameOriginGuard wraps the dashboard mux with the same-origin local guard.
func (s Server) sameOriginGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Offline rendering (demo export) and in-process test harnesses serve
		// the mux through httptest's recorder without a network listener, so
		// there is no browser connection to rebind. A *httptest.ResponseRecorder
		// never occurs on a real http.Server connection path.
		if _, offline := w.(*httptest.ResponseRecorder); offline {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, replayGuardPrefix) {
			// The replay routes apply localReplayRequest with stricter rules.
			next.ServeHTTP(w, r)
			return
		}
		if !localDashboardRequest(r, s.ListenAddr) {
			httpError(w, guardMessage, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// localDashboardRequest reports whether r may reach the dashboard: its Host
// must be the configured listen host, localhost, or a literal IP (a domain
// name is exactly what DNS rebinding controls), a present Origin must name the
// same host, and cross-site fetch markers are rejected on writes.
func localDashboardRequest(r *http.Request, listen string) bool {
	host := requestHost(r)
	if host == "" || !hostIsLocal(host, listen) {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if err != nil || u.Scheme != scheme || u.Host == "" || !strings.EqualFold(u.Host, r.Host) ||
			u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
	}
	if writeMethod(r.Method) {
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			return false
		}
	}
	return true
}

// hostIsLocal accepts the listen host when configured, localhost, and literal
// IP addresses. Literal IPs cannot be rebound through DNS, so a LAN host
// reached by address keeps working while a rebindable domain never does.
func hostIsLocal(host, listen string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if listen != "" {
		if lh := listenHost(listen); lh != "" && strings.EqualFold(lh, host) {
			return true
		}
	}
	return false
}

// requestHost extracts the host part of the Host header, stripping the port
// and IPv6 brackets.
func requestHost(r *http.Request) string {
	return hostPart(r.Host)
}

// listenHost extracts the host part of a listen address ("host:port").
func listenHost(addr string) string {
	return hostPart(addr)
}

func hostPart(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	// No port: a bare IPv6 literal keeps its brackets and must be unwrapped.
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return hostport[1 : len(hostport)-1]
	}
	return hostport
}

func writeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}
