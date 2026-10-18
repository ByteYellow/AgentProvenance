package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
)

type replayPreview struct {
	SchemaVersion   string          `json:"schema_version"`
	ID              string          `json:"id"`
	ExpiresAt       time.Time       `json:"expires_at"`
	Inventory       ReplayInventory `json:"inventory"`
	InventorySHA256 string          `json:"inventory_sha256"`
	ZIPBytes        int64           `json:"zip_bytes"`
	ZIPSHA256       string          `json:"zip_sha256"`
}

type replayJob struct {
	preview  replayPreview
	prepared *PreparedReplay
	files    map[string]bool
	archive  string
	ready    bool
	retired  bool
	refs     int
	cancel   context.CancelFunc
	timer    *time.Timer
}

// ReplayExports owns at most one preparation or frozen archive. It is enabled
// by the local CLI, not by public static replay or internal projection handlers.
type ReplayExports struct {
	mu      sync.Mutex
	wg      sync.WaitGroup
	server  Server
	job     *replayJob
	active  bool
	closed  bool
	ttl     time.Duration
	timeout time.Duration
}

func NewReplayExports(server Server) *ReplayExports {
	return &ReplayExports{server: Server{DB: server.DB}, ttl: 10 * time.Minute, timeout: 5 * time.Minute}
}

func (m *ReplayExports) Close() {
	m.mu.Lock()
	m.closed = true
	j := m.job
	m.mu.Unlock()
	if j != nil {
		m.retire(j)
	}
	m.wg.Wait()
}

func (m *ReplayExports) retire(j *replayJob) {
	m.mu.Lock()
	if j.retired {
		m.mu.Unlock()
		return
	}
	j.retired = true
	j.cancel()
	if j.timer != nil {
		j.timer.Stop()
	}
	if m.job == j {
		m.job = nil
	}
	cleanup := j.refs == 0
	m.mu.Unlock()
	if cleanup {
		m.cleanup(j)
	}
}

func (m *ReplayExports) cleanup(j *replayJob) {
	if j.prepared != nil {
		_ = j.prepared.Close()
	}
	m.mu.Lock()
	m.active = false
	m.mu.Unlock()
	m.wg.Done()
}

func (m *ReplayExports) release(j *replayJob) {
	m.mu.Lock()
	j.refs--
	cleanup := j.retired && j.refs == 0
	m.mu.Unlock()
	if cleanup {
		m.cleanup(j)
	}
}

func (m *ReplayExports) acquire(id string) *replayJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	j := m.job
	if j == nil || j.preview.ID != id || !j.ready || !time.Now().Before(j.preview.ExpiresAt) {
		return nil
	}
	j.refs++
	return j
}

// Export uses local saved evidence. Reject non-loopback clients/hosts and
// cross-site requests, including DNS rebinding against a local listener.
func localReplayRequest(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host != "localhost" && !net.ParseIP(host).IsLoopback() {
		return false
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(peer).IsLoopback() {
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if err != nil || u.Scheme != scheme || u.Host != r.Host || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
	}
	if r.Method != http.MethodGet && r.Header.Get("X-AgentProv-Export") != "1" {
		return false
	}
	return true
}

func (s Server) replayRoutes(mux *http.ServeMux) {
	guard := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
			if !localReplayRequest(r) {
				httpError(w, "Replay export requires a same-origin local connection.", http.StatusForbidden)
				return
			}
			if s.ReplayExports == nil {
				httpError(w, "Replay export is unavailable on this server. Use dashboard serve on your local store.", http.StatusServiceUnavailable)
				return
			}
			handler(w, r)
		}
	}
	mux.HandleFunc("POST /api/replay/previews", guard(func(w http.ResponseWriter, r *http.Request) { s.ReplayExports.prepare(w, r) }))
	mux.HandleFunc("GET /api/replay/previews/{id}", guard(func(w http.ResponseWriter, r *http.Request) {
		j := s.ReplayExports.acquire(r.PathValue("id"))
		if j == nil {
			httpError(w, "Replay preview expired. Prepare it again.", http.StatusGone)
			return
		}
		defer s.ReplayExports.release(j)
		writeJSON(w, j.preview)
	}))
	mux.HandleFunc("DELETE /api/replay/previews/{id}", guard(func(w http.ResponseWriter, r *http.Request) {
		j := s.ReplayExports.acquire(r.PathValue("id"))
		if j != nil {
			s.ReplayExports.retire(j)
			s.ReplayExports.release(j)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET /api/replay/previews/{id}/download", guard(func(w http.ResponseWriter, r *http.Request) {
		j := s.ReplayExports.acquire(r.PathValue("id"))
		if j == nil {
			httpError(w, "Replay preview expired. Prepare it again.", http.StatusGone)
			return
		}
		defer s.ReplayExports.release(j)
		if r.URL.Query().Get("inventory") != j.preview.InventorySHA256 {
			httpError(w, "Confirm the current replay inventory before downloading.", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="agentprovenance-replay.zip"`)
		w.Header().Set("X-Content-SHA256", j.preview.ZIPSHA256)
		serveReplayFile(w, r, "agentprovenance-replay.zip", j.archive)
	}))
	mux.HandleFunc("GET /api/replay/previews/{id}/files/{file...}", guard(func(w http.ResponseWriter, r *http.Request) {
		j := s.ReplayExports.acquire(r.PathValue("id"))
		if j == nil {
			httpError(w, "Replay preview expired. Prepare it again.", http.StatusGone)
			return
		}
		defer s.ReplayExports.release(j)
		name := r.PathValue("file")
		// Only inventory-listed files are reachable, never the private ZIP or a
		// caller-supplied filesystem path. The snapshot DB was already removed.
		if !j.files[name] {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'; object-src 'none'; base-uri 'none'")
		serveReplayFile(w, r, name, filepath.Join(j.prepared.root, filepath.FromSlash(name)))
	}))
}

func serveReplayFile(w http.ResponseWriter, r *http.Request, name, path string) {
	f, err := os.Open(path)
	if err != nil {
		httpError(w, "Prepared replay file is unavailable.", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		httpError(w, "Prepared replay file is unavailable.", http.StatusInternalServerError)
		return
	}
	// Keep preview assets and downloads on bounded buffered reads instead of
	// platform-specific sendfile, which truncated large local browser responses.
	http.ServeContent(w, r, name, time.Time{}, io.NewSectionReader(f, 0, info.Size()))
}

func (m *ReplayExports) prepare(w http.ResponseWriter, r *http.Request) {
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/json" {
		httpError(w, "Replay preview requires JSON.", http.StatusUnsupportedMediaType)
		return
	}
	var input struct {
		Run               string   `json:"run"`
		Scope             string   `json:"scope"`
		Harness           string   `json:"harness,omitempty"`
		SessionID         string   `json:"session_id,omitempty"`
		ExcludeRecords    []string `json:"exclude_records,omitempty"`
		ExcludeCategories []string `json:"exclude_categories,omitempty"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil || d.Decode(new(any)) != io.EOF {
		httpError(w, "Supply run, scope, and optional session or exclusions as JSON.", http.StatusBadRequest)
		return
	}
	selection, err := (ReplaySelection{RunID: input.Run, Scope: input.Scope, Harness: input.Harness, SessionID: input.SessionID,
		ExcludeRecords: input.ExcludeRecords, ExcludeCategories: input.ExcludeCategories}).normalized()
	if err != nil {
		httpError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		httpError(w, "Could not create replay preview.", 500)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), m.timeout)
	j := &replayJob{preview: replayPreview{SchemaVersion: "agentprovenance.replay_preview/v1", ID: hex.EncodeToString(token[:])}, cancel: cancel, refs: 1}
	m.mu.Lock()
	if m.active || m.closed {
		m.mu.Unlock()
		cancel()
		httpError(w, "Another replay preview is active. Close it or wait for it to expire.", http.StatusConflict)
		return
	}
	m.job, m.active = j, true
	m.wg.Add(1)
	m.mu.Unlock()
	defer m.release(j)
	defer cancel()
	err = m.build(ctx, j, selection)
	if err != nil {
		m.retire(j)
		if r.Context().Err() != nil {
			return
		}
		code := http.StatusInternalServerError
		if errors.Is(err, agentcontext.ErrInvalidArgument) {
			code = http.StatusBadRequest
		} else if errors.Is(err, sql.ErrNoRows) {
			code = http.StatusNotFound
		} else if errors.Is(err, context.DeadlineExceeded) {
			code = http.StatusRequestTimeout
		}
		httpError(w, fmt.Sprintf("Could not prepare replay: %v", err), code)
		return
	}
	m.mu.Lock()
	if j.retired || ctx.Err() != nil {
		m.mu.Unlock()
		m.retire(j)
		httpError(w, "Replay preparation was canceled or timed out.", http.StatusRequestTimeout)
		return
	}
	j.preview.ExpiresAt = time.Now().UTC().Add(m.ttl)
	j.ready = true
	j.timer = time.AfterFunc(m.ttl, func() { m.retire(j) })
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, j.preview)
}

func (m *ReplayExports) build(ctx context.Context, j *replayJob, selection ReplaySelection) error {
	p, err := m.server.PrepareSelectedOfflineReplay(ctx, selection)
	if err != nil {
		return err
	}
	j.prepared = p
	j.archive = filepath.Join(p.root, "prepared-replay.zip")
	f, err := os.OpenFile(j.archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	err = p.WriteZIP(ctx, io.MultiWriter(f, hash))
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	info, err := os.Stat(j.archive)
	if err != nil {
		return err
	}
	// Deserialize the private frozen bytes, not the caller-visible copy.
	if err = json.Unmarshal(p.inventory, &j.preview.Inventory); err != nil {
		return err
	}
	j.preview.InventorySHA256, j.preview.ZIPBytes, j.preview.ZIPSHA256 = p.InventorySHA256, info.Size(), hex.EncodeToString(hash.Sum(nil))
	j.files = map[string]bool{"export-inventory.json": true}
	for _, file := range j.preview.Inventory.Files {
		j.files[file.Path] = true
	}
	return ctx.Err()
}
