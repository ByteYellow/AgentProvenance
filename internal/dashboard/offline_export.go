package dashboard

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	project "github.com/byteyellow/agentprovenance"
	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/buildinfo"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
)

type ReplayFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// ReplayInventory describes the exact files frozen for a share. The inventory
// excludes itself; its digest is returned separately by the preparation step.
type ReplayInventory struct {
	SchemaVersion     string                         `json:"schema_version"`
	RunID             string                         `json:"run_id"`
	Scope             string                         `json:"scope"`
	CreatedAt         string                         `json:"created_at"`
	Commit            string                         `json:"commit"`
	Signed            bool                           `json:"signed"`
	Events            int                            `json:"events"`
	Contents          ReplayContents                 `json:"contents"`
	Selection         ReplayFile                     `json:"record_selection"`
	SelectionSummary  *ReplaySelectionSummary        `json:"selection_summary,omitempty"`
	AnalysisOmissions map[string]int                 `json:"analysis_omissions,omitempty"`
	CapturePolicy     *agentcontext.CapturePolicy    `json:"capture_policy,omitempty"`
	CaptureSettings   *observability.CaptureSettings `json:"capture_settings,omitempty"`
	Runs              []ReplayRunInventory           `json:"runs,omitempty"`
	Files             []ReplayFile                   `json:"files"`
	Bytes             int64                          `json:"bytes_excluding_inventory"`
}

// Counts describe saved sources, not successful operations or collection coverage.
type ReplayContents struct {
	Sessions       int            `json:"sessions"`
	ContextEntries int            `json:"context_entries"`
	LatestEntries  int            `json:"latest_context_entries"`
	BodyRefs       int            `json:"context_body_refs"`
	RawRefs        int            `json:"context_raw_refs"`
	Sources        map[string]int `json:"indexed_sources"`
}

// PreparedReplay owns a private, frozen directory, independent of the source
// database and workspace. Close removes it after download or cancellation.
type PreparedReplay struct {
	Inventory       ReplayInventory
	InventorySHA256 string
	root            string
	inventory       []byte
}

func (p *PreparedReplay) Close() error { return os.RemoveAll(p.root) }

type replaySnapshot struct {
	DB   *sql.DB
	root string
}

func (snapshot *replaySnapshot) Close() {
	_ = snapshot.DB.Close()
	_ = os.RemoveAll(snapshot.root)
}

// A separate SQLite snapshot keeps selection and every projection on the same
// committed database version while the live collector continues writing.
func (s Server) freezeReplaySource(ctx context.Context) (_ *replaySnapshot, err error) {
	private, err := os.MkdirTemp("", "agentprov-replay-source-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(private)
		}
	}()
	path := filepath.Join(private, "snapshot.db")
	if _, err = s.DB.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return nil, fmt.Errorf("freeze replay database: %w", err)
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=query_only(1)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &replaySnapshot{DB: db, root: private}, nil
}

// PrepareOfflineReplay freezes one complete run. Selection is explicit here;
// linked runs remain references and are never recursively exported. Source
// content is read only through the dashboard's saved-evidence readers.
func (s Server) PrepareOfflineReplay(ctx context.Context, run string) (_ *PreparedReplay, err error) {
	return s.PrepareSelectedOfflineReplay(ctx, ReplaySelection{RunID: run, Scope: "whole_run"})
}

// PrepareSelectedOfflineReplay freezes a run and projects all replay readers
// onto the same explicit selection. Related records outside it stay references.
func (s Server) PrepareSelectedOfflineReplay(ctx context.Context, input ReplaySelection) (_ *PreparedReplay, err error) {
	return s.PrepareOfflineReplaySet(ctx, []ReplaySelection{input})
}

// PrepareOfflineReplaySet prepares only the explicitly selected runs. Every
// index is derived from one committed snapshot, with a separate selection for
// each run. Relationship discovery never adds another run to the export.
func (s Server) PrepareOfflineReplaySet(ctx context.Context, inputs []ReplaySelection) (_ *PreparedReplay, err error) {
	inputs, err = normalizeReplaySelections(inputs)
	if err != nil {
		return nil, err
	}
	snapshot, err := s.freezeReplaySource(ctx)
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	return s.prepareReplaySet(ctx, snapshot, inputs)
}

func (s Server) prepareReplaySet(ctx context.Context, snapshot *replaySnapshot, inputs []ReplaySelection) (_ *PreparedReplay, err error) {
	root, err := os.MkdirTemp("", "agentprov-readonly-replay-")
	if err != nil {
		return nil, err
	}
	p := &PreparedReplay{root: root}
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	labels := map[string]string{}
	visibleRuns := make([]string, 0, len(inputs))
	for _, input := range inputs {
		visibleRuns = append(visibleRuns, input.RunID)
		if label := s.RunLabels[input.RunID]; label != "" {
			labels[input.RunID] = label
		}
	}
	frozen := Server{DB: snapshot.DB, RunLabels: labels}
	get := replayResource(ctx, frozen.Handler())
	writer := &staticdata.Writer{Root: root}
	catalog := struct {
		SchemaVersion string               `json:"schema_version"`
		Summaries     []runSummary         `json:"summaries"`
		Runs          map[string]ReplayRun `json:"runs"`
	}{SchemaVersion: "agentprovenance.static_replay/v1", Runs: map[string]ReplayRun{}}
	var runs []ReplayRunInventory
	partial, analysisOmitted := false, false
	for _, input := range inputs {
		item, replay, err := frozen.prepareReplayRun(ctx, snapshot, input, visibleRuns, writer)
		if err != nil {
			return nil, fmt.Errorf("prepare replay run %q: %w", input.RunID, err)
		}
		runs = append(runs, item)
		catalog.Summaries = append(catalog.Summaries, runSummary{Run: input.RunID, Events: item.Events})
		catalog.Runs[input.RunID] = replay
		partial = partial || (&replaySelectionPlan{Selection: input}).partial()
		analysisOmitted = analysisOmitted || len(item.AnalysisOmissions) > 0
	}
	manifest, err := json.Marshal(catalog)
	if err != nil {
		return nil, err
	}
	write := func(name string, data []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		return os.WriteFile(path, data, 0600)
	}
	selectionFile := runs[0].Selection
	if len(runs) > 1 {
		data, err := json.Marshal(struct {
			SchemaVersion string               `json:"schema_version"`
			Runs          []ReplayRunInventory `json:"runs"`
		}{"agentprovenance.replay_selection_set/v1", runs})
		if err != nil {
			return nil, err
		}
		selectionFile = ReplayFile{Path: "record-selection.json", SHA256: replayDigest(data), Bytes: int64(len(data))}
		if err = write(selectionFile.Path, data); err != nil {
			return nil, err
		}
	}
	assets := map[string][]byte{
		"theme.css": themeCSS, "context.css": contextCSS, "context.js": contextJS,
		"workspace.css": workspaceCSS, "workspace.js": workspaceJS,
		"access-control.css": accessControlCSS, "access-control.js": accessControlJS,
		"search-engine.js": searchEngineJS, "search.js": searchJS, "search.css": searchCSS,
		"compare-engine.js": compareEngineJS, "compare.js": compareJS, "compare.css": compareCSS,
		"export.js": exportJS, "export.css": exportCSS,
		"replay.js": replayJS, "offline.js": offlineJS,
		"catalog.js": []byte(`window.AgentProvOfflineCatalog="` + base64.StdEncoding.EncodeToString(manifest) + `";`),
	}
	for name, data := range assets {
		if err = write("assets/"+name, data); err != nil {
			return nil, err
		}
	}
	// file:// cannot fetch sibling JSON. A fixed script wrapper transports only
	// base64 gzip bytes to the reader, which still checks decoded length/hash.
	shards, err := os.ReadDir(filepath.Join(root, "data"))
	if err != nil {
		return nil, err
	}
	for _, shard := range shards {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		name := "data/" + shard.Name()
		compressed, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if readErr != nil {
			return nil, readErr
		}
		data := []byte(`window.AgentProvOffline.accept("` + name + `","` + base64.StdEncoding.EncodeToString(compressed) + `");`)
		if err = write(strings.TrimSuffix(name, ".json.gz")+".js", data); err != nil {
			return nil, err
		}
		if err = os.Remove(filepath.Join(root, filepath.FromSlash(name))); err != nil {
			return nil, err
		}
	}
	for _, lang := range []i18n.Locale{i18n.English, i18n.Chinese} {
		script, getErr := get("/assets/i18n.js?lang=" + string(lang))
		if getErr != nil {
			return nil, getErr
		}
		if err = write("assets/i18n."+string(lang)+".js", script); err != nil {
			return nil, err
		}
		raw, getErr := get("/?lang=" + string(lang))
		if getErr != nil {
			return nil, getErr
		}
		page, pageErr := offlineReplayHTMLSet(raw, lang, inputs, partial, analysisOmitted)
		if pageErr != nil {
			return nil, pageErr
		}
		if err = write(string(lang)+"/index.html", page); err != nil {
			return nil, err
		}
	}
	if err = write("index.html", []byte(offlineReplayIndex)); err != nil {
		return nil, err
	}
	license, err := project.Documentation.ReadFile("LICENSE")
	if err != nil {
		return nil, err
	}
	if err = write("LICENSE", license); err != nil {
		return nil, err
	}
	first := runs[0]
	p.Inventory = ReplayInventory{SchemaVersion: "agentprovenance.replay_inventory/v1", RunID: first.RunID, Scope: first.Scope, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Commit: buildinfo.Commit, Events: first.Events, Contents: first.Contents, Selection: selectionFile}
	if len(runs) == 1 {
		p.Inventory.AnalysisOmissions = first.AnalysisOmissions
		p.Inventory.CapturePolicy, p.Inventory.CaptureSettings = first.CapturePolicy, first.CaptureSettings
		p.Inventory.SelectionSummary = &first.SelectionSummary
	} else {
		p.Inventory.Scope, p.Inventory.Runs = "run_set", runs
		p.Inventory.Events = 0
		p.Inventory.Contents = ReplayContents{Sources: map[string]int{}}
		for _, item := range runs {
			p.Inventory.Events += item.Events
			p.Inventory.Contents.add(item.Contents)
		}
	}
	if err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		p.Inventory.Files = append(p.Inventory.Files, ReplayFile{Path: filepath.ToSlash(rel), SHA256: replayDigest(data), Bytes: int64(len(data))})
		p.Inventory.Bytes += int64(len(data))
		if p.Inventory.Bytes > 1280<<20 {
			return fmt.Errorf("offline replay exceeds 1280 MiB")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(p.Inventory.Files, func(i, j int) bool { return p.Inventory.Files[i].Path < p.Inventory.Files[j].Path })
	encoded, err := json.MarshalIndent(p.Inventory, "", "  ")
	if err != nil {
		return nil, err
	}
	p.InventorySHA256 = replayDigest(encoded)
	p.inventory = bytes.Clone(encoded)
	if err = write("export-inventory.json", encoded); err != nil {
		return nil, err
	}
	return p, nil
}

func describeReplay(root string, replay ReplayRun) (ReplayContents, error) {
	read := func(ref staticdata.Ref, out any) error {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(ref.Path)))
		if err != nil {
			return err
		}
		defer f.Close()
		z, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer z.Close()
		b, err := io.ReadAll(io.LimitReader(z, int64(ref.Bytes)+1))
		if err != nil {
			return err
		}
		if len(b) != ref.Bytes || replayDigest(b) != ref.SHA256 {
			return fmt.Errorf("prepared replay index changed")
		}
		return json.Unmarshal(b, out)
	}
	contents := ReplayContents{Sessions: len(replay.Sessions), Sources: map[string]int{}}
	var entries replayContext
	if err := read(replay.Context, &entries); err != nil {
		return contents, err
	}
	contents.ContextEntries, contents.LatestEntries = len(entries.Entries), len(entries.Latest)
	bodies, raw := map[string]bool{}, map[string]bool{}
	for _, entry := range entries.Entries {
		if entry.Content.State == "stored" && entry.Content.Ref != "" {
			bodies[entry.Content.Ref] = true
		}
		if entry.RawContent.State == "stored" && entry.RawContent.Ref != "" {
			raw[entry.RawContent.Ref] = true
		}
	}
	contents.BodyRefs, contents.RawRefs = len(bodies), len(raw)
	for _, ref := range replay.Search[`["",""]`] {
		var page SearchSources
		if err := read(ref, &page); err != nil {
			return contents, err
		}
		for _, source := range page.Sources {
			contents.Sources[source.Category]++
		}
	}
	return contents, nil
}

func replayDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func replayResource(ctx context.Context, handler http.Handler) func(string) ([]byte, error) {
	return func(route string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil).WithContext(ctx))
		if w.Code != http.StatusOK {
			return nil, fmt.Errorf("replay resource %s: HTTP %d", route, w.Code)
		}
		return bytes.Clone(w.Body.Bytes()), nil
	}
}

// WriteZIP uses only the prepared inventory, never the live database. Each file
// is checked before writing, so a changed or missing shard aborts the download.
func (p *PreparedReplay) WriteZIP(ctx context.Context, out io.Writer) error {
	var frozen ReplayInventory
	if err := json.Unmarshal(p.inventory, &frozen); err != nil {
		return fmt.Errorf("prepared replay inventory is unavailable: %w", err)
	}
	z := zip.NewWriter(out)
	files := append(frozen.Files, ReplayFile{Path: "export-inventory.json", SHA256: replayDigest(p.inventory)})
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(p.root, filepath.FromSlash(file.Path)))
		if err != nil {
			return err
		}
		if replayDigest(data) != file.SHA256 || (file.Path != "export-inventory.json" && int64(len(data)) != file.Bytes) {
			return fmt.Errorf("prepared replay file changed: %s", file.Path)
		}
		header := &zip.FileHeader{Name: file.Path, Method: zip.Deflate}
		header.SetMode(0600)
		w, err := z.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err = w.Write(data); err != nil {
			return err
		}
	}
	return z.Close()
}
