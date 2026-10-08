package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	project "github.com/byteyellow/agentprovenance"
	"github.com/byteyellow/agentprovenance/demo"
	projectdocs "github.com/byteyellow/agentprovenance/docs"
	"github.com/byteyellow/agentprovenance/internal/buildinfo"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/spf13/cobra"
	"golang.org/x/net/html"
)

type publicReplayManifest struct {
	Guides        []projectdocs.Entry            `json:"guides"`
	SchemaVersion string                         `json:"schema_version"`
	Commit        string                         `json:"commit"`
	Summaries     json.RawMessage                `json:"summaries"`
	Runs          map[string]dashboard.ReplayRun `json:"runs"`
	Verifications []demoVerification             `json:"verifications"`
}

func demoExportCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{Use: "export", Short: "build a static website from the bundled public demos and guides", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("data-dir") || cmd.Flags().Changed("daemon-url") {
			return fmt.Errorf("demo export only includes the bundled public examples; omit --data-dir and --daemon-url")
		}
		if output == "" {
			return fmt.Errorf("--output is required")
		}
		target, err := filepath.Abs(output)
		if err != nil {
			return err
		}
		if _, err = os.Stat(target); err == nil {
			return fmt.Errorf("output already exists: %s; choose a new directory", target)
		} else if !os.IsNotExist(err) {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		stage, err := os.MkdirTemp(filepath.Dir(target), ".agentprov-site-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stage)
		work, err := os.MkdirTemp("", "agentprov-public-demo-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(work)
		storePath := filepath.Join(work, "state")
		catalog := demo.Catalog()
		manifest := publicReplayManifest{SchemaVersion: "agentprovenance.static_replay/v1", Guides: projectdocs.Pages(), Commit: buildinfo.Commit, Runs: map[string]dashboard.ReplayRun{}}
		for _, entry := range catalog {
			if entry.Run == "" {
				continue
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Verifying public demo %s...\n", entry.ID)
			verified, err := prepareDemo(work, storePath, entry, demo.Files)
			if err != nil {
				return err
			}
			manifest.Verifications = append(manifest.Verifications, verified)
		}
		db, cleanup, err := openLocalDB(storePath)
		if err != nil {
			return err
		}
		defer cleanup()
		server := dashboard.Server{DB: db}
		writer := &staticdata.Writer{Root: stage}
		for _, entry := range catalog {
			if entry.Run == "" {
				continue
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Exporting public replay %s...\n", entry.ID)
			snapshot, err := server.ExportReplay(cmd.Context(), entry.Run, writer)
			if err != nil {
				return err
			}
			manifest.Runs[entry.Run] = snapshot
		}
		mux := http.NewServeMux()
		mux.Handle("/", server.Handler())
		mux.HandleFunc("/demos/", demoGallery(catalog))
		get := func(route string) ([]byte, error) {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest("GET", route, nil).WithContext(cmd.Context()))
			if response.Code != 200 {
				return nil, fmt.Errorf("static page %s: HTTP %d", route, response.Code)
			}
			return response.Body.Bytes(), nil
		}
		manifest.Summaries, err = get("/api/runs")
		if err != nil {
			return err
		}
		write := func(name string, data []byte) error {
			dest := filepath.Join(stage, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
				return err
			}
			return os.WriteFile(dest, data, 0644)
		}
		for _, asset := range []string{"/assets/theme.css", "/assets/context.css", "/assets/context.js", "/demos/demo.css", "/demos/guide.js"} {
			b, err := get(asset)
			if err != nil {
				return err
			}
			if err = write(strings.TrimPrefix(asset, "/"), b); err != nil {
				return err
			}
		}
		if err = write("assets/replay.js", dashboard.ReplayScript()); err != nil {
			return err
		}
		if err = write("assets/site.js", []byte(publicSiteJS)); err != nil {
			return err
		}
		for _, locale := range []i18n.Locale{i18n.English, i18n.Chinese} {
			lang := string(locale)
			b, err := get("/assets/i18n.js?lang=" + lang)
			if err != nil {
				return err
			}
			if err = write("assets/i18n."+lang+".js", b); err != nil {
				return err
			}
			pages := map[string]string{lang + "/index.html": "/demos/", lang + "/replay.html": "/"}
			for _, entry := range catalog {
				pages[lang+"/demos/"+entry.ID+".html"] = "/demos/docs/" + entry.ID
			}
			for _, entry := range projectdocs.Pages() {
				pages[lang+"/guides/"+entry.ID+".html"] = "/demos/guide/" + entry.ID
			}
			for filename, route := range pages {
				raw, err := get(route + "?lang=" + lang)
				if err != nil {
					return err
				}
				page, err := staticDemoHTML(raw, filename, locale, route == "/")
				if err != nil {
					return err
				}
				if err = write(filename, page); err != nil {
					return err
				}
			}
		}
		for _, source := range []struct {
			Files  fs.FS
			Prefix string
		}{{demo.Files, "demos/assets/"}, {projectdocs.Files, "demos/assets/docs/"}} {
			err = fs.WalkDir(source.Files, ".", func(name string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return nil
				}
				switch path.Ext(name) {
				case ".png", ".gif", ".svg", ".json", ".yaml":
					b, err := fs.ReadFile(source.Files, name)
					if err != nil {
						return err
					}
					return write(source.Prefix+name, b)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		license, _ := project.Documentation.ReadFile("LICENSE")
		if err = write("demos/assets/project/LICENSE", license); err != nil {
			return err
		}
		for _, entry := range catalog {
			if entry.Run == "" {
				continue
			}
			for _, name := range []string{entry.Bundle + ".forensics.json.gz", entry.Bundle + ".forensics.dsse.json", entry.Key} {
				b, err := demo.Files.ReadFile(path.Join(entry.Directory, name))
				if err != nil {
					return err
				}
				if err = write("downloads/"+entry.ID+"/"+name, b); err != nil {
					return err
				}
			}
		}
		data, err := json.Marshal(manifest)
		if err != nil {
			return err
		}
		if err = write("replay-manifest.json", data); err != nil {
			return err
		}
		if err = write("index.html", []byte(publicSiteIndex)); err != nil {
			return err
		}
		if err = write(".nojekyll", nil); err != nil {
			return err
		}
		if err = os.Rename(stage, target); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Static demo site: %s\n7 signed replays, 9 demo guides, %d user guides and release history, English and Chinese.\n", target, len(projectdocs.Catalog()))
		return nil
	}}
	cmd.Flags().StringVar(&output, "output", "", "new directory for the static website")
	return cmd
}

func staticDemoURL(value, filename string, locale i18n.Locale) string {
	u, err := url.Parse(value)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return value
	}
	lang := string(locale)
	if selected, ok := i18n.Parse(u.Query().Get("lang")); ok {
		lang = string(selected)
	}
	var target string
	switch {
	case u.Path == "/":
		target = lang + "/replay.html"
	case u.Path == "/demos/":
		target = lang + "/index.html"
	case strings.HasPrefix(u.Path, "/demos/docs/"):
		target = lang + "/demos/" + strings.TrimPrefix(u.Path, "/demos/docs/") + ".html"
	case strings.HasPrefix(u.Path, "/demos/guide/"):
		target = lang + "/guides/" + strings.TrimPrefix(u.Path, "/demos/guide/") + ".html"
	case u.Path == "/assets/i18n.js":
		target = "assets/i18n." + lang + ".js"
	default:
		target = strings.TrimPrefix(u.Path, "/")
	}
	relative, err := filepath.Rel(filepath.FromSlash(path.Dir(filename)), filepath.FromSlash(target))
	if err != nil {
		return value
	}
	u.Path = filepath.ToSlash(relative)
	query := u.Query()
	query.Del("lang")
	if strings.HasSuffix(target, "/replay.html") {
		query.Set("live", "0")
	}
	u.RawQuery = query.Encode()
	return u.String()
}
func staticDemoHTML(raw []byte, filename string, locale i18n.Locale, replay bool) ([]byte, error) {
	text := string(raw)
	for _, pair := range [][2]string{{"Replay works offline. No API key or virtual machine required.", "Browse recorded executions. No install or API key required."}, {"Local replay", "Public replay"}, {"Local guide", "Documentation"}, {"Signed captures · verified locally", "Signed captures · checked at build"}, {"Signature and graph checks passed", "Signature and graph checks passed during site build"}} {
		text = strings.ReplaceAll(text, i18n.T(locale, pair[0]), i18n.T(locale, pair[1]))
	}
	doc, err := html.Parse(strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	prefix, _ := filepath.Rel(filepath.FromSlash(path.Dir(filename)), ".")
	// Go 1.23 can return "../." here; keep generated URLs stable across versions.
	prefix = path.Clean(filepath.ToSlash(prefix)) + "/"
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		for i, a := range node.Attr {
			if a.Key == "href" || a.Key == "src" {
				node.Attr[i].Val = staticDemoURL(a.Val, filename, locale)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
		if node.Type == html.ElementNode && node.Data == "head" {
			additions := `<meta name="agentprov-site-root" content="` + prefix + `"><script src="` + prefix + `assets/site.js"></script>`
			if replay {
				additions += `<script src="` + prefix + `assets/replay.js"></script><style>#live{display:none}.public-demo-bar{padding:10px 26px;border-bottom:1px solid var(--line);font-size:12px;color:var(--mut);display:flex;gap:20px;flex-wrap:wrap}.public-demo-bar a{color:var(--acc)}</style>`
			}
			fragment, err := html.ParseFragment(strings.NewReader(additions), node)
			if err == nil {
				for _, n := range fragment {
					node.AppendChild(n)
				}
			}
		}
		if node.Type == html.ElementNode && node.Data == "article" && strings.Contains(filename, "/demos/") {
			for _, entry := range demo.Catalog() {
				if entry.Run == "" || path.Base(filename) != entry.ID+".html" {
					continue
				}
				links := `<aside class="doc-note"><strong>` + i18n.T(locale, "Download signed evidence") + `</strong><p>`
				for _, item := range [][2]string{{entry.Bundle + ".forensics.json.gz", "Evidence bundle"}, {entry.Bundle + ".forensics.dsse.json", "Signature"}, {entry.Key, "Public key"}} {
					links += `<a href="` + prefix + `downloads/` + entry.ID + `/` + item[0] + `">` + i18n.T(locale, item[1]) + `</a> · `
				}
				links = strings.TrimSuffix(links, " · ") + `</p></aside>`
				fragment, err := html.ParseFragment(strings.NewReader(links), node)
				if err == nil {
					for _, n := range fragment {
						node.AppendChild(n)
					}
				}
			}
		}
		if replay && node.Type == html.ElementNode && node.Data == "body" {
			bar := `<nav class="public-demo-bar"><a href="index.html">` + i18n.T(locale, "← Demo library") + `</a><a href="guides/start.html">` + i18n.T(locale, "Documentation") + `</a><a href="https://github.com/ByteYellow/AgentProvenance/releases/latest">` + i18n.T(locale, "Download CLI") + `</a><span>` + i18n.T(locale, "Public replay · recorded execution") + `</span></nav>`
			fragment, err := html.ParseFragment(strings.NewReader(bar), node)
			if err == nil {
				for _, n := range fragment {
					node.InsertBefore(n, node.FirstChild)
				}
			}
		}
	}
	walk(doc)
	var out bytes.Buffer
	err = html.Render(&out, doc)
	return out.Bytes(), err
}

const publicSiteIndex = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AgentProvenance demos</title><script>
const valid=v=>/^(zh|zh-cn|zh-hans)$/i.test(v||'')?'zh-CN':/^en(?:-|$)/i.test(v||'')?'en':null;
let saved;try{saved=localStorage.getItem('agentprov_language');}catch{}
const q=new URLSearchParams(location.search),browser=(navigator.languages||[navigator.language]).map(valid).find(Boolean),lang=valid(q.get('lang'))||valid(saved)||browser||'en';
location.replace(lang+'/index.html');</script><body><p><a href="en/index.html">English demos</a> · <a href="zh-CN/index.html">中文示例</a></p></body></html>`
const publicSiteJS = `'use strict';
// Language selection is presentation only; saved evidence is never translated.
document.addEventListener('click',event=>{const a=event.target.closest('.language-switch a');if(a){try{localStorage.setItem('agentprov_language',a.lang);}catch{}}});
const current=new URL(location.href);if(current.pathname.endsWith('/replay.html')){current.searchParams.set('live','0');history.replaceState(null,'',current);}
`
