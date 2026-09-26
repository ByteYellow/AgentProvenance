package cli

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode"

	"github.com/byteyellow/agentprovenance/demo"
	"github.com/byteyellow/agentprovenance/internal/buildinfo"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
)

//go:embed demo_ui/gallery.html
var demoGalleryHTML string

//go:embed demo_ui/guide.html
var demoGuideHTML string

//go:embed demo_ui/demo.css
var demoCSS []byte

//go:embed demo_ui/guide.js
var demoGuideJS []byte

type demoHeading struct{ ID, Title string }
type demoPage struct {
	Lang                        i18n.Locale
	EnglishURL, ChineseURL      string
	Entries                     []demo.Entry
	Entry                       demo.Entry
	ReplayCount, EvaluatorCount int
	Content                     template.HTML
	Headings                    []demoHeading
}

func demoCategory(entry demo.Entry) string {
	switch entry.Directory {
	case "snake-supply-chain":
		return "Single agent"
	case "multiagent-provenance":
		return "Agent team"
	case "k8s-cross-pod-a2a", "k8s-substrate":
		return "Kubernetes"
	case "grok-codebase-exfil":
		return "Outbound data"
	default:
		return "External evaluator"
	}
}

func demoGallery(entries []demo.Entry) http.HandlerFunc {
	functions := template.FuncMap{"runURL": demoRunURL, "category": demoCategory, "tr": i18n.T, "localURL": i18n.URL}
	gallery := template.Must(template.New("gallery").Funcs(functions).Parse(demoGalleryHTML))
	guide := template.Must(template.New("guide").Funcs(functions).Parse(demoGuideHTML))
	data := demoPage{Entries: entries}
	for _, entry := range entries {
		if entry.Run != "" {
			data.ReplayCount++
		} else {
			data.EvaluatorCount++
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		lang := i18n.FromRequest(r)
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, i18n.T(lang, "method not allowed"), http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/demos/demo.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			_, _ = w.Write(demoCSS)
			return
		case "/demos/guide.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			_, _ = w.Write(demoGuideJS)
			return
		}
		if name, ok := strings.CutPrefix(r.URL.Path, "/demos/assets/"); ok {
			// Serve only the images and supplemental JSON embedded for these guides.
			if path.Ext(name) != ".png" && path.Ext(name) != ".json" {
				http.Error(w, i18n.T(lang, "page or resource not found"), http.StatusNotFound)
				return
			}
			b, err := demo.Files.ReadFile(name)
			if err != nil {
				http.Error(w, i18n.T(lang, "page or resource not found"), http.StatusNotFound)
				return
			}
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if path.Ext(name) == ".png" {
				w.Header().Set("Content-Type", "image/png")
			} else {
				w.Header().Set("Content-Type", "application/json")
			}
			_, _ = w.Write(b)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Language", string(lang))
		i18n.Remember(w, r)
		page := data
		page.Lang = lang
		page.EnglishURL = i18n.URL(r.URL.RequestURI(), i18n.English)
		page.ChineseURL = i18n.URL(r.URL.RequestURI(), i18n.Chinese)
		if r.URL.Path == "/demos/" {
			_ = gallery.Execute(w, page)
			return
		}
		for _, entry := range entries {
			if r.URL.Path != "/demos/docs/"+entry.ID {
				continue
			}
			b, err := demo.Files.ReadFile(path.Join(entry.Directory, i18n.GuideFilename(lang)))
			if err != nil {
				http.Error(w, i18n.T(lang, "guide unavailable"), http.StatusInternalServerError)
				return
			}
			page.Entry = entry
			page.Content, page.Headings, err = renderLocalizedDemoGuide(entry, entries, b, lang)
			if err != nil {
				http.Error(w, i18n.T(lang, "guide rendering failed"), http.StatusInternalServerError)
				return
			}
			_ = guide.Execute(w, page)
			return
		}
		http.Error(w, i18n.T(lang, "page or resource not found"), http.StatusNotFound)
	}
}

func renderDemoGuide(entry demo.Entry, entries []demo.Entry, source []byte) (template.HTML, []demoHeading, error) {
	return renderLocalizedDemoGuide(entry, entries, source, i18n.English)
}

func renderLocalizedDemoGuide(entry demo.Entry, entries []demo.Entry, source []byte, lang i18n.Locale) (template.HTML, []demoHeading, error) {
	// Leave unsafe HTML disabled: guide source cannot introduce scripts or raw
	// HTML. Goldmark also rejects dangerous link/image URL schemes.
	md := goldmark.New(goldmark.WithExtensions(extension.GFM), goldmark.WithParserOptions(parser.WithAutoHeadingID()))
	context := parser.NewContext()
	if lang == i18n.Chinese {
		context = parser.NewContext(parser.WithIDs(&demoHeadingIDs{used: map[string]bool{}}))
	}
	doc := md.Parser().Parse(text.NewReader(source), parser.WithContext(context))
	var headings []demoHeading
	if err := ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch node := n.(type) {
		case *ast.Heading:
			if node.Level == 2 {
				id, _ := node.AttributeString("id")
				headings = append(headings, demoHeading{fmt.Sprintf("%s", id), string(node.Text(source))})
			}
		case *ast.Link:
			linkLang := lang
			if target, err := url.Parse(string(node.Destination)); err == nil {
				switch path.Base(target.Path) {
				case "README.md":
					linkLang = i18n.English
				case "README.zh-CN.md":
					linkLang = i18n.Chinese
				}
			}
			node.Destination = []byte(demoGuideLink(entry, entries, string(node.Destination)))
			if strings.HasPrefix(string(node.Destination), "/demos/docs/") {
				node.Destination = []byte(i18n.URL(string(node.Destination), linkLang))
			}
		case *ast.Image:
			node.Destination = []byte(demoGuideLink(entry, entries, string(node.Destination)))
		}
		return ast.WalkContinue, nil
	}); err != nil {
		return "", nil, err
	}
	var out bytes.Buffer
	if err := md.Renderer().Render(&out, source, doc); err != nil {
		return "", nil, err
	}
	return template.HTML(out.String()), headings, nil
}

// Goldmark's default heading IDs discard non-ASCII characters. Keep Chinese
// titles addressable by their text, with deterministic suffixes for duplicates.
type demoHeadingIDs struct{ used map[string]bool }

func (ids *demoHeadingIDs) Generate(value []byte, _ ast.NodeKind) []byte {
	var slug strings.Builder
	for _, r := range strings.TrimSpace(string(value)) {
		switch {
		case unicode.IsLetter(r), unicode.IsNumber(r):
			slug.WriteRune(unicode.ToLower(r))
		case unicode.IsSpace(r), r == '-', r == '_':
			slug.WriteByte('-')
		}
	}
	base := slug.String()
	if base == "" {
		base = "heading"
	}
	id := base
	for n := 1; ids.used[id]; n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	ids.used[id] = true
	return []byte(id)
}

func (ids *demoHeadingIDs) Put(value []byte) { ids.used[string(value)] = true }

func demoGuideLink(entry demo.Entry, entries []demo.Entry, href string) string {
	u, err := url.Parse(href)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path == "" || strings.HasPrefix(u.Path, "/") {
		return href
	}
	resolved := path.Clean(path.Join("demo", entry.Directory, u.Path))
	// Two historical Grok captures share a guide directory. A language switch
	// in that guide must retain the selected capture and its replay link.
	for _, candidate := range append([]demo.Entry{entry}, entries...) {
		root := "demo/" + candidate.Directory
		if resolved == root || resolved == root+"/README.md" || resolved == root+"/README.zh-CN.md" {
			u.Path = "/demos/docs/" + candidate.ID
			return u.String()
		}
	}
	if file, ok := strings.CutPrefix(resolved, "demo/"); ok && (path.Ext(file) == ".png" || path.Ext(file) == ".json") {
		if _, err := demo.Files.ReadFile(file); err == nil {
			u.Path = "/demos/assets/" + file
			return u.String()
		}
	}
	// Other repository references remain usable without pretending their files
	// are in the embedded reader. They open only when the reader follows them.
	u.Scheme, u.Host = "https", "github.com"
	ref := buildinfo.Commit
	if ref == "" || ref == "unknown" {
		ref = "main"
	}
	u.Path = "/ByteYellow/AgentProvenance/blob/" + ref + "/" + resolved
	return u.String()
}
