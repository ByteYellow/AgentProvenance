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

	"github.com/byteyellow/agentprovenance/demo"
	"github.com/byteyellow/agentprovenance/internal/buildinfo"
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
	functions := template.FuncMap{"runURL": demoRunURL, "category": demoCategory}
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
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
				http.NotFound(w, r)
				return
			}
			b, err := demo.Files.ReadFile(name)
			if err != nil {
				http.NotFound(w, r)
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
		if r.URL.Path == "/demos/" {
			_ = gallery.Execute(w, data)
			return
		}
		for _, entry := range entries {
			if r.URL.Path != "/demos/docs/"+entry.ID {
				continue
			}
			b, err := demo.Files.ReadFile(path.Join(entry.Directory, "README.md"))
			if err != nil {
				http.Error(w, "guide unavailable", http.StatusInternalServerError)
				return
			}
			page := data
			page.Entry = entry
			page.Content, page.Headings, err = renderDemoGuide(entry, entries, b)
			if err != nil {
				http.Error(w, "guide rendering failed", http.StatusInternalServerError)
				return
			}
			_ = guide.Execute(w, page)
			return
		}
		http.NotFound(w, r)
	}
}

func renderDemoGuide(entry demo.Entry, entries []demo.Entry, source []byte) (template.HTML, []demoHeading, error) {
	// Leave unsafe HTML disabled: guide source cannot introduce scripts or raw
	// HTML. Goldmark also rejects dangerous link/image URL schemes.
	md := goldmark.New(goldmark.WithExtensions(extension.GFM), goldmark.WithParserOptions(parser.WithAutoHeadingID()))
	doc := md.Parser().Parse(text.NewReader(source))
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
			node.Destination = []byte(demoGuideLink(entry, entries, string(node.Destination)))
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

func demoGuideLink(entry demo.Entry, entries []demo.Entry, href string) string {
	u, err := url.Parse(href)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path == "" || strings.HasPrefix(u.Path, "/") {
		return href
	}
	resolved := path.Clean(path.Join("demo", entry.Directory, u.Path))
	for _, candidate := range entries {
		root := "demo/" + candidate.Directory
		if resolved == root || resolved == root+"/README.md" {
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
