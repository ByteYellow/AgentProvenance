package cli

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/byteyellow/agentprovenance/demo"
	projectdocs "github.com/byteyellow/agentprovenance/docs"
	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func projectDocLink(source, href string) string {
	u, err := url.Parse(href)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path == "" {
		return href
	}
	resolved := path.Clean(path.Join(path.Dir(source), u.Path))
	if local, ok := localProjectDocURL(resolved, u); ok {
		return local
	}
	return repositoryGuideURL(resolved, u)
}
func localProjectDocURL(resolved string, u *url.URL) (string, bool) {
	lang := i18n.English
	file := strings.TrimPrefix(resolved, "docs/")
	if strings.HasPrefix(file, "zh-CN/") {
		lang = i18n.Chinese
		file = strings.TrimPrefix(file, "zh-CN/")
	}
	for _, entry := range projectdocs.Pages() {
		for _, language := range []i18n.Locale{i18n.English, i18n.Chinese} {
			if resolved == entry.Source(language == i18n.Chinese) {
				u.Path = "/demos/guide/" + entry.ID
				return i18n.URL(u.String(), language), true
			}
		}
	}
	for _, entry := range demo.Catalog() {
		for _, language := range []i18n.Locale{i18n.English, i18n.Chinese} {
			if resolved == "demo/"+entry.Directory+"/"+i18n.GuideFilename(language) {
				u.Path = "/demos/docs/" + entry.ID
				return i18n.URL(u.String(), language), true
			}
		}
	}
	if file, ok := strings.CutPrefix(resolved, "demo/"); ok && (path.Ext(file) == ".png" || path.Ext(file) == ".gif" || path.Ext(file) == ".json") {
		if _, err := demo.Files.ReadFile(file); err == nil {
			u.Path = "/demos/assets/" + file
			return u.String(), true
		}
	}
	if resolved == "demo/README.md" || resolved == "demo/README.zh-CN.md" {
		if strings.HasSuffix(resolved, ".zh-CN.md") {
			lang = i18n.Chinese
		}
		u.Path = "/demos/"
		u.Fragment = ""
		return i18n.URL(u.String(), lang), true
	}
	if resolved == "LICENSE" {
		u.Path = "/demos/assets/project/LICENSE"
		return u.String(), true
	}
	if strings.HasPrefix(resolved, "docs/") && (path.Ext(file) == ".png" || path.Ext(file) == ".svg" || path.Ext(file) == ".gif" || path.Ext(file) == ".yaml") {
		if _, err := projectdocs.Files.ReadFile(strings.TrimPrefix(resolved, "docs/")); err == nil {
			u.Path = "/demos/assets/" + resolved
			return u.String(), true
		}
	}
	return "", false
}

// projectMarkdown preserves the README's centered illustrations without enabling
// arbitrary HTML in documentation. Markdown still applies URL-scheme checks.
func projectMarkdown(source []byte) []byte {
	// Protect code samples before converting presentation-only markup.
	var protected []string
	var lines []string
	var fence string
	var block strings.Builder
	protect := func(text string) string {
		protected = append(protected, text)
		return fmt.Sprintf("\x00project-code-%d\x00", len(protected)-1)
	}
	for _, line := range strings.SplitAfter(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if fence != "" {
			block.WriteString(line)
			if strings.HasPrefix(trimmed, fence) {
				lines = append(lines, protect(block.String()))
				block.Reset()
				fence = ""
			}
			continue
		}
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			fence = trimmed[:3]
			block.WriteString(line)
			continue
		}
		if strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t") {
			line = protect(line)
		}
		lines = append(lines, line)
	}
	if block.Len() > 0 {
		lines = append(lines, protect(block.String()))
	}
	s := strings.Join(lines, "")
	s = centeredProjectImage.ReplaceAllStringFunc(s, func(block string) string {
		z := html.NewTokenizer(strings.NewReader(block))
		for {
			token := z.Next()
			if token == html.ErrorToken {
				return block
			}
			if token != html.StartTagToken && token != html.SelfClosingTagToken {
				continue
			}
			t := z.Token()
			if t.Data != "img" {
				continue
			}
			var src, alt string
			for _, a := range t.Attr {
				if a.Key == "src" {
					src = a.Val
				}
				if a.Key == "alt" {
					alt = a.Val
				}
			}
			if src == "" {
				return block
			}
			alt = strings.NewReplacer("[", "\\[", "]", "\\]").Replace(alt)
			src = strings.NewReplacer("(", "%28", ")", "%29", " ", "%20").Replace(src)
			return "![" + alt + "](" + src + ")"
		}
	})
	s = strings.ReplaceAll(s, "<div align=\"center\">", "")
	s = strings.ReplaceAll(s, "</div>", "")
	for i, text := range protected {
		s = strings.ReplaceAll(s, fmt.Sprintf("\x00project-code-%d\x00", i), text)
	}
	return []byte(s)
}

var centeredProjectImage = regexp.MustCompile(`(?s)<p align="center">\s*<img\s[^>]*>\s*</p>`)
