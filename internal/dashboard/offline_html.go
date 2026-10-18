package dashboard

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"golang.org/x/net/html"
)

func offlineReplayHTML(raw []byte, locale i18n.Locale) ([]byte, error) {
	doc, err := html.Parse(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var head, body *html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if n.Data == "head" {
				head = n
			} else if n.Data == "body" {
				body = n
			}
			for i, a := range n.Attr {
				if a.Key != "href" && a.Key != "src" {
					continue
				}
				u, parseErr := url.Parse(a.Val)
				if parseErr != nil {
					continue
				}
				switch {
				case u.Path == "/assets/i18n.js":
					n.Attr[i].Val = "../assets/i18n." + string(locale) + ".js"
				case strings.HasPrefix(u.Path, "/assets/"):
					n.Attr[i].Val = ".." + u.Path
				case u.Path == "/":
					lang := u.Query().Get("lang")
					if lang != "zh-CN" {
						lang = "en"
					}
					n.Attr[i].Val = "../" + lang + "/index.html"
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if head == nil || body == nil {
		return nil, fmt.Errorf("dashboard HTML is missing its head or body")
	}
	prepend := func(parent *html.Node, text string) error {
		nodes, err := html.ParseFragment(strings.NewReader(text), parent)
		if err != nil {
			return err
		}
		first := parent.FirstChild
		for _, n := range nodes {
			parent.InsertBefore(n, first)
		}
		return nil
	}
	// No network connections, embedded documents or form submissions are needed
	// to view an export. The application scripts are the same trusted reader.
	if err = prepend(head, `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"><meta name="agentprov-site-root" content="../"><script src="../assets/catalog.js"></script><script src="../assets/offline.js"></script><script src="../assets/replay.js"></script><style>#live{display:none}.offline-replay-bar{padding:10px 26px;border-bottom:1px solid var(--line);font-size:12px;color:var(--mut);display:flex;gap:16px;flex-wrap:wrap}.offline-replay-bar a{color:var(--acc)}</style>`); err != nil {
		return nil, err
	}
	label, scope, inventory := "Offline replay · unsigned sharing copy", "Whole run · recorded content", "Export inventory"
	if locale == i18n.Chinese {
		label, scope, inventory = "离线回放 · 未签名的分享副本", "整个 Run · 已保存内容", "导出清单"
	}
	if err = prepend(body, `<nav class="offline-replay-bar"><strong>`+label+`</strong><span>`+scope+`</span><a href="../export-inventory.json" target="_blank" rel="noopener">`+inventory+`</a></nav>`); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = html.Render(&out, doc)
	return out.Bytes(), err
}

const offlineReplayIndex = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>AgentProvenance offline replay</title></head><body><p><a href="en/index.html">English replay</a> · <a href="zh-CN/index.html">中文回放</a></p><script>
const q=new URLSearchParams(location.search),lang=/^zh/i.test(q.get('lang')||navigator.language)?'zh-CN':'en';q.set('live','0');location.replace(lang+'/index.html?'+q.toString());
</script></body></html>`
