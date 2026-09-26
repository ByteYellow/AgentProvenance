package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/demo"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

type demoVerification struct {
	ID                string                  `json:"id"`
	SignatureVerified bool                    `json:"signature_verified"`
	Graph             provenance.VerifyResult `json:"graph"`
}

func demoCmd() *cobra.Command {
	var list, noBrowser, jsonOutput bool
	cmd := &cobra.Command{
		Use:   "demo [name]",
		Short: "browse all demos or replay one signed example offline",
		Long:  "Open the demo gallery, or replay a named signed capture. Bundles and guides are embedded in the CLI. Each invocation uses an isolated temporary store, removed on normal exit. Nothing is executed from a capture; evaluator examples require separate, explicit setup. This command does not use --data-dir or --daemon-url.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog := demo.Catalog()
			if list {
				if len(args) != 0 {
					return fmt.Errorf("--list does not take a demo name")
				}
				if jsonOutput {
					return json.NewEncoder(cmd.OutOrStdout()).Encode(catalog)
				}
				for _, entry := range catalog {
					kind := "signed replay"
					if entry.Run == "" {
						kind = "setup guide"
					}
					fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", entry.ID, kind, entry.Title)
				}
				return nil
			}
			if cmd.Flags().Changed("data-dir") || cmd.Flags().Changed("daemon-url") {
				return fmt.Errorf("demo uses its own temporary store; omit --data-dir and --daemon-url")
			}
			selected := catalog
			var chosen *demo.Entry
			if len(args) > 0 {
				for _, entry := range catalog {
					if entry.ID == args[0] {
						e := entry
						chosen = &e
						break
					}
				}
				if chosen == nil {
					return fmt.Errorf("unknown demo %q; use agentprov demo --list", args[0])
				}
				selected = []demo.Entry{*chosen}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			dir, err := os.MkdirTemp("", "agentprov-demo-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(dir)
			dataDir := filepath.Join(dir, "state")
			verified := make([]demoVerification, 0)
			for _, entry := range selected {
				if err := ctx.Err(); err != nil {
					return err
				}
				if entry.Run == "" {
					continue
				}
				if !jsonOutput {
					fmt.Fprintf(cmd.ErrOrStderr(), "Verifying and loading %s...\n", entry.ID)
				}
				result, err := prepareDemo(dir, dataDir, entry, demo.Files)
				if err != nil {
					return fmt.Errorf("demo %s: %w", entry.ID, err)
				}
				verified = append(verified, result)
			}
			db, cleanup, err := openLocalDB(dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				return err
			}
			defer ln.Close()
			mux := http.NewServeMux()
			mux.Handle("/", dashboard.Server{DB: db}.Handler())
			mux.HandleFunc("/demos/", demoGallery(selected))
			server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			done := make(chan error, 1)
			go func() { done <- server.Serve(ln) }()
			defer server.Close()
			link := "http://" + ln.Addr().String() + "/demos/"
			if chosen != nil {
				if chosen.Run != "" {
					link = "http://" + ln.Addr().String() + demoRunURL(*chosen)
				} else {
					link += "docs/" + chosen.ID
				}
			}
			if jsonOutput {
				err = json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
					URL           string             `json:"url"`
					Verifications []demoVerification `json:"verifications"`
				}{link, verified})
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "AgentProvenance demos: %s\nRead-only replay; Ctrl-C to stop and remove temporary data.\n", link)
			}
			if err != nil {
				return err
			}
			if !noBrowser && !jsonOutput {
				if err := openDemoBrowser(ctx, link); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Open the printed URL in your browser (%v).\n", err)
				}
			}
			select {
			case err := <-done:
				if err == http.ErrServerClosed {
					return nil
				}
				return err
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return server.Shutdown(shutdownCtx)
			}
		},
	}
	cmd.Flags().BoolVar(&list, "list", false, "list all bundled demos and evaluator guides")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "print the local URL without opening a browser")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print JSON (also disables browser launch)")
	return cmd
}

func prepareDemo(dir, dataDir string, entry demo.Entry, files fs.FS) (demoVerification, error) {
	result := demoVerification{ID: entry.ID}
	bundle := entry.Bundle + ".forensics.json.gz"
	attestation := entry.Bundle + ".forensics.dsse.json"
	dest := filepath.Join(dir, entry.ID)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return result, err
	}
	for _, name := range []string{bundle, attestation, entry.Key} {
		b, err := fs.ReadFile(files, path.Join(entry.Directory, name))
		if err != nil {
			return result, err
		}
		if err := os.WriteFile(filepath.Join(dest, name), b, 0o600); err != nil {
			return result, err
		}
	}
	info, err := importForensics(dataDir, filepath.Join(dest, bundle), filepath.Join(dest, entry.Key))
	if err != nil {
		return result, err
	}
	if info.RunID != entry.Run {
		return result, fmt.Errorf("unexpected bundle run %q, want %q", info.RunID, entry.Run)
	}
	result.SignatureVerified = true
	db, err := store.Open(store.ResolvePaths(dataDir))
	if err != nil {
		return result, err
	}
	defer db.Close()
	result.Graph, err = provenance.Verify(db, entry.Run)
	if err != nil {
		return result, err
	}
	if result.Graph.ErrorCount > 0 {
		return result, fmt.Errorf("graph verification failed: %+v", result.Graph)
	}
	return result, nil
}

func demoRunURL(entry demo.Entry) string {
	return "/?" + url.Values{"run": {entry.Run}, "lens": {entry.Lens}, "replay": {"1"}}.Encode()
}

func demoGallery(entries []demo.Entry) http.HandlerFunc {
	page := template.Must(template.New("gallery").Funcs(template.FuncMap{"runURL": demoRunURL}).Parse(demoGalleryHTML))
	guide := template.Must(template.New("guide").Parse(demoGuideHTML))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/demos/" {
			_ = page.Execute(w, entries)
			return
		}
		for _, entry := range entries {
			if r.URL.Path == "/demos/docs/"+entry.ID {
				b, err := demo.Files.ReadFile(path.Join(entry.Directory, "README.md"))
				if err != nil {
					http.Error(w, "guide unavailable", http.StatusInternalServerError)
					return
				}
				_ = guide.Execute(w, struct{ Title, Text string }{entry.Title, string(b)})
				return
			}
		}
		http.NotFound(w, r)
	}
}

func openDemoBrowser(parent context.Context, link string) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	candidates := [][]string{{"xdg-open", link}}
	if runtime.GOOS == "darwin" {
		candidates = [][]string{{"open", link}}
	} else if os.Getenv("WSL_DISTRO_NAME") != "" {
		candidates = [][]string{{"wslview", link}, {"rundll32.exe", "url.dll,FileProtocolHandler", link}, {"xdg-open", link}}
	}
	for _, args := range candidates {
		if _, err := exec.LookPath(args[0]); err == nil {
			return exec.CommandContext(ctx, args[0], args[1:]...).Run()
		}
	}
	return fmt.Errorf("no browser launcher found")
}

const demoGalleryHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentProvenance demos</title><style>
body{margin:0;background:#10141d;color:#e7edf6;font:16px/1.6 system-ui}main{max-width:1040px;margin:60px auto;padding:0 24px}h1{font-size:36px;line-height:1.2}h2{font-size:21px}p{color:#b3bfd0}a{color:#80bfff}section{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px}article{background:#1b2331;border:1px solid #344054;border-radius:12px;padding:24px}.tag{color:#83dbc1;font-size:13px}.action{display:inline-block;margin:8px 18px 0 0}small{display:block;color:#9eacc0}</style><main><div class="tag">AGENTPROVENANCE · DEMOS</div><h1>What did the agent actually do?</h1><p>Choose a recorded execution. Its signed evidence is already loaded and verified locally. Replay needs no account, API key, VM or network connection.</p><p>Verification checks evidence integrity against the bundled demo key, not capture completeness or every inferred relationship. Optional evaluators have separate setup requirements.</p><section>{{range .}}<article><div class="tag">{{if .Run}}VERIFIED SIGNED REPLAY{{else}}OPTIONAL EVALUATOR{{end}}</div><h2>{{.Title}}</h2><p>{{.Description}}</p><small>{{.Requirements}}</small>{{if .Run}}<a class="action" href="{{runURL .}}">Open replay →</a>{{end}}<a class="action" href="/demos/docs/{{.ID}}">Read guide</a></article>{{end}}</section></main></html>`

const demoGuideHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title><style>body{background:#10141d;color:#e7edf6;font:16px/1.6 system-ui;max-width:1000px;margin:40px auto;padding:0 24px}a{color:#80bfff}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><a href="/demos/">← Demo gallery</a><h1>{{.Title}}</h1><p>Offline copy of the demo's source guide. Paths below refer to the demo directory included in the release archive or source checkout. Replay does not execute these instructions.</p><pre>{{.Text}}</pre></html>`
