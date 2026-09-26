package cli

import (
	"context"
	"encoding/json"
	"fmt"
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
					return commandErrorf("--list does not take a demo name")
				}
				if jsonOutput {
					return json.NewEncoder(cmd.OutOrStdout()).Encode(catalog)
				}
				for _, entry := range catalog {
					kind := "signed replay"
					if entry.Run == "" {
						kind = "setup guide"
					}
					fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", entry.ID, commandText(cmd, kind), commandText(cmd, entry.Title))
				}
				return nil
			}
			if cmd.Flags().Changed("data-dir") || cmd.Flags().Changed("daemon-url") {
				return commandErrorf("demo uses its own temporary store; omit --data-dir and --daemon-url")
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
					return commandErrorf("unknown demo %q; use agentprov demo --list", args[0])
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
					fmt.Fprintf(cmd.ErrOrStderr(), commandText(cmd, "Verifying and loading %s...\n"), entry.ID)
				}
				result, err := prepareDemo(dir, dataDir, entry, demo.Files)
				if err != nil {
					return commandErrorf("demo %s: %w", entry.ID, err)
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
			link = commandURL(cmd, link)
			if jsonOutput {
				err = json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
					URL           string             `json:"url"`
					Verifications []demoVerification `json:"verifications"`
				}{link, verified})
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), commandText(cmd, "AgentProvenance demos: %s\nRead-only replay; Ctrl-C to stop and remove temporary data.\n"), link)
			}
			if err != nil {
				return err
			}
			if !noBrowser && !jsonOutput {
				if err := openDemoBrowser(ctx, link); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), commandText(cmd, "Open the printed URL in your browser (%v).\n"), err)
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
		return result, commandErrorf("unexpected bundle run %q, want %q", info.RunID, entry.Run)
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
		return result, commandErrorf("graph verification failed: %+v", result.Graph)
	}
	return result, nil
}

func demoRunURL(entry demo.Entry) string {
	return "/?" + url.Values{"run": {entry.Run}, "lens": {entry.Lens}, "replay": {"1"}}.Encode()
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
	return commandErrorf("no browser launcher found")
}
