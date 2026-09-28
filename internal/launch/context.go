package launch

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// Leave room for discovery/hooks/processing reports in the bounded overview.
const maxContextSources = 128

type contextCapture struct {
	harness, root, workdir, session, file string
	disabled                              bool
	before                                agentcontext.Inventory
}

func contextProblem(db *sql.DB, paths store.Paths, runID, code string, report *Report, stderr io.Writer) {
	report.ContextIssues = append(report.ContextIssues, code)
	svc := agentcontext.Service{DB: db, Paths: paths}
	_, err := svc.Save(context.Background(), runID, agentcontext.Source{Harness: "launch", Channel: "processing",
		SessionID: code, ParserVersion: agentcontext.ParserVersion, Binding: "unbound"}, nil,
		agentcontext.Coverage{Status: agentcontext.Failed, Issues: []agentcontext.Issue{{Code: code}}})
	if err != nil {
		fmt.Fprintln(stderr, "launch: unable to persist context failure report")
		return
	}
	if overview, err := svc.Overview(context.Background(), runID); err == nil {
		report.AgentContext = &overview
	}
}

func prepareContext(ctx context.Context, opts Options, recipe recipe) (contextCapture, error) {
	c := contextCapture{harness: recipe.harness, workdir: opts.Workdir,
		session: opts.ContextSession, file: opts.ContextFile, disabled: opts.NoContext}
	if opts.ContextHarness != "" {
		c.harness = opts.ContextHarness
	}
	if c.workdir == "" {
		var err error
		c.workdir, err = os.Getwd()
		if err != nil {
			return c, err
		}
	}
	if opts.NoContext && (opts.ContextDir != "" || c.file != "" || c.session != "" || opts.ContextHarness != "") {
		return c, fmt.Errorf("--no-context cannot be combined with context source options")
	}
	if c.harness == "" {
		if c.file != "" || c.session != "" || opts.ContextDir != "" {
			return c, fmt.Errorf("--context-harness is required for an unrecognized agent command")
		}
		c.harness, c.disabled = "unknown", true
		return c, nil
	}
	if opts.ContextDir != "" && c.file != "" {
		return c, fmt.Errorf("choose --context-dir or --context-file, not both")
	}
	c.root = opts.ContextDir
	if c.file != "" {
		var err error
		c.file, err = filepath.Abs(c.file)
		if err != nil {
			return c, err
		}
		c.root = c.file
	}
	if c.root == "" {
		c.root = contextRoot(c.harness)
	}
	if c.root == "" {
		return c, fmt.Errorf("unsupported context harness %q", c.harness)
	}
	if c.disabled {
		return c, nil
	}
	var err error
	c.before, err = agentcontext.Discover(ctx, agentcontext.DiscoverOptions{
		Harness: c.harness, Root: c.root, Workdir: c.workdir, SessionID: c.session, Snapshot: true,
	})
	return c, err
}

func contextRoot(harness string) string {
	base := func(env, fallback string) string {
		if value := os.Getenv(env); value != "" {
			return value
		}
		return filepath.Join(home(), fallback)
	}
	switch harness {
	case "claude":
		return filepath.Join(base("CLAUDE_CONFIG_DIR", ".claude"), "projects")
	case "codex":
		return filepath.Join(base("CODEX_HOME", ".codex"), "sessions")
	case "deepseek":
		return filepath.Join(base("DSH_HOME", ".dsh"), "sessions")
	case "kimi":
		return filepath.Join(base("KIMI_SHARE_DIR", ".kimi-code"), "sessions")
	case "grok":
		return filepath.Join(home(), ".grok")
	default:
		return ""
	}
}

// finish persists source diagnostics even when selection cannot be proven.
// Hook paths can refine an inventory; they cannot retroactively supply the
// pre-execution prefix of a transcript outside that inventory.
func (c contextCapture) finish(ctx context.Context, svc agentcontext.Service, runID, hookPath string, start, end time.Time) (agentcontext.Overview, error) {
	discovery := agentcontext.Coverage{Status: agentcontext.Disabled,
		StartedAt: start.UTC().Format(time.RFC3339Nano), EndedAt: end.UTC().Format(time.RFC3339Nano)}
	src := agentcontext.Source{Harness: c.harness, Channel: "discovery", Path: c.root,
		SessionID: c.session, ParserVersion: agentcontext.ParserVersion, Binding: "unbound", Workdir: c.workdir}
	if c.disabled {
		discovery.Issues = []agentcontext.Issue{{Code: "context_disabled"}}
		if c.harness == "unknown" {
			discovery.Issues[0].Code = "no_context_recipe"
		}
		if _, err := svc.Save(ctx, runID, src, nil, discovery); err != nil {
			return agentcontext.Overview{}, err
		}
		return svc.Overview(ctx, runID)
	}
	after, err := agentcontext.Discover(ctx, agentcontext.DiscoverOptions{Harness: c.harness, Root: c.root, SessionID: c.session})
	if err != nil {
		return agentcontext.Overview{}, err
	}
	selectionOpts := agentcontext.SelectOptions{Workdir: c.workdir, SessionID: c.session, Path: c.file, StartedAt: start, EndedAt: end}
	anchors := map[string]string{}
	hookSession, hookMain := "", ""
	if hookPath != "" && c.harness == "claude" {
		file, openErr := os.Open(hookPath)
		if openErr == nil {
			parsed, parseErr := agentcontext.Parse(ctx, file, agentcontext.ParseOptions{Harness: "claude", Path: hookPath,
				SessionID: c.session, Binding: "exact", BindingEvidence: []string{"run_owned_hook_log"}})
			file.Close()
			if parseErr != nil {
				return agentcontext.Overview{}, parseErr
			}
			if _, err := svc.Save(ctx, runID, parsed.Source, parsed.Records, parsed.Coverage); err != nil {
				return agentcontext.Overview{}, err
			}
			if parsed.Coverage.Status == agentcontext.Ambiguous {
				discovery.Issues = append(discovery.Issues, agentcontext.Issue{Code: "hook_session_ambiguous"})
			}
			if parsed.Coverage.Status != agentcontext.Ambiguous {
				hookSession = parsed.Source.SessionID
				for _, r := range parsed.Records {
					if r.RawBody == nil {
						continue
					}
					var raw struct {
						Transcript string `json:"transcript_path"`
						Child      string `json:"agent_transcript_path"`
						Agent      string `json:"agent_id"`
					}
					if json.Unmarshal([]byte(*r.RawBody), &raw) != nil {
						continue
					}
					if raw.Transcript != "" {
						if hookMain != "" && hookMain != raw.Transcript {
							discovery.Issues = append(discovery.Issues, agentcontext.Issue{Code: "conflicting_hook_transcripts"})
						} else {
							hookMain = raw.Transcript
						}
					}
					if raw.Child != "" && raw.Agent != "" {
						if old := anchors[raw.Child]; old != "" && old != raw.Agent {
							discovery.Issues = append(discovery.Issues, agentcontext.Issue{Code: "conflicting_hook_agents"})
						} else {
							anchors[raw.Child] = raw.Agent
						}
					}
				}
			}
		} else {
			status, code := agentcontext.NoInput, "hook_log_not_found"
			if !os.IsNotExist(openErr) {
				status, code = agentcontext.Failed, "hook_log_unreadable"
				discovery.Issues = append(discovery.Issues, agentcontext.Issue{Code: code})
			}
			if _, err := svc.Save(ctx, runID, agentcontext.Source{Harness: "claude", Channel: "hooks", Path: hookPath,
				ParserVersion: agentcontext.ParserVersion, SessionID: c.session, Binding: "unbound"}, nil,
				agentcontext.Coverage{Status: status, Issues: []agentcontext.Issue{{Code: code}}}); err != nil {
				return agentcontext.Overview{}, err
			}
		}
	}
	if hookSession != "" && c.session == "" {
		selectionOpts.SessionID = hookSession
	}
	if hookMain != "" && c.file == "" {
		selectionOpts.Path = hookMain
	}
	selection := agentcontext.SelectSources(ctx, c.before, after, selectionOpts)
	if len(discovery.Issues) > 0 {
		selection.Sources, selection.Status = nil, agentcontext.Ambiguous
	}
	if len(selection.Sources) > 0 && hookSession != "" && c.session == "" && c.file == "" {
		for i := range selection.Sources {
			selection.Sources[i].Binding = "exact"
			proof := []string{"run_hook_session"}
			if hookMain != "" {
				proof[0] = "run_hook_session_and_path"
			}
			for _, item := range selection.Sources[i].BindingEvidence {
				if item != "user_selected_session" && item != "user_selected_file" {
					proof = append(proof, item)
				}
			}
			selection.Sources[i].BindingEvidence = proof
		}
	}
	// A subagent shares a Claude session ID, but its source-provided agent ID
	// and hook path identify a separate transcript. Never infer its parent.
	if len(selection.Sources) > 0 {
		paths := make([]string, 0, len(anchors))
		for path := range anchors {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			child := agentcontext.SelectSources(ctx, c.before, after, agentcontext.SelectOptions{Path: path, SessionID: hookSession, StartedAt: start, EndedAt: end})
			if len(child.Sources) != 1 || child.Sources[0].AgentID != anchors[path] {
				selection.Status = agentcontext.Partial
				selection.Issues = append(selection.Issues, agentcontext.Issue{Code: "hook_child_binding_not_proven"})
				continue
			}
			child.Sources[0].Binding = "exact"
			child.Sources[0].BindingEvidence = []string{"run_hook_child_path_and_agent_id"}
			selection.Sources = append(selection.Sources, child.Sources[0])
		}
	}
	seen := map[string]bool{}
	for _, selected := range selection.Sources {
		if seen[selected.Path] {
			continue
		}
		if len(seen) >= maxContextSources {
			selection.Status = agentcontext.Partial
			selection.Issues = append(selection.Issues, agentcontext.Issue{Code: "selected_source_limit"})
			break
		}
		seen[selected.Path] = true
		if _, err := svc.ImportFile(ctx, runID, selected.ParseOptions(c.harness)); err != nil {
			return agentcontext.Overview{}, err
		}
	}
	discovery.Status = selection.Status
	discovery.Counts.Discovered = agentcontext.Number(int64(len(after.Candidates)))
	discovery.Counts.Matched = agentcontext.Number(int64(len(seen)))
	discovery.Issues = append(discovery.Issues, c.before.Issues...)
	discovery.Issues = append(discovery.Issues, after.Issues...)
	discovery.Issues = append(discovery.Issues, selection.Issues...)
	if len(discovery.Issues) > 100 {
		discovery.Issues = discovery.Issues[:100]
	}
	if _, err := svc.Save(ctx, runID, src, nil, discovery); err != nil {
		return agentcontext.Overview{}, err
	}
	return svc.Overview(ctx, runID)
}
