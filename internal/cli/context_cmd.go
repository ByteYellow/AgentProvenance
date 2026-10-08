package cli

import (
	"encoding/json"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func contextCmd(dataDir *string) *cobra.Command {
	root := &cobra.Command{Use: "context", Short: "Import and inspect recorded agent context"}
	var run string
	root.PersistentFlags().StringVar(&run, "run", "", "execution run id")
	withService := func(cmd *cobra.Command, f func(agentcontext.Service) (any, error)) error {
		if run == "" {
			return commandErrorf("--run is required")
		}
		paths, err := store.Init(*dataDir)
		if err != nil {
			return err
		}
		db, err := store.Open(paths)
		if err != nil {
			return err
		}
		defer db.Close()
		result, err := f(agentcontext.Service{DB: db, Paths: paths})
		if err != nil {
			return err
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	var opts agentcontext.ParseOptions
	importCmd := &cobra.Command{Use: "import", Short: "Import one explicitly selected transcript without changing earlier evidence", Args: cobra.NoArgs}
	importCmd.Flags().StringVar(&opts.Path, "file", "", "JSONL or Zstandard transcript file")
	importCmd.Flags().StringVar(&opts.Harness, "harness", "", "claude, codex, kimi, grok, or deepseek")
	importCmd.Flags().StringVar(&opts.SessionID, "session", "", "expected native session id; required if absent in the source")
	importCmd.Flags().StringVar(&opts.AgentID, "agent", "", "source-provided agent id, when separate from session identity")
	importCmd.Flags().Int64Var(&opts.AfterLine, "after-line", 0, "retain records through this resume cursor as prior context, not current execution")
	importCmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if opts.Path == "" || opts.Harness == "" {
			return commandErrorf("--file and --harness are required")
		}
		opts.Binding = "explicit"
		opts.BindingEvidence = []string{"user_selected_file"}
		var status agentcontext.Status
		err := withService(cmd, func(s agentcontext.Service) (any, error) {
			result, err := s.ImportFile(cmd.Context(), run, opts)
			status = result.Coverage.Status
			return result, err
		})
		if err != nil {
			return err
		}
		if status != agentcontext.OK && status != agentcontext.Empty {
			// The saved diagnostic is still useful to callers. Keep stdout as
			// one JSON document, but do not report an incomplete import as success.
			cmd.SilenceUsage = true
			return commandErrorf("context import is %s; see the saved coverage report", status)
		}
		return nil
	}
	var page agentcontext.PageOptions
	list := &cobra.Command{Use: "list", Short: "List recorded messages, tools, snapshots, and source references", Args: cobra.NoArgs}
	list.Flags().StringVar(&page.SessionID, "session", "", "native session filter")
	list.Flags().StringVar(&page.SourceID, "source", "", "source filter")
	list.Flags().StringVar(&page.Kind, "kind", "", "record kind filter")
	list.Flags().StringVar(&page.ToolCallID, "tool-call", "", "native tool call id filter")
	list.Flags().StringVar(&page.EntryID, "entry", "", "immutable context entry id filter")
	list.Flags().StringVar(&page.NodeID, "node", "", "graph node filter using recorded relationships only")
	list.Flags().StringVar(&page.Group, "group", "", "conversation or configuration record group")
	list.Flags().StringVar(&page.Cursor, "cursor", "", "continuation cursor from a previous page")
	list.Flags().IntVar(&page.Limit, "limit", 50, "records per page (maximum 200)")
	list.Flags().BoolVar(&page.IncludeRevisions, "revisions", false, "include immutable earlier revisions")
	list.RunE = func(cmd *cobra.Command, _ []string) error {
		if page.Limit < 1 || page.Limit > 200 {
			return commandErrorf("--limit must be between 1 and 200")
		}
		page.RunID = run
		return withService(cmd, func(s agentcontext.Service) (any, error) { return s.Entries(cmd.Context(), page) })
	}
	overview := &cobra.Command{Use: "coverage", Short: "Show source-scoped context coverage; historical unknowns remain null", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withService(cmd, func(s agentcontext.Service) (any, error) { return s.Overview(cmd.Context(), run) })
		}}
	var ref string
	var offset int64
	var limit int
	content := &cobra.Command{Use: "content", Short: "Read a bounded page of stored redacted text", Args: cobra.NoArgs}
	content.Flags().StringVar(&ref, "ref", "", "stored content manifest reference")
	content.Flags().Int64Var(&offset, "offset", 0, "UTF-8 byte offset")
	content.Flags().IntVar(&limit, "limit", 64<<10, "maximum bytes per page (up to 262144)")
	content.RunE = func(cmd *cobra.Command, _ []string) error {
		if ref == "" {
			return commandErrorf("--ref is required")
		}
		if offset < 0 || limit < 4 || limit > provenance.MaxContentPageBytes {
			return commandErrorf("--offset must be nonnegative and --limit must be between 4 and 262144")
		}
		return withService(cmd, func(s agentcontext.Service) (any, error) {
			return provenance.ReadTextContentPage(s.DB, run, ref, offset, int64(limit))
		})
	}
	var left, right, rightRun string
	compare := &cobra.Command{Use: "compare", Short: "Compare two recorded task, configuration, or approval snapshots", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withService(cmd, func(s agentcontext.Service) (any, error) {
				return s.CompareSnapshots(cmd.Context(), run, left, rightRun, right)
			})
		}}
	compare.Flags().StringVar(&left, "left", "", "earlier recorded context entry id")
	compare.Flags().StringVar(&right, "right", "", "later recorded context entry id")
	compare.Flags().StringVar(&rightRun, "right-run", "", "run containing the later entry; defaults to --run")
	var entryID string
	links := &cobra.Command{Use: "links", Short: "Show recorded graph links for a context entry", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if entryID == "" {
				return commandErrorf("--entry is required")
			}
			return withService(cmd, func(s agentcontext.Service) (any, error) {
				return s.Links(cmd.Context(), run, entryID)
			})
		}}
	links.Flags().StringVar(&entryID, "entry", "", "immutable context entry id")
	root.AddCommand(importCmd, list, overview, content, compare, links)
	return root
}
