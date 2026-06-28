package cli

import (
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/aitools"
	"github.com/byteyellow/agentprovenance/internal/mcpserver"
	"github.com/spf13/cobra"
)

// aiCmd exposes the AI-callable tool surface: `ai tools` emits provider tool
// definitions, `ai call` dispatches one tool against the local store / policy
// engine. See docs/ai-access.md.
func aiCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "AI-callable tools over the verifiable provenance graph",
	}
	cmd.AddCommand(aiToolsCmd())
	cmd.AddCommand(aiCallCmd(dataDir))
	cmd.AddCommand(aiMCPCmd(dataDir))
	return cmd
}

// aiMCPCmd runs a stdio MCP server over the same aitools catalog/dispatcher, so
// MCP clients get the read surface + inline gate. Only JSON-RPC goes to stdout;
// cobra writes its own diagnostics to stderr.
func aiMCPCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "run a stdio MCP server exposing the AI tool surface (JSON-RPC 2.0)",
		Long: "Speaks the Model Context Protocol (spec 2025-06-18) over stdin/stdout so MCP " +
			"clients (Claude Desktop, the mcp inspector) can query the verifiable provenance " +
			"graph and pre-flight proposed actions through the trusted policy gate. The tool set " +
			"is the same one served by `ai tools`/`ai call`. Only JSON-RPC is written to stdout.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			return mcpserver.Serve(db, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
}

func aiToolsCmd() *cobra.Command {
	var provider string
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "emit AI tool definitions for a provider (generic|anthropic|openai)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var tools []map[string]any
			switch provider {
			case "", "generic":
				tools = aitools.GenericTools()
			case "anthropic":
				tools = aitools.AnthropicTools()
			case "openai":
				tools = aitools.OpenAITools()
			default:
				return fmt.Errorf("unknown provider %q (want generic|anthropic|openai)", provider)
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{
				"schema_version": "agentprovenance.ai_tools/v1",
				"provider":       firstNonEmptyStr(provider, "generic"),
				"tools":          tools,
			})
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "generic", "tool schema provider: generic, anthropic, or openai")
	return cmd
}

func aiCallCmd(dataDir *string) *cobra.Command {
	var input string
	cmd := &cobra.Command{
		Use:   "call <tool>",
		Short: "dispatch one AI tool with a JSON --input",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			parsed := map[string]any{}
			if input != "" {
				if err := json.Unmarshal([]byte(input), &parsed); err != nil {
					return fmt.Errorf("invalid --input JSON: %w", err)
				}
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			result, err := aitools.Dispatch(db, args[0], parsed)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		},
	}
	cmd.Flags().StringVar(&input, "input", "", "tool input as a JSON object")
	return cmd
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
