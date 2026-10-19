package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/spf13/cobra"
)

// internalCmd is the hidden home for plumbing subcommands that porcelain
// commands (launch) invoke but users rarely call directly -- the git
// porcelain/plumbing split. Kept hidden so `agentprov --help` stays focused on
// the handful of top-level verbs. More plumbing will migrate here over time.
func internalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "internal",
		Short:  "plumbing subcommands used by porcelain commands",
		Hidden: true,
	}
	cmd.AddCommand(internalHookLogCmd())
	return cmd
}

// internalHookLogCmd appends the hook event's retained JSON to a run's hook log
// as one line. This is the command every entry in launch's per-run Claude Code
// settings overlay points at; the resulting JSONL is folded into the graph by
// `hooks bridge` at seal time.
//
// Input and log size are bounded. Retention and redaction precede the write;
// malformed input is replaced by a body-free diagnostic, never an agent error.
func internalHookLogCmd() *cobra.Command {
	var file string
	var capture captureFlags
	cmd := &cobra.Command{
		Use:    "hook-log",
		Short:  "append a hook event (stdin JSON) to a run hook log",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return commandErrorf("--file is required")
			}
			policy, err := capture.policy(cmd, false)
			if err != nil {
				return err
			}
			data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), agentcontext.MaxLineBytes+1))
			code := ""
			switch {
			case err != nil:
				code = "hook_input_read_failed"
			case len(data) > agentcontext.MaxLineBytes:
				code = "hook_input_limit"
			default:
				// Hook stdin has no timestamp; stamp before retaining the fields
				// used to correlate tool windows with kernel events.
				data, err = agentcontext.RetainHookEvent(stampHookTS(data), *policy)
				if errors.Is(err, agentcontext.ErrHookCaptureLimit) {
					code = "hook_input_limit"
				} else if err != nil {
					code = "hook_input_invalid"
				} else if len(data)+1 > agentcontext.MaxLineBytes {
					code = "hook_input_limit"
				}
			}
			if code != "" {
				data = agentcontext.HookCaptureDiagnostic(code)
				fmt.Fprintf(cmd.ErrOrStderr(), "hook-log: %s\n", code)
			}
			// A hook must never break the agent: swallow write errors to stderr
			// rather than returning nonzero (a nonzero PreToolUse hook can abort
			// the agent's tool call). Missing evidence is acceptable; a broken
			// agent run is not.
			if err := appendHookLog(file, append(data, '\n'), agentcontext.MaxInputBytes); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), commandText(cmd, "hook-log: write: %v\n"), err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "hook log file to append to")
	capture.bind(cmd)
	return cmd
}

// stampHookTS injects a real-time `_ts` into a hook event JSON object. If the
// payload is not a JSON object it is returned unchanged (the bridge tolerates
// unstamped lines).
func stampHookTS(data []byte) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return data
	}
	if _, ok := obj["_ts"]; !ok {
		obj["_ts"], _ = json.Marshal(time.Now().UTC().Format(time.RFC3339Nano))
	}
	stamped, err := json.Marshal(obj)
	if err != nil {
		return data
	}
	return stamped
}
