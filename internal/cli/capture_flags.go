package cli

import (
	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/spf13/cobra"
)

type captureFlags struct {
	preset      string
	toolResults bool
}

func (f *captureFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.preset, "capture", "detailed", "additional context retention: basic or detailed; fixed per run")
	cmd.Flags().BoolVar(&f.toolResults, "capture-tool-results", false, "override the preset's tool-result retention; false also omits raw source records")
}

func (f captureFlags) override(cmd *cobra.Command) *bool {
	if cmd.Flags().Changed("capture-tool-results") {
		value := f.toolResults
		return &value
	}
	return nil
}

func (f captureFlags) policy(cmd *cobra.Command, reuseExisting bool) (*agentcontext.CapturePolicy, error) {
	if reuseExisting && !cmd.Flags().Changed("capture") && !cmd.Flags().Changed("capture-tool-results") {
		return nil, nil
	}
	p, err := agentcontext.NewCapturePolicy(f.preset, f.override(cmd))
	return &p, err
}
