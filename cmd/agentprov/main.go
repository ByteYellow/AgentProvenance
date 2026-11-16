package main

import (
	"fmt"
	"os"

	"github.com/byteyellow/agentprovenance/internal/cli"
	"github.com/byteyellow/agentprovenance/internal/runtimegate"
)

func main() {
	if handled, err := runtimegate.Run(os.Args); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(125)
		}
		return
	}
	cmd := cli.NewRootCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, cli.ErrorText(cmd, err))
		os.Exit(1)
	}
}
