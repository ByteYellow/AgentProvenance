package main

import (
	"errors"
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
	if handled, err := dispatchTools(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	cmd := cli.NewRootCommand()
	if err := cmd.Execute(); err != nil {
		var child cli.ChildExitError
		if errors.As(err, &child) {
			os.Exit(child.ExitCode())
		}
		fmt.Fprintln(os.Stderr, cli.ErrorText(cmd, err))
		os.Exit(1)
	}
}
