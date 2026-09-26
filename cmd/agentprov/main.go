package main

import (
	"fmt"
	"os"

	"github.com/byteyellow/agentprovenance/internal/cli"
)

func main() {
	cmd := cli.NewRootCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, cli.ErrorText(cmd, err))
		os.Exit(1)
	}
}
