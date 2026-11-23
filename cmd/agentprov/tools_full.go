//go:build agentprov_tools

package main

import (
	"errors"
	"os"

	"github.com/byteyellow/agentprovenance/internal/substrate/node"
)

func dispatchTools(args []string) (bool, error) {
	if len(args) != 2 || args[0] != "internal" || args[1] != "docker-runtime-v1" {
		return false, nil
	}
	result := os.NewFile(3, "docker-result")
	if result == nil {
		return true, errors.New("Docker tools requires a result pipe")
	}
	defer result.Close()
	if stat, err := result.Stat(); err != nil || stat.Mode()&os.ModeNamedPipe == 0 {
		return true, errors.New("Docker tools requires a result pipe")
	}
	return true, node.ServeDockerCall(os.Stdin, os.Stdout, os.Stderr, result)
}
