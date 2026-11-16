//go:build !linux

package runtimegate

import "fmt"

const Entry = "__runtime-gate"

func Run(args []string) (bool, error) {
	if len(args) > 1 && args[1] == Entry {
		return true, fmt.Errorf("runtime gate requires Linux")
	}
	return false, nil
}
