//go:build !agentprov_tools

package main

func dispatchTools([]string) (bool, error) { return false, nil }
