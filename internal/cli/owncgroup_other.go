//go:build !linux

package cli

// ownCgroupID is unavailable off Linux (no cgroup v2 / no sensor). The sensor
// stream is Linux-only anyway; this keeps the package building on other hosts.
func ownCgroupID() string { return "" }
