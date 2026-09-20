//go:build linux

package sensor

// Generate on the matching Linux architecture with its vmlinux.h present.
// Keep each architecture's committed object separate; see scripts/regen-sensor.sh.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target $GOARCH -tags linux,$GOARCH -type sensor_event sensorbpf exec.c -- -I. -I/usr/include
