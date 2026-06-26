//go:build linux

package sensor

// bpf2go compiles exec.c (CO-RE, clang) and generates sensorbpf_bpfel.go plus
// the embedded object. Run on a Linux host with clang + vmlinux.h present:
//   go generate ./internal/sensor
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type exec_event sensorbpf exec.c -- -I. -I/usr/include
