//go:build linux

package runtimegate

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestGateHelperProcess(t *testing.T) {
	if os.Getenv("AGENTPROV_GATE_TEST_CHILD") != "1" {
		return
	}
	fmt.Println("waiting")
	handled, err := Run([]string{"agentprov", Entry, "/bin/sh", "-c", `printf once > "$1"`, "sh", os.Getenv("AGENTPROV_GATE_TEST_MARKER")})
	if !handled || err != nil {
		os.Exit(125)
	}
	os.Exit(126)
}

func TestGateRequiresPrivateRelease(t *testing.T) {
	for _, release := range []string{"valid", "invalid", "eof"} {
		t.Run(release, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			marker := filepath.Join(t.TempDir(), "workload-output")
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGateHelperProcess$")
			cmd.Env = append(os.Environ(), "AGENTPROV_GATE_TEST_CHILD=1", "AGENTPROV_GATE_TEST_MARKER="+marker)
			cmd.ExtraFiles = []*os.File{reader}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reader.Close()
			if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "waiting\n" {
				t.Fatalf("gate readiness: %q %v", line, err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("workload ran before release")
			}
			switch release {
			case "valid":
				_, err = writer.Write([]byte{0xa5})
			case "invalid":
				_, err = writer.Write([]byte{0})
			}
			if err != nil {
				t.Fatal(err)
			}
			writer.Close()
			err = cmd.Wait()
			if release == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if raw, err := os.ReadFile(marker); err != nil || string(raw) != "once" {
					t.Fatalf("workload result: %q %v", raw, err)
				}
			} else {
				if err == nil {
					t.Fatal("denied gate succeeded")
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("denied gate executed workload")
				}
			}
		})
	}
}
