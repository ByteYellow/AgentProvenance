//go:build linux || darwin

package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// The subprocess runs the real CLI under a controlling terminal. The nested
// probe must share its foreground process group, read input and receive Ctrl-C.
func TestRecordLaunchTerminal(t *testing.T) {
	for _, command := range []string{"record", "launch"} {
		for _, action := range []string{"success", "input", "interrupt", "signal-exit"} {
			t.Run(command+"/"+action, func(t *testing.T) {
				root := t.TempDir()
				workdir := filepath.Join(root, "workspace")
				if err := os.Mkdir(workdir, 0o700); err != nil {
					t.Fatal(err)
				}
				args := []string{"--data-dir", filepath.Join(root, "data"), "--lang", "en", command, "--json", "--workdir", workdir}
				if command == "launch" {
					args = append(args, "--sensor", "off", "--no-dashboard", "--no-context")
				}
				args = append(args, "--", os.Args[0], "-test.run=^TestRecordTerminalProcess$", "--", "probe", action)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestRecordTerminalProcess$", "--", "cli"}, args...)...)
				cmd.Env = append(os.Environ(), "AGENTPROV_TERMINAL_TEST=1")
				terminal, err := pty.Start(cmd)
				if err != nil {
					t.Fatal(err)
				}
				finished := false
				stop := make(chan struct{})
				t.Cleanup(func() {
					close(stop)
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					_ = terminal.Close()
					if !finished {
						_ = cmd.Wait()
					}
				})
				chunks := make(chan string, 16)
				go func() {
					defer close(chunks)
					buf := make([]byte, 4096)
					for {
						n, err := terminal.Read(buf)
						if n > 0 {
							select {
							case chunks <- string(buf[:n]):
							case <-stop:
								return
							}
						}
						if err != nil {
							return
						}
					}
				}()
				var output strings.Builder
				ready := regexp.MustCompile(`PTY_READY pid=(\d+) pgid=(\d+) foreground=(\d+)`)
				var match []string
				for match == nil {
					select {
					case chunk, ok := <-chunks:
						if !ok {
							t.Fatalf("probe exited before readiness: %s", output.String())
						}
						output.WriteString(chunk)
						match = ready.FindStringSubmatch(output.String())
					case <-ctx.Done():
						t.Fatalf("waiting for probe: %s", output.String())
					}
				}
				pid, _ := strconv.Atoi(match[1])
				group, _ := strconv.Atoi(match[2])
				t.Cleanup(func() {
					if !finished {
						_ = syscall.Kill(-group, syscall.SIGKILL)
						_ = syscall.Kill(pid, syscall.SIGKILL)
					}
				})
				if match[2] != match[3] {
					t.Fatalf("recorded command is outside the terminal foreground group: %s", match[0])
				}
				input := "terminal-input\n"
				exitCode, marker := 7, "PTY_INPUT terminal-input"
				status := "failed"
				if action == "success" {
					exitCode, status = 0, "passed"
				}
				if action == "interrupt" || action == "signal-exit" {
					input = "\x03"
					exitCode, marker = 130, "PTY_INTERRUPT"
					if action == "signal-exit" {
						marker = "PTY_READY"
					}
				}
				if _, err := terminal.Write([]byte(input)); err != nil {
					t.Fatal(err)
				}
			readOutput:
				for {
					select {
					case chunk, ok := <-chunks:
						if !ok {
							break readOutput
						}
						output.WriteString(chunk)
					case <-ctx.Done():
						t.Fatalf("terminal execution did not finish: %s", output.String())
					}
				}
				err = cmd.Wait()
				finished = true
				wantCLIExit := 0 // record reports the child's exit in its manifest.
				if command == "launch" {
					wantCLIExit = exitCode
				}
				if cmd.ProcessState.ExitCode() != wantCLIExit {
					t.Fatalf("CLI exit=%d, want %d (err=%v): %s", cmd.ProcessState.ExitCode(), wantCLIExit, err, output.String())
				}
				for _, want := range []string{marker, fmt.Sprintf(`"exit_code": %d`, exitCode), fmt.Sprintf(`"status": %q`, status)} {
					if !strings.Contains(output.String(), want) {
						t.Fatalf("missing %q after terminal interaction: %s", want, output.String())
					}
				}
			})
		}
	}
}

func TestRecordTerminalProcess(t *testing.T) {
	if os.Getenv("AGENTPROV_TERMINAL_TEST") != "1" {
		return
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		t.Fatal("missing terminal helper role")
	}
	if args[0] == "cli" {
		root := NewRootCommand()
		root.SetArgs(args[1:])
		root.SetOut(os.Stdout)
		root.SetErr(os.Stderr)
		if err := root.Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(args) != 2 || args[0] != "probe" {
		t.Fatal("invalid terminal helper arguments")
	}
	interrupts := make(chan os.Signal, 1)
	if args[1] != "signal-exit" {
		signal.Notify(interrupts, os.Interrupt)
	}
	foreground, err := unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PTY_READY pid=%d pgid=%d foreground=%d\n", os.Getpid(), syscall.Getpgrp(), foreground)
	switch args[1] {
	case "success", "input":
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("PTY_INPUT %s", line)
		if args[1] == "success" {
			os.Exit(0)
		}
		os.Exit(7)
	case "interrupt":
		<-interrupts
		fmt.Println("PTY_INTERRUPT")
		os.Exit(130)
	case "signal-exit":
		for {
			time.Sleep(time.Second)
		}
	}
}
