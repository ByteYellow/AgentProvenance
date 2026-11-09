package node

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

// Run on a Docker host as its workspace owner, including a non-root account:
// AGENTPROV_DOCKER_TEST_IMAGE=python:3-slim go test ./internal/substrate/node -run TestDockerSessionWorkspace
func TestDockerSessionWorkspace(t *testing.T) {
	image := os.Getenv("AGENTPROV_DOCKER_TEST_IMAGE")
	if image == "" {
		t.Skip("set AGENTPROV_DOCKER_TEST_IMAGE to run the Docker integration test")
	}
	rt, err := NewDockerRuntime()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Client.Close() })
	workspace := t.TempDir()
	if err := os.Chmod(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := rt.CreateSession(CreateSessionRequest{
		SessionID: ids.New("workspace-test"), Image: image, WorkspaceHostPath: workspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rt.Remove(id); err != nil {
			t.Error(err)
		}
	})
	info, err := rt.Client.ContainerInspect(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if info.HostConfig.Privileged || len(info.HostConfig.CapAdd) != 0 || len(info.HostConfig.CapDrop) != 1 || info.HostConfig.CapDrop[0] != "ALL" {
		t.Fatalf("unexpected container capabilities: %+v", info.HostConfig)
	}
	var output bytes.Buffer
	_, err = rt.ExecWithWriters(id, []string{"sh", "-c", `
set -eu
id
test "$(awk '/^CapEff:/ {print $2}' /proc/self/status)" = 0000000000000000
test "$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)" = 1
mkdir -p build
printf 'workspace-output\n' > build/result.txt
cat build/result.txt
`}, &output, &output)
	if err != nil {
		t.Fatalf("workspace command: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "workspace-output") {
		t.Fatalf("missing workspace output: %s", output.String())
	}
	var build []string
	switch {
	case strings.HasPrefix(image, "python:"):
		build = []string{"sh", "-c", "python3 -m venv build/venv && build/venv/bin/python -m pip --version && python3 -c 'import pathlib,py_compile; p=pathlib.Path(\"build/main.py\"); p.write_text(\"assert 6*7 == 42\\n\"); py_compile.compile(str(p), doraise=True)' && build/venv/bin/python build/main.py"}
	case strings.HasPrefix(image, "node:"):
		build = []string{"sh", "-c", `printf '{"scripts":{"test":"node test.js"}}' > package.json && printf 'require("node:assert").equal(6*7,42)\n' > test.js && npm test`}
	}
	if len(build) != 0 {
		if _, err := rt.ExecWithWriters(id, build, &output, &output); err != nil {
			t.Fatalf("build command: %v\n%s", err, output.String())
		}
	}
	t.Logf("workspace owner uid=%d gid=%d; container output:\n%s", os.Getuid(), os.Getgid(), output.String())
}
