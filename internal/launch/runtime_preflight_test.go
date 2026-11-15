package launch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRuntimePreflightPinMatchesDeployment(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/microvm/runtime.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Version != supportedFirecracker {
		t.Fatalf("doctor expects %s but deployment pins %s", supportedFirecracker, profile.Version)
	}
}

func TestRuntimeVersionCheckOnlyRequestsVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	root := t.TempDir()
	binary, invocation := filepath.Join(root, "runtime"), filepath.Join(root, "invocation")
	script := "#!/bin/sh\nprintf '%s' \"$*\" > " + shQuote(invocation) + "\nprintf 'Firecracker v1.18.0\\n'\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if check := checkRuntimeBinary(binary, supportedFirecracker); check.Status != CheckPass {
		t.Fatalf("version check: %+v", check)
	}
	raw, err := os.ReadFile(invocation)
	if err != nil || string(raw) != "--version" {
		t.Fatalf("runtime launched work: %q %v", raw, err)
	}
	if check := checkRuntimeBinary(binary, "v0.0.0"); check.Status != CheckFail {
		t.Fatal("unsupported runtime release passed")
	}
	if check := checkRuntimeBinary(filepath.Join(root, "missing"), supportedFirecracker); check.Status != CheckFail {
		t.Fatal("missing binary passed")
	}
}

func TestRuntimeArtifactsAndSelection(t *testing.T) {
	root := t.TempDir()
	image := filepath.Join(root, "image")
	if err := os.WriteFile(image, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path      string
		directory bool
		want      CheckStatus
	}{
		{root, true, CheckPass}, {image, false, CheckPass}, {root, false, CheckFail}, {image, true, CheckFail},
		{filepath.Join(root, "missing"), false, CheckFail}, {"", false, CheckWarn},
	} {
		if got := checkRuntimeFile("artifact", test.path, test.directory, "--runtime-rootfs"); got.Status != test.want {
			t.Fatalf("artifact %q directory=%v: %+v", test.path, test.directory, got)
		}
	}
	if got := RuntimePreflight(RuntimePreflightOptions{}); len(got) != 0 {
		t.Fatal("unselected runtime was checked")
	}
	for _, opts := range []RuntimePreflightOptions{{Runtime: "unknown"}, {Binary: "runsc"}} {
		if got := RuntimePreflight(opts); len(got) != 1 || got[0].Status != CheckFail {
			t.Fatalf("bad runtime accepted: %+v", got)
		}
	}
	var output preflightVersionOutput
	input := strings.Repeat("x", 16384)
	if n, err := output.Write([]byte(input)); n != len(input) || err != nil || len(output.data) != 8192 {
		t.Fatal("runtime output is not bounded")
	}
}
