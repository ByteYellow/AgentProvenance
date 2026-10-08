package record

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Release the fixture only after a real ps snapshot contains its child. This
// retains the production process-table parser without timing-dependent sleeps.
func sampledChildGate(t *testing.T) (pidFile, observedFile, stopFile string) {
	t.Helper()
	ps, err := exec.LookPath("ps")
	if err != nil {
		t.Fatal(err)
	}
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pidFile = filepath.Join(dir, "child.pid")
	observedFile = filepath.Join(dir, "observed")
	stopFile = filepath.Join(dir, "stop")
	script := fmt.Sprintf(`#!/bin/sh
table="$(%s "$@")" || exit $?
if [ -s %s ]; then
  pid="$(%s 'NR == 1 { print; exit }' %s)"
  if printf '%%s\n' "$table" | %s -v pid="$pid" '$1 == pid { found = 1 } END { exit !found }'; then
    : > %s
  fi
fi
printf '%%s\n' "$table"
`, fixtureShellQuote(ps), fixtureShellQuote(pidFile), fixtureShellQuote(awk),
		fixtureShellQuote(pidFile), fixtureShellQuote(awk), fixtureShellQuote(observedFile))
	if err := os.WriteFile(filepath.Join(dir, "ps"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(func() { _ = os.WriteFile(stopFile, nil, 0o600) })
	return pidFile, observedFile, stopFile
}

func fixtureShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
