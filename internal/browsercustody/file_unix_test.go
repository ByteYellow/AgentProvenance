//go:build linux || darwin

package browsercustody

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserCustodyPrivateConfigFile(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "receiver.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readPrivate(context.Background(), path); err != nil || string(raw) != "{}" {
		t.Fatalf("private config: %s %v", raw, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readPrivate(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel ignored: %v", err)
	}
	for _, kind := range []string{"relative", "symlink", "hardlink", "public", "oversized", "directory"} {
		t.Run(kind, func(t *testing.T) {
			selected := filepath.Join(root, kind+".json")
			switch kind {
			case "relative":
				selected = "relative.json"
			case "symlink":
				if err := os.Symlink(path, selected); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, selected); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(selected)
			case "public":
				if err := os.WriteFile(selected, []byte(`{}`), 0644); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(selected, []byte(strings.Repeat(" ", (64<<10)+1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(selected, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readPrivate(context.Background(), selected); err == nil {
				t.Fatalf("accepted %s config", kind)
			}
		})
	}
}
