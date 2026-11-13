package forensics

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictBundleReadLimitsDecodedBytes(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "bundle.json")
		data := []byte(strings.Repeat("x", 1025))
		if compressed {
			path += ".gz"
			writeGzipFile(t, path, data)
		} else if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBoundedBundle(context.Background(), path, 1024); err == nil {
			t.Fatalf("compressed=%t: limit ignored", compressed)
		}
		got, err := readBoundedBundle(context.Background(), path, 1025)
		if err != nil || string(got) != string(data) {
			t.Fatalf("exact bound: %v", err)
		}
	}
}
