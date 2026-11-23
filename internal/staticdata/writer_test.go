package staticdata

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReusedCompressorPreservesIndividualShardBytes(t *testing.T) {
	w := Writer{Root: t.TempDir()}
	for _, s := range []string{"small", "another recording", string(bytes.Repeat([]byte("larger"), 4000)), "small"} {
		ref, err := w.JSON(s)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(s)
		var expected bytes.Buffer
		z, _ := gzip.NewWriterLevel(&expected, gzip.BestSpeed)
		_, _ = z.Write(raw)
		_ = z.Close()
		got, err := os.ReadFile(filepath.Join(w.Root, ref.Path))
		if err != nil || !bytes.Equal(got, expected.Bytes()) {
			t.Fatal("compressed shard changed", ref, err)
		}
	}
}
