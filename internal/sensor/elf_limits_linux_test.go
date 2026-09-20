//go:build linux && (amd64 || arm64)

package sensor

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestELFPreflightRejectsHugeLinkedStringTable(t *testing.T) {
	data := make([]byte, 64+3*64)
	copy(data, "\x7fELF")
	data[4], data[5] = 2, 1
	binary.LittleEndian.PutUint64(data[40:], 64)
	binary.LittleEndian.PutUint16(data[58:], 64)
	binary.LittleEndian.PutUint16(data[60:], 3)
	binary.LittleEndian.PutUint32(data[64+64+4:], 2)
	binary.LittleEndian.PutUint64(data[64+64+32:], 24)
	binary.LittleEndian.PutUint32(data[64+128+4:], 3)
	binary.LittleEndian.PutUint64(data[64+128+32:], 1<<40)
	path := filepath.Join(t.TempDir(), "malformed")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateELFMetadata(path); err == nil || !strings.Contains(err.Error(), "16 MiB") {
		t.Fatalf("huge STRTAB accepted before ELF parsing: %v", err)
	}
}
