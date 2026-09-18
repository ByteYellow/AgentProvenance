package sensor

import (
	"bytes"
	"debug/elf"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestGoTLSReturnsDecodeInstructionsRatherThanScanBytes(t *testing.T) {
	// MOV AX, 0xc3 has an embedded RET byte which must not become a probe.
	code := []byte{0x48, 0xc7, 0xc0, 0xc3, 0x00, 0x00, 0x00, 0xc3, 0x90, 0xc3}
	offsets, err := decodeGoTLSReturns(code)
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint64{7, 9}; !reflect.DeepEqual(offsets, want) {
		t.Fatalf("return offsets = %v, want %v", offsets, want)
	}
}

func TestGoTLSSymbolTablesBoundLinkedStringAllocation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		symbol uint64
		text   uint64
		link   uint32
	}{
		{"oversized symbols", maxELFSymbolBytes + 1, 1, 1},
		{"oversized linked strings", 24, maxELFSymbolBytes + 1, 1},
		{"missing linked section", 24, 1, 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &elf.File{Sections: []*elf.Section{
				{SectionHeader: elf.SectionHeader{Type: elf.SHT_SYMTAB, Size: tc.symbol, Link: tc.link}},
				{SectionHeader: elf.SectionHeader{Type: elf.SHT_STRTAB, Size: tc.text}},
			}}
			if err := validateGoTLSSymbolTables(f); err == nil {
				t.Fatal("accepted unbounded or invalid ELF symbol allocation")
			}
		})
	}
	if _, err := decodeGoTLSReturns(bytes.Repeat([]byte{0xc3}, 129)); err == nil {
		t.Fatal("accepted an unbounded number of return-probe attachments")
	}
}

func TestGoTLSReadReturnOffsetsExecutableAndStripped(t *testing.T) {
	if err := supportedGoTLSABI(runtime.Version()); err != nil {
		t.Skip(err)
	}
	bin := filepath.Join(t.TempDir(), "tls-client")
	if output, err := exec.Command("go", "build", "-o", bin, "testdata/tls_client.go").CombinedOutput(); err != nil {
		t.Fatalf("build Go ELF: %v\n%s", err, output)
	}
	if offsets, err := goTLSReadReturnOffsets(bin); err != nil || len(offsets) == 0 {
		t.Fatalf("Go Read returns=%v error=%v", offsets, err)
	}
	if output, err := exec.Command("go", "build", "-ldflags=-s -w", "-o", bin, "testdata/tls_client.go").CombinedOutput(); err != nil {
		t.Fatalf("build stripped Go ELF: %v\n%s", err, output)
	}
	if _, err := goTLSReadReturnOffsets(bin); err == nil || !strings.Contains(err.Error(), "unstripped") {
		t.Fatalf("stripped Go binary should explicitly reject Read attachment, got %v", err)
	}
}

func TestGoTLSReturnsRejectUnsupportedInstructions(t *testing.T) {
	for _, code := range [][]byte{nil, {0x90}, {0x0f}, {0xc2, 0x08, 0x00}} {
		if _, err := decodeGoTLSReturns(code); err == nil {
			t.Fatalf("accepted unsupported function %x", code)
		}
	}
}

func TestGoTLSReadABIIsExplicit(t *testing.T) {
	for _, version := range []string{"go1.23.0", "go1.24.9", "go1.25.1", "go1.26.0"} {
		if err := supportedGoTLSABI(version); err != nil {
			t.Errorf("reject %s: %v", version, err)
		}
	}
	for _, version := range []string{"go1.16.0", "go1.27.0", "devel go1.27", "go1.26rc1", "other"} {
		if err := supportedGoTLSABI(version); err == nil {
			t.Errorf("accepted unreviewed ABI %s", version)
		}
	}
}
