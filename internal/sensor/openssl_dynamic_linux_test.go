//go:build linux && (amd64 || arm64)

package sensor

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A sparse, valid ELF has bounded dynamic symbols and an unused large .strtab,
// matching the layout that previously excluded the Node executable.
func dynamicTLSFixture(t *testing.T, mutate func([]byte)) string {
	t.Helper()
	b := make([]byte, 0x2200)
	order := binary.LittleEndian
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	order.PutUint16(b[16:], uint16(elf.ET_DYN))
	order.PutUint16(b[18:], uint16(elf.EM_X86_64))
	order.PutUint32(b[20:], 1)
	order.PutUint64(b[32:], 64)
	order.PutUint64(b[40:], 128)
	order.PutUint16(b[52:], 64)
	order.PutUint16(b[54:], 56)
	order.PutUint16(b[56:], 1)
	order.PutUint16(b[58:], 64)
	order.PutUint16(b[60:], 5)
	order.PutUint32(b[64:], uint32(elf.PT_LOAD))
	order.PutUint32(b[68:], uint32(elf.PF_R|elf.PF_X))
	order.PutUint64(b[72:], 0x1000)
	order.PutUint64(b[80:], 0x401000)
	order.PutUint64(b[96:], 64)
	order.PutUint64(b[104:], 64)
	section := func(index int, kind elf.SectionType, offset, size uint64) []byte {
		s := b[128+index*64:]
		order.PutUint32(s[4:], uint32(kind))
		order.PutUint64(s[24:], offset)
		order.PutUint64(s[32:], size)
		return s
	}
	section(1, elf.SHT_PROGBITS, 0x1000, 64)
	s := section(2, elf.SHT_DYNSYM, 0x2000, 3*24)
	order.PutUint32(s[40:], 3)
	order.PutUint64(s[56:], 24)
	names := "\x00SSL_write\x00SSL_read_ex\x00"
	section(3, elf.SHT_STRTAB, 0x2100, uint64(len(names)))
	section(4, elf.SHT_STRTAB, 0x2200, maxELFSymbolBytes+1)
	copy(b[0x2100:], names)
	for i, name := range []uint32{1, 11} {
		s := b[0x2000+(i+1)*24:]
		order.PutUint32(s, name)
		s[4] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)
		order.PutUint16(s[6:], 1)
		order.PutUint64(s[8:], 0x401010+uint64(i)*16)
		order.PutUint64(s[16:], 8)
	}
	if mutate != nil {
		mutate(b)
	}
	path := filepath.Join(t.TempDir(), "large-elf")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(0x2200 + maxELFSymbolBytes + 1); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenSSLDynamicOffsetsAvoidUnusedLargeStringTable(t *testing.T) {
	path := dynamicTLSFixture(t, nil)
	if err := validateELFMetadata(path); err == nil || !strings.Contains(err.Error(), "16 MiB") {
		t.Fatalf("whole-table protection changed: %v", err)
	}
	offsets, err := opensslDynamicOffsets(path)
	if err != nil || offsets["SSL_write"] != 0x1010 || offsets["SSL_read_ex"] != 0x1020 || len(offsets) != 2 {
		t.Fatalf("bounded exported offsets: %v %v", offsets, err)
	}
	if kind := classifyTLSExecutable(path); kind.kind != "openssl" || kind.unsupported {
		t.Fatalf("dynamic TLS discovery: %+v", kind)
	}
}

func TestOpenSSLDynamicMetadataBounds(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"aggregate metadata budget": func(b []byte) {
			binary.LittleEndian.PutUint16(b[62:], 4)
			for _, index := range []int{2, 3, 4} {
				binary.LittleEndian.PutUint64(b[128+index*64+24:], 0)
				binary.LittleEndian.PutUint64(b[128+index*64+32:], maxELFSymbolBytes)
			}
			binary.LittleEndian.PutUint64(b[128+4*64+32:], 1)
		},
		"large dynamic symbols":      func(b []byte) { binary.LittleEndian.PutUint64(b[128+2*64+32:], maxELFSymbolBytes+1) },
		"large linked strings":       func(b []byte) { binary.LittleEndian.PutUint64(b[128+3*64+32:], maxELFSymbolBytes+1) },
		"large section names":        func(b []byte) { binary.LittleEndian.PutUint16(b[62:], 4) },
		"invalid section names":      func(b []byte) { binary.LittleEndian.PutUint16(b[62:], 5) },
		"invalid linked section":     func(b []byte) { binary.LittleEndian.PutUint32(b[128+2*64+40:], 5) },
		"wrong linked type":          func(b []byte) { binary.LittleEndian.PutUint32(b[128+2*64+40:], 1) },
		"compressed dynamic symbols": func(b []byte) { binary.LittleEndian.PutUint64(b[128+2*64+8:], uint64(elf.SHF_COMPRESSED)) },
		"compressed linked strings":  func(b []byte) { binary.LittleEndian.PutUint64(b[128+3*64+8:], uint64(elf.SHF_COMPRESSED)) },
		"strings outside file":       func(b []byte) { binary.LittleEndian.PutUint64(b[128+3*64+24:], 1<<63) },
		"symbol table outside file":  func(b []byte) { binary.LittleEndian.PutUint64(b[128+2*64+24:], 1<<63) },
		"large version needs":        func(b []byte) { binary.LittleEndian.PutUint32(b[128+4*64+4:], uint32(elf.SHT_GNU_VERNEED)) },
		"large symbol versions":      func(b []byte) { binary.LittleEndian.PutUint32(b[128+4*64+4:], uint32(elf.SHT_GNU_VERSYM)) },
		"large version definitions":  func(b []byte) { binary.LittleEndian.PutUint32(b[128+4*64+4:], uint32(elf.SHT_GNU_VERDEF)) },
		"compressed version metadata": func(b []byte) {
			binary.LittleEndian.PutUint32(b[128+4*64+4:], uint32(elf.SHT_GNU_VERNEED))
			binary.LittleEndian.PutUint64(b[128+4*64+32:], 16)
			binary.LittleEndian.PutUint64(b[128+4*64+8:], uint64(elf.SHF_COMPRESSED))
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := dynamicTLSFixture(t, mutate)
			if err := validateELFDynamicMetadata(path); err == nil {
				t.Fatal("unsafe dynamic metadata accepted")
			}
			if _, err := opensslDynamicOffsets(path); err == nil {
				t.Fatal("unsafe metadata reached symbol parsing")
			}
		})
	}
}

func TestOpenSSLDynamicSymbolsRequireExecutableFileOffsets(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"undefined":                  func(b []byte) { binary.LittleEndian.PutUint16(b[0x2000+24+6:], 0) },
		"outside segment":            func(b []byte) { binary.LittleEndian.PutUint64(b[0x2000+24+8:], 0x402000) },
		"extends past segment":       func(b []byte) { binary.LittleEndian.PutUint64(b[0x2000+24+16:], 64) },
		"object instead of function": func(b []byte) { b[0x2000+24+4] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT) },
		"unbacked load segment":      func(b []byte) { binary.LittleEndian.PutUint64(b[72:], 1<<30) },
		"nonexecutable load":         func(b []byte) { binary.LittleEndian.PutUint32(b[68:], uint32(elf.PF_R)) },
	} {
		t.Run(name, func(t *testing.T) {
			offsets, err := opensslDynamicOffsets(dynamicTLSFixture(t, mutate))
			if err != nil || offsets["SSL_write"] != 0 {
				t.Fatalf("invalid function offset: %v %v", offsets, err)
			}
		})
	}
}

func TestOpenSSLDynamicOffsetsRejectConflictingExports(t *testing.T) {
	path := dynamicTLSFixture(t, func(b []byte) { binary.LittleEndian.PutUint32(b[0x2000+48:], 1) })
	if _, err := opensslDynamicOffsets(path); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous TLS symbol accepted: %v", err)
	}
}

func TestOpenSSLDynamicOffsetsLiveExecutable(t *testing.T) {
	path := os.Getenv("AGENTPROV_LIVE_OPENSSL_BINARY")
	if path == "" {
		t.Skip("set AGENTPROV_LIVE_OPENSSL_BINARY for an exported OpenSSL executable")
	}
	offsets, err := opensslDynamicOffsets(path)
	if err != nil || len(offsets) != 13 {
		t.Fatalf("complete dynamic OpenSSL probe set: %v %v", offsets, err)
	}
	if got := classifyTLSExecutable(path); got.kind != "openssl" || got.unsupported {
		t.Fatalf("live executable discovery: %+v", got)
	}
}
