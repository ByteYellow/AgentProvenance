//go:build linux && (amd64 || arm64)

package sensor

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var errGoTLSNotLinked = errors.New("Go TLS function is not linked")

// goTLSFunctionLocation resolves a file offset, never a runtime virtual address.
// Stripped Go executables retain pclntab for stack traces. Read only the bounded
// function/name tables; do not allocate from its untrusted function count.
func goTLSFunctionLocation(path, name string) (uint64, []byte, error) {
	if err := validateELFMetadata(path); err != nil {
		return 0, nil, err
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return 0, nil, fmt.Errorf("read Go ABI build information: %w", err)
	}
	if err = supportedGoTLSABI(info.GoVersion); err != nil {
		return 0, nil, err
	}
	for _, s := range info.Settings {
		if s.Key == "GOEXPERIMENT" && (strings.Contains(s.Value, "noregabi") || strings.Contains(s.Value, "none")) {
			return 0, nil, fmt.Errorf("unsupported Go TLS ABI: GOEXPERIMENT=%s", s.Value)
		}
	}
	f, err := elf.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	if f.Machine != elf.EM_X86_64 || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		return 0, nil, fmt.Errorf("Go TLS function resolution requires an amd64 little-endian ELF")
	}
	var start, size uint64
	if syms, symErr := f.Symbols(); symErr == nil {
		for _, s := range syms {
			if s.Name == name && s.Section != elf.SHN_UNDEF && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
				if start != 0 {
					return 0, nil, fmt.Errorf("ambiguous Go TLS symbol %s", name)
				}
				start, size = s.Value, s.Size
			}
		}
	}
	if start == 0 {
		section := f.Section(".gopclntab")
		if section == nil {
			section = f.Section(".data.rel.ro.gopclntab")
		}
		text := f.Section(".text")
		if section == nil || text == nil {
			return 0, nil, fmt.Errorf("Go TLS symbol %s and pclntab are missing", name)
		}
		if section.Flags&elf.SHF_COMPRESSED != 0 {
			return 0, nil, fmt.Errorf("compressed Go pclntab is unsupported")
		}
		start, size, err = goPCLNFunctionReader(section, section.Size, text.Addr, name)
		if err != nil {
			return 0, nil, err
		}
	}
	if size == 0 || size > 1<<20 {
		return 0, nil, fmt.Errorf("invalid Go TLS function size: %d", size)
	}
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 || start < p.Vaddr {
			continue
		}
		rel := start - p.Vaddr
		if rel > p.Filesz || size > p.Filesz-rel {
			continue
		}
		code := make([]byte, int(size))
		if _, err := p.ReadAt(code, int64(rel)); err != nil {
			return 0, nil, err
		}
		return p.Off + rel, code, nil
	}
	return 0, nil, fmt.Errorf("Go TLS function %s is outside executable file segments", name)
}

// Go 1.23–1.26 use the Go 1.20 pclntab layout (runtime/symtab.go).
func goPCLNFunction(data []byte, text uint64, name string) (uint64, uint64, error) {
	return goPCLNFunctionReader(bytes.NewReader(data), uint64(len(data)), text, name)
}

func goPCLNFunctionReader(reader io.ReaderAt, size, text uint64, name string) (uint64, uint64, error) {
	bad := func() (uint64, uint64, error) { return 0, 0, fmt.Errorf("invalid or unsupported Go pclntab") }
	var header [72]byte
	if size < 72 {
		return bad()
	}
	if _, err := reader.ReadAt(header[:], 0); err != nil {
		return bad()
	}
	if binary.LittleEndian.Uint32(header[:]) != 0xfffffff1 || header[4] != 0 || header[5] != 0 || header[6] != 1 || header[7] != 8 {
		return bad()
	}
	u64 := binary.LittleEndian.Uint64
	n, names, namesEnd, funcs := u64(header[8:16]), u64(header[32:40]), u64(header[40:48]), u64(header[64:72])
	tableBytes := (n*2 + 1) * 4
	if n == 0 || n > 200000 || names < 72 || namesEnd <= names || namesEnd-names > maxELFSymbolBytes || funcs < namesEnd || funcs > size || tableBytes > size-funcs || funcs > 1<<62 {
		return bad()
	}
	// Only names and the small PC index are allocated, not line/file/stack maps.
	strings := make([]byte, namesEnd-names)
	table := make([]byte, tableBytes)
	if _, err := reader.ReadAt(strings, int64(names)); err != nil {
		return bad()
	}
	if _, err := reader.ReadAt(table, int64(funcs)); err != nil {
		return bad()
	}
	var found, length uint64
	for i := uint64(0); i < n; i++ {
		entry := uint64(binary.LittleEndian.Uint32(table[i*8:]))
		end := uint64(binary.LittleEndian.Uint32(table[(i+1)*8:]))
		off := uint64(binary.LittleEndian.Uint32(table[i*8+4:]))
		if end <= entry || off < tableBytes || off > size-funcs || size-funcs-off < 8 {
			return bad()
		}
		var record [8]byte
		if _, err := reader.ReadAt(record[:], int64(funcs+off)); err != nil {
			return bad()
		}
		if uint64(binary.LittleEndian.Uint32(record[:])) != entry {
			return bad()
		}
		noff := uint64(binary.LittleEndian.Uint32(record[4:]))
		if noff >= uint64(len(strings)) {
			return bad()
		}
		raw := strings[noff:]
		if len(raw) > 1024 {
			raw = raw[:1024]
		}
		endName := bytes.IndexByte(raw, 0)
		if endName < 0 {
			return bad()
		}
		if string(raw[:endName]) != name {
			continue
		}
		if found != 0 || text > ^uint64(0)-end {
			return bad()
		}
		found, length = text+entry, end-entry
	}
	if found == 0 {
		return 0, 0, fmt.Errorf("%w: %s", errGoTLSNotLinked, name)
	}
	return found, length, nil
}

func supportedGoTLSABI(version string) error {
	parts := strings.Split(strings.TrimPrefix(version, "go"), ".")
	if len(parts) >= 2 && strings.HasPrefix(version, "go") && parts[0] == "1" {
		minor, err := strconv.Atoi(parts[1])
		if err == nil && minor >= 23 && minor <= 26 {
			return nil
		}
	}
	return fmt.Errorf("unsupported Go TLS Read ABI %q (supported: Go 1.23–1.26 amd64 ABIInternal)", version)
}
