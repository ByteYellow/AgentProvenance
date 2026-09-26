package sensor

import (
	"debug/buildinfo"
	"debug/elf"
	"strconv"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/cilium/ebpf/link"
	"golang.org/x/arch/x86/x86asm"
)

const goTLSReadSymbol = "crypto/tls.(*Conn).Read"

// attachGoTLSRead never installs a uretprobe: its return trampoline corrupts
// Go's stack unwinding when a goroutine grows or changes OS threads. Ordinary
// uprobes at the actual RET instructions observe return registers without
// changing the return address. Either every return site and entry is attached,
// or every newly created link is closed and the caller reports a degradation.
func attachGoTLSRead(ex *link.Executable, path string, objs *sensorbpfObjects) ([]link.Link, error) {
	offsets, err := goTLSReadReturnOffsets(path)
	if err != nil {
		return nil, err
	}
	links := make([]link.Link, 0, len(offsets)+1)
	cleanup := func() {
		for _, l := range links {
			_ = l.Close()
		}
	}
	for _, offset := range offsets {
		l, err := ex.Uprobe(goTLSReadSymbol, objs.HandleGoTlsReadReturn, &link.UprobeOptions{Offset: offset})
		if err != nil {
			cleanup()
			return nil, i18n.Errorf("attach Go TLS Read return +%#x: %w", offset, err)
		}
		links = append(links, l)
	}
	l, err := ex.Uprobe(goTLSReadSymbol, objs.HandleGoTlsReadEnter, nil)
	if err != nil {
		cleanup()
		return nil, i18n.Errorf("attach Go TLS Read entry: %w", err)
	}
	return append(links, l), nil
}

func goTLSReadReturnOffsets(path string) ([]uint64, error) {
	if err := validateELFMetadata(path); err != nil {
		return nil, i18n.Errorf("inspect Go TLS ELF: %w", err)
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, i18n.Errorf("read Go ABI build information: %w", err)
	}
	if err := supportedGoTLSABI(info.GoVersion); err != nil {
		return nil, err
	}
	for _, setting := range info.Settings {
		if setting.Key == "GOEXPERIMENT" && (strings.Contains(setting.Value, "noregabi") || strings.Contains(setting.Value, "none")) {
			return nil, i18n.Errorf("unsupported Go TLS ABI: GOEXPERIMENT=%s", setting.Value)
		}
	}
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Machine != elf.EM_X86_64 || f.Class != elf.ELFCLASS64 {
		return nil, i18n.Errorf("Go TLS Read requires an amd64 ELF")
	}
	if err := validateGoTLSSymbolTables(f); err != nil {
		return nil, err
	}
	symbols, err := f.Symbols()
	if err != nil {
		return nil, i18n.Errorf("Go TLS Read requires an unstripped symbol table: %w", err)
	}
	for _, symbol := range symbols {
		if symbol.Name != goTLSReadSymbol || elf.ST_TYPE(symbol.Info) != elf.STT_FUNC {
			continue
		}
		if symbol.Size == 0 || symbol.Size > 1<<20 {
			return nil, i18n.Errorf("invalid Go TLS Read symbol size: %d", symbol.Size)
		}
		for _, p := range f.Progs {
			if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 || symbol.Value < p.Vaddr {
				continue
			}
			rel := symbol.Value - p.Vaddr
			if rel > p.Filesz || symbol.Size > p.Filesz-rel {
				continue
			}
			code := make([]byte, int(symbol.Size))
			if _, err := p.ReadAt(code, int64(rel)); err != nil {
				return nil, i18n.Errorf("read Go TLS Read instructions: %w", err)
			}
			return decodeGoTLSReturns(code)
		}
		return nil, i18n.Errorf("Go TLS Read symbol is outside executable file segments")
	}
	return nil, i18n.Errorf("Go TLS Read symbol is missing (stripped or not linked)")
}

func validateGoTLSSymbolTables(f *elf.File) error {
	for _, section := range f.Sections {
		if section.Type != elf.SHT_SYMTAB {
			continue
		}
		if section.Size > maxELFSymbolBytes {
			return i18n.Errorf("Go TLS Read symbol table exceeds %d-byte inspection limit", maxELFSymbolBytes)
		}
		if uint64(section.Link) >= uint64(len(f.Sections)) {
			return i18n.Errorf("Go TLS Read symbol table has an invalid string-table link")
		}
		strings := f.Sections[section.Link]
		if strings.Type != elf.SHT_STRTAB || strings.Size > maxELFSymbolBytes {
			return i18n.Errorf("Go TLS Read linked string table is invalid or exceeds %d-byte inspection limit", maxELFSymbolBytes)
		}
	}
	return nil
}

func supportedGoTLSABI(version string) error {
	parts := strings.Split(strings.TrimPrefix(version, "go"), ".")
	if len(parts) >= 2 && strings.HasPrefix(version, "go") && parts[0] == "1" {
		minor, err := strconv.Atoi(parts[1])
		// The probe relies on ABIInternal and runtime.g's stack bounds. Fail
		// explicitly on unreviewed toolchains rather than claiming coverage.
		if err == nil && minor >= 23 && minor <= 26 {
			return nil
		}
	}
	return i18n.Errorf("unsupported Go TLS Read ABI %q (supported: Go 1.23–1.26 amd64 ABIInternal)", version)
}

func decodeGoTLSReturns(code []byte) ([]uint64, error) {
	var offsets []uint64
	for offset := 0; offset < len(code); {
		inst, err := x86asm.Decode(code[offset:], 64)
		if err != nil || inst.Len == 0 || inst.Op == 0 {
			return nil, i18n.Errorf("cannot decode Go TLS Read instruction at +%#x", offset)
		}
		if inst.Op == x86asm.RET {
			if inst.Args[0] != nil {
				return nil, i18n.Errorf("unsupported Go TLS Read RET operand at +%#x", offset)
			}
			offsets = append(offsets, uint64(offset))
			if len(offsets) > 128 {
				return nil, i18n.Errorf("Go TLS Read exceeds the 128 return-probe attachment limit")
			}
		}
		offset += inst.Len
	}
	if len(offsets) == 0 {
		return nil, i18n.Errorf("Go TLS Read has no decoded RET instructions")
	}
	return offsets, nil
}
