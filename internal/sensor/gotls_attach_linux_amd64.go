package sensor

import (
	"debug/elf"

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
	address, code, err := goTLSFunctionLocation(path, goTLSReadSymbol)
	if err != nil {
		return nil, err
	}
	offsets, err := decodeGoTLSReturns(code)
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
		l, err := ex.Uprobe(goTLSReadSymbol, objs.HandleGoTlsReadReturn, &link.UprobeOptions{Address: address, Offset: offset})
		if err != nil {
			cleanup()
			return nil, i18n.Errorf("attach Go TLS Read return +%#x: %w", offset, err)
		}
		links = append(links, l)
	}
	l, err := ex.Uprobe(goTLSReadSymbol, objs.HandleGoTlsReadEnter, &link.UprobeOptions{Address: address})
	if err != nil {
		cleanup()
		return nil, i18n.Errorf("attach Go TLS Read entry: %w", err)
	}
	return append(links, l), nil
}

func goTLSReadReturnOffsets(path string) ([]uint64, error) {
	_, code, err := goTLSFunctionLocation(path, goTLSReadSymbol)
	if err != nil {
		return nil, err
	}
	return decodeGoTLSReturns(code)
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
