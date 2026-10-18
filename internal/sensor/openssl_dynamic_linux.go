//go:build linux && (amd64 || arm64)

package sensor

import (
	"debug/elf"
	"os"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

// Large executables can have a small exported symbol table and an unrelated
// oversized debug string table. Resolve only bounded dynamic metadata, then
// pass file offsets so the uprobe library never lazily loads the latter.
func opensslDynamicOffsets(path string) (map[string]uint64, error) {
	if err := validateELFDynamicMetadata(path); err != nil {
		return nil, err
	}
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	syms, err := f.DynamicSymbols()
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, name := range []string{"SSL_new", "SSL_free", "SSL_clear", "SSL_set_bio", "SSL_set0_rbio", "SSL_set0_wbio", "SSL_set_fd", "SSL_set_rfd", "SSL_set_wfd", "SSL_write", "SSL_write_ex", "SSL_read", "SSL_read_ex"} {
		wanted[name] = true
	}
	result := map[string]uint64{}
	for _, sym := range syms {
		if !wanted[sym.Name] || sym.Section == elf.SHN_UNDEF || sym.Value == 0 || elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}
		for _, prog := range f.Progs {
			if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 || sym.Value < prog.Vaddr {
				continue
			}
			rel := sym.Value - prog.Vaddr
			if rel >= prog.Filesz || sym.Size > prog.Filesz-rel || prog.Off > uint64(info.Size()) || prog.Filesz > uint64(info.Size())-prog.Off {
				continue
			}
			offset := prog.Off + rel
			if offset == 0 {
				continue
			}
			if previous, ok := result[sym.Name]; ok && previous != offset {
				return nil, i18n.Errorf("ambiguous dynamic TLS symbol %s", sym.Name)
			}
			result[sym.Name] = offset
		}
	}
	return result, nil
}
