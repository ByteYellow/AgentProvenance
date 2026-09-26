//go:build linux && (amd64 || arm64)

package sensor

import (
	"debug/elf"
	"encoding/binary"
	"os"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

// Validate metadata before debug/elf opens it: elf.Open itself reads shstrtab,
// and Symbols also loads its linked string table. Checking only symbol section
// sizes after elf.Open is too late for a container-supplied malformed binary.
func validateELFMetadata(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	var header [64]byte
	if _, err := f.ReadAt(header[:], 0); err != nil {
		return err
	}
	if string(header[:4]) != "\x7fELF" {
		return i18n.Errorf("not an ELF file")
	}
	var order binary.ByteOrder
	switch elf.Data(header[5]) {
	case elf.ELFDATA2LSB:
		order = binary.LittleEndian
	case elf.ELFDATA2MSB:
		order = binary.BigEndian
	default:
		return i18n.Errorf("unsupported ELF byte order")
	}
	var offset uint64
	var entrySize, count uint16
	class := elf.Class(header[4])
	switch class {
	case elf.ELFCLASS64:
		offset = order.Uint64(header[40:48])
		entrySize = order.Uint16(header[58:60])
		count = order.Uint16(header[60:62])
		if entrySize != 64 {
			return i18n.Errorf("unsupported ELF64 section layout")
		}
	case elf.ELFCLASS32:
		offset = uint64(order.Uint32(header[32:36]))
		entrySize = order.Uint16(header[46:48])
		count = order.Uint16(header[48:50])
		if entrySize != 40 {
			return i18n.Errorf("unsupported ELF32 section layout")
		}
	default:
		return i18n.Errorf("unsupported ELF class")
	}
	// Extended numbering and section-less ELF cannot supply the symbols needed
	// for these uprobes. Do not allocate based on attacker-controlled counts.
	if count == 0 || offset > uint64(info.Size()) || uint64(count)*uint64(entrySize) > uint64(info.Size())-offset {
		return i18n.Errorf("ELF section table missing or outside file")
	}
	var section [64]byte
	var total uint64
	for i := uint16(0); i < count; i++ {
		if _, err := f.ReadAt(section[:entrySize], int64(offset+uint64(i)*uint64(entrySize))); err != nil {
			return err
		}
		typ := elf.SectionType(order.Uint32(section[4:8]))
		if typ != elf.SHT_SYMTAB && typ != elf.SHT_DYNSYM && typ != elf.SHT_STRTAB {
			continue
		}
		var size, flags uint64
		if class == elf.ELFCLASS64 {
			size = order.Uint64(section[32:40])
			flags = order.Uint64(section[8:16])
		} else {
			size = uint64(order.Uint32(section[20:24]))
			flags = uint64(order.Uint32(section[8:12]))
		}
		if flags&uint64(elf.SHF_COMPRESSED) != 0 {
			return i18n.Errorf("compressed ELF symbol metadata unsupported")
		}
		if size > maxELFSymbolBytes {
			return i18n.Errorf("ELF symbol/string section exceeds 16 MiB")
		}
		total += size
		if total > 2*maxELFSymbolBytes {
			return i18n.Errorf("ELF symbol/string metadata exceeds 32 MiB")
		}
	}
	return nil
}
