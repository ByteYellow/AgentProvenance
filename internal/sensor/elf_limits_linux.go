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
	return validateELFTables(path, false)
}

// Dynamic-only resolution never loads the ordinary symbol/string tables. Keep
// the same budgets for the section names, dynamic symbols and linked strings.
func validateELFDynamicMetadata(path string) error {
	return validateELFTables(path, true)
}

func validateELFTables(path string, dynamicOnly bool) error {
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
	var entrySize, count, names uint16
	class := elf.Class(header[4])
	switch class {
	case elf.ELFCLASS64:
		offset = order.Uint64(header[40:48])
		entrySize = order.Uint16(header[58:60])
		count = order.Uint16(header[60:62])
		names = order.Uint16(header[62:64])
		if entrySize != 64 {
			return i18n.Errorf("unsupported ELF64 section layout")
		}
	case elf.ELFCLASS32:
		offset = uint64(order.Uint32(header[32:36]))
		entrySize = order.Uint16(header[46:48])
		count = order.Uint16(header[48:50])
		names = order.Uint16(header[50:52])
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
	type metadata struct {
		kind                elf.SectionType
		size, flags, offset uint64
		link                uint32
	}
	read := func(index uint32) (metadata, error) {
		var m metadata
		if index >= uint32(count) {
			return m, i18n.Errorf("ELF metadata section index outside table")
		}
		var section [64]byte
		if _, err := f.ReadAt(section[:entrySize], int64(offset+uint64(index)*uint64(entrySize))); err != nil {
			return m, err
		}
		m.kind = elf.SectionType(order.Uint32(section[4:8]))
		if class == elf.ELFCLASS64 {
			m.size, m.flags = order.Uint64(section[32:40]), order.Uint64(section[8:16])
			m.offset, m.link = order.Uint64(section[24:32]), order.Uint32(section[40:44])
		} else {
			m.size, m.flags = uint64(order.Uint32(section[20:24])), uint64(order.Uint32(section[8:12]))
			m.offset, m.link = uint64(order.Uint32(section[16:20])), order.Uint32(section[24:28])
		}
		return m, nil
	}
	var total uint64
	checked := map[uint32]bool{}
	check := func(index uint32, m metadata) error {
		if checked[index] {
			return nil
		}
		checked[index] = true
		if m.flags&uint64(elf.SHF_COMPRESSED) != 0 {
			return i18n.Errorf("compressed ELF symbol metadata unsupported")
		}
		if m.size > maxELFSymbolBytes {
			return i18n.Errorf("ELF symbol/string section exceeds 16 MiB")
		}
		if m.offset > uint64(info.Size()) || m.size > uint64(info.Size())-m.offset {
			return i18n.Errorf("ELF symbol/string section outside file")
		}
		total += m.size
		if total > 2*maxELFSymbolBytes {
			return i18n.Errorf("ELF symbol/string metadata exceeds 32 MiB")
		}
		return nil
	}
	if names != 0 {
		m, err := read(uint32(names))
		if err != nil {
			return err
		}
		if m.kind != elf.SHT_STRTAB {
			return i18n.Errorf("invalid ELF section-name string table")
		}
		if err := check(uint32(names), m); err != nil {
			return err
		}
	}
	for i := uint32(0); i < uint32(count); i++ {
		m, err := read(i)
		if err != nil {
			return err
		}
		// DynamicSymbols also reads GNU version metadata, even though probe
		// lookup only uses names and addresses. Bound those sections as well.
		versions := m.kind == elf.SHT_GNU_VERNEED || m.kind == elf.SHT_GNU_VERSYM || m.kind == elf.SHT_GNU_VERDEF
		symbols := m.kind == elf.SHT_DYNSYM || !dynamicOnly && (m.kind == elf.SHT_SYMTAB || m.kind == elf.SHT_STRTAB)
		if !symbols && !versions {
			continue
		}
		if err := check(i, m); err != nil {
			return err
		}
		if dynamicOnly && m.kind == elf.SHT_DYNSYM {
			strings, err := read(m.link)
			if err != nil {
				return err
			}
			if strings.kind != elf.SHT_STRTAB {
				return i18n.Errorf("invalid ELF dynamic symbol string-table link")
			}
			if err := check(m.link, strings); err != nil {
				return err
			}
		}
	}
	return nil
}
