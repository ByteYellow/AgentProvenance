package derivedview

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"math"
	"sort"
	"strings"
)

// VerifyZIP validates raw ZIP entries, not zip.Reader's normalized FS view. It
// accepts Store/Deflate, single-disk ZIP/ZIP64 and ordinary directory entries.
// Recompression, entry order, timestamps, permissions and comments do not affect
// signed identity. Ambiguous local/central names, overlaps, unindexed local data,
// self-extracting prefixes and multi-disk archives are rejected. No extraction
// takes place. size is the length of r, not the uncompressed payload size.
func VerifyZIP(ctx context.Context, r io.ReaderAt, size int64, policy TrustPolicy, limits Limits) (Result, error) {
	result := initialResult()
	l, err := effectiveLimits(limits)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if size < 0 || size > l.MaxZIPBytes {
		return failedInput(result, fmt.Errorf("%w: ZIP size", ErrLimit))
	}
	reader := &zipReaderAt{ctx: ctx, r: r, remaining: l.MaxZIPMetadataBytes}
	layout, err := inspectZIP(reader, size, l)
	if err != nil {
		return failedInput(result, err)
	}
	z, err := zip.NewReader(reader, size)
	if err != nil {
		return failedInput(result, err)
	}
	if len(z.File) != len(layout.offsets) {
		return failedInput(result, fmt.Errorf("%w: inconsistent ZIP directory", ErrUnsafe))
	}
	if err := checkLocalRecords(reader, z.File, layout); err != nil {
		return failedInput(result, err)
	}
	// Metadata allocation/reads are now complete. Payloads have their own size
	// limits and are streamed through the same cancellation-aware ReaderAt.
	reader.remaining = -1
	s := newInventory(l)
	for _, file := range z.File {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		mode := file.Mode().Type()
		if mode != 0 && mode != fs.ModeDir {
			return failedInput(result, fmt.Errorf("%w: nonregular ZIP member %q", ErrUnsafe, file.Name))
		}
		if file.Flags&1 != 0 || (file.Method != zip.Store && file.Method != zip.Deflate) {
			return failedInput(result, fmt.Errorf("%w: encrypted or unsupported ZIP member", ErrUnsafe))
		}
		if file.UncompressedSize64 > math.MaxInt64 {
			return failedInput(result, fmt.Errorf("%w: ZIP member size", ErrLimit))
		}
		isDir := file.FileInfo().IsDir()
		name := file.Name
		if isDir {
			if !strings.HasSuffix(name, "/") {
				return failedInput(result, fmt.Errorf("%w: inconsistent ZIP directory mode", ErrUnsafe))
			}
			name = strings.TrimSuffix(name, "/")
		}
		e := entry{name: name, size: int64(file.UncompressedSize64), open: file.Open}
		if err := s.add(e, isDir); err != nil {
			return failedInput(result, err)
		}
		if isDir {
			if _, err := streamEntry(ctx, e, nil); err != nil {
				return failedInput(result, err)
			}
		}
	}
	return verifyEntries(ctx, s, policy)
}

type zipReaderAt struct {
	ctx       context.Context
	r         io.ReaderAt
	remaining int64
}

func (r *zipReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining >= 0 {
		if int64(len(p)) > r.remaining {
			return 0, fmt.Errorf("%w: ZIP metadata reads", ErrLimit)
		}
		r.remaining -= int64(len(p))
	}
	return r.r.ReadAt(p, off)
}

type zipLayout struct {
	directory int64
	offsets   []int64
}

// archive/zip allocates from the directory count before exposing entries. Bound
// that count, then count actual central records before letting it parse them.
func inspectZIP(r io.ReaderAt, size int64, limits Limits) (zipLayout, error) {
	invalid := func() (zipLayout, error) {
		return zipLayout{}, fmt.Errorf("%w: malformed or ambiguous ZIP directory", ErrUnsafe)
	}
	if size < 22 {
		return invalid()
	}
	tailSize := min(size, 22+65535)
	tail := make([]byte, int(tailSize))
	if _, err := r.ReadAt(tail, size-tailSize); err != nil {
		return zipLayout{}, err
	}
	index := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == 0x06054b50 {
			// Match archive/zip's last-signature choice. Skipping a later fake
			// EOCD in a comment could leave its allocation count unbounded.
			if i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) != len(tail) {
				return invalid()
			}
			index = i
			break
		}
	}
	if index < 0 {
		return invalid()
	}
	end := tail[index:]
	endOffset := size - tailSize + int64(index)
	if binary.LittleEndian.Uint16(end[4:]) != 0 || binary.LittleEndian.Uint16(end[6:]) != 0 || binary.LittleEndian.Uint16(end[8:]) != binary.LittleEndian.Uint16(end[10:]) {
		return invalid()
	}
	count := uint64(binary.LittleEndian.Uint16(end[10:]))
	dirSize := uint64(binary.LittleEndian.Uint32(end[12:]))
	dirOffset := uint64(binary.LittleEndian.Uint32(end[16:]))
	if count == 0xffff || dirSize == 0xffffffff || dirSize == 0xffff || dirOffset == 0xffffffff {
		// ZIP64 is also valid for small archives produced by streaming writers.
		var locator [20]byte
		if endOffset < 20 {
			return invalid()
		}
		if _, err := r.ReadAt(locator[:], endOffset-20); err != nil {
			return zipLayout{}, err
		}
		if binary.LittleEndian.Uint32(locator[:]) == 0x07064b50 {
			if binary.LittleEndian.Uint32(locator[4:]) != 0 || binary.LittleEndian.Uint32(locator[16:]) != 1 {
				return invalid()
			}
			offset := binary.LittleEndian.Uint64(locator[8:])
			if offset > uint64(endOffset-20) || uint64(endOffset-20)-offset < 56 {
				return invalid()
			}
			var header [56]byte
			if _, err := r.ReadAt(header[:], int64(offset)); err != nil {
				return zipLayout{}, err
			}
			if binary.LittleEndian.Uint32(header[:]) != 0x06064b50 || binary.LittleEndian.Uint64(header[4:]) != uint64(endOffset-20)-offset-12 ||
				binary.LittleEndian.Uint32(header[16:]) != 0 || binary.LittleEndian.Uint32(header[20:]) != 0 ||
				binary.LittleEndian.Uint64(header[24:]) != binary.LittleEndian.Uint64(header[32:]) {
				return invalid()
			}
			count = binary.LittleEndian.Uint64(header[32:])
			dirSize = binary.LittleEndian.Uint64(header[40:])
			dirOffset = binary.LittleEndian.Uint64(header[48:])
			endOffset = int64(offset)
		} else if count == 0xffff || dirSize == 0xffffffff || dirOffset == 0xffffffff {
			return invalid()
		}
	}
	if count > uint64(limits.MaxEntries) || dirSize > uint64(limits.MaxZIPMetadataBytes) {
		return zipLayout{}, fmt.Errorf("%w: ZIP central directory", ErrLimit)
	}
	if dirOffset > uint64(endOffset) || dirSize != uint64(endOffset)-dirOffset {
		return invalid()
	}
	layout := zipLayout{directory: int64(dirOffset)}
	position := int64(dirOffset)
	for position < endOffset {
		if len(layout.offsets) >= limits.MaxEntries {
			return zipLayout{}, fmt.Errorf("%w: actual ZIP entry count", ErrLimit)
		}
		var h [46]byte
		if endOffset-position < int64(len(h)) {
			return invalid()
		}
		if _, err := r.ReadAt(h[:], position); err != nil {
			return zipLayout{}, err
		}
		nameLen, extraLen, commentLen := int(binary.LittleEndian.Uint16(h[28:])), int(binary.LittleEndian.Uint16(h[30:])), int(binary.LittleEndian.Uint16(h[32:]))
		length := int64(46 + nameLen + extraLen + commentLen)
		if binary.LittleEndian.Uint32(h[:]) != 0x02014b50 || length > endOffset-position || binary.LittleEndian.Uint16(h[34:]) != 0 {
			return invalid()
		}
		if nameLen > limits.MaxPathBytes+1 {
			return zipLayout{}, fmt.Errorf("%w: ZIP path length", ErrLimit)
		}
		offset := uint64(binary.LittleEndian.Uint32(h[42:]))
		if offset == 0xffffffff {
			extra := make([]byte, extraLen)
			if _, err := r.ReadAt(extra, position+46+int64(nameLen)); err != nil {
				return zipLayout{}, err
			}
			found := false
			for len(extra) >= 4 {
				id, n := binary.LittleEndian.Uint16(extra), int(binary.LittleEndian.Uint16(extra[2:]))
				extra = extra[4:]
				if n > len(extra) {
					return invalid()
				}
				if id == 1 {
					skip := 0
					if binary.LittleEndian.Uint32(h[24:]) == 0xffffffff {
						skip += 8
					}
					if binary.LittleEndian.Uint32(h[20:]) == 0xffffffff {
						skip += 8
					}
					if found || n < skip+8 {
						return invalid()
					}
					offset, found = binary.LittleEndian.Uint64(extra[skip:]), true
				}
				extra = extra[n:]
			}
			if !found {
				return invalid()
			}
		}
		if offset >= dirOffset {
			return invalid()
		}
		layout.offsets = append(layout.offsets, int64(offset))
		position += length
	}
	if uint64(len(layout.offsets)) != count {
		return invalid()
	}
	return layout, nil
}

func checkLocalRecords(r io.ReaderAt, files []*zip.File, layout zipLayout) error {
	type record struct {
		start, end int64
		file       *zip.File
	}
	records := make([]record, 0, len(files))
	for i, file := range files {
		var header [30]byte
		start := layout.offsets[i]
		if layout.directory-start < int64(len(header)) {
			return fmt.Errorf("%w: truncated ZIP local header", ErrUnsafe)
		}
		if _, err := r.ReadAt(header[:], start); err != nil {
			return err
		}
		nameLen, extraLen := int64(binary.LittleEndian.Uint16(header[26:])), int64(binary.LittleEndian.Uint16(header[28:]))
		if nameLen+extraLen > layout.directory-start-30 {
			return fmt.Errorf("%w: truncated ZIP local metadata", ErrUnsafe)
		}
		data := start + 30 + nameLen + extraLen
		if binary.LittleEndian.Uint32(header[:]) != 0x04034b50 || binary.LittleEndian.Uint16(header[6:]) != file.Flags ||
			binary.LittleEndian.Uint16(header[8:]) != file.Method || nameLen != int64(len(file.Name)) || data > layout.directory ||
			file.CompressedSize64 > uint64(layout.directory-data) {
			return fmt.Errorf("%w: conflicting ZIP local header", ErrUnsafe)
		}
		name := make([]byte, int(nameLen))
		if _, err := r.ReadAt(name, start+30); err != nil {
			return err
		}
		if !bytes.Equal(name, []byte(file.Name)) {
			return fmt.Errorf("%w: local/central ZIP path mismatch", ErrUnsafe)
		}
		if file.Flags&8 == 0 && (binary.LittleEndian.Uint32(header[14:]) != file.CRC32 ||
			(binary.LittleEndian.Uint32(header[18:]) != 0xffffffff && uint64(binary.LittleEndian.Uint32(header[18:])) != file.CompressedSize64) ||
			(binary.LittleEndian.Uint32(header[22:]) != 0xffffffff && uint64(binary.LittleEndian.Uint32(header[22:])) != file.UncompressedSize64)) {
			return fmt.Errorf("%w: local/central ZIP length or CRC mismatch", ErrUnsafe)
		}
		records = append(records, record{start: start, end: data + int64(file.CompressedSize64), file: file})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].start < records[j].start })
	if len(records) == 0 && layout.directory != 0 {
		return fmt.Errorf("%w: unindexed ZIP data", ErrUnsafe)
	}
	for i, rec := range records {
		if i == 0 && rec.start != 0 {
			return fmt.Errorf("%w: ZIP prefix or unindexed local file", ErrUnsafe)
		}
		next := layout.directory
		if i+1 < len(records) {
			next = records[i+1].start
		}
		gap := next - rec.end
		if rec.file.Flags&8 == 0 {
			if gap != 0 {
				return fmt.Errorf("%w: overlapping or unindexed ZIP data", ErrUnsafe)
			}
			continue
		}
		if gap != 12 && gap != 16 && gap != 20 && gap != 24 {
			return fmt.Errorf("%w: invalid ZIP descriptor span", ErrUnsafe)
		}
		descriptor := make([]byte, int(gap))
		if _, err := r.ReadAt(descriptor, rec.end); err != nil {
			return err
		}
		if gap == 16 || gap == 24 {
			if binary.LittleEndian.Uint32(descriptor) != 0x08074b50 {
				return fmt.Errorf("%w: invalid ZIP descriptor signature", ErrUnsafe)
			}
			descriptor = descriptor[4:]
		}
		compressed, uncompressed := uint64(binary.LittleEndian.Uint32(descriptor[4:])), uint64(binary.LittleEndian.Uint32(descriptor[8:]))
		if len(descriptor) == 20 {
			compressed, uncompressed = binary.LittleEndian.Uint64(descriptor[4:]), binary.LittleEndian.Uint64(descriptor[12:])
		}
		if binary.LittleEndian.Uint32(descriptor) != rec.file.CRC32 || compressed != rec.file.CompressedSize64 || uncompressed != rec.file.UncompressedSize64 {
			return fmt.Errorf("%w: ZIP descriptor differs from directory", ErrUnsafe)
		}
	}
	return nil
}
