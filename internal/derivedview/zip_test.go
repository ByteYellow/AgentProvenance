package derivedview

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"
)

func zip64Directory(t *testing.T, data []byte) []byte {
	t.Helper()
	end := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if end < 0 {
		t.Fatal("missing EOCD")
	}
	eocd := bytes.Clone(data[end:])
	count := binary.LittleEndian.Uint16(eocd[10:])
	header := make([]byte, 56)
	binary.LittleEndian.PutUint32(header, 0x06064b50)
	binary.LittleEndian.PutUint64(header[4:], 44)
	binary.LittleEndian.PutUint16(header[12:], 45)
	binary.LittleEndian.PutUint16(header[14:], 45)
	binary.LittleEndian.PutUint64(header[24:], uint64(count))
	binary.LittleEndian.PutUint64(header[32:], uint64(count))
	binary.LittleEndian.PutUint64(header[40:], uint64(binary.LittleEndian.Uint32(eocd[12:])))
	binary.LittleEndian.PutUint64(header[48:], uint64(binary.LittleEndian.Uint32(eocd[16:])))
	locator := make([]byte, 20)
	binary.LittleEndian.PutUint32(locator, 0x07064b50)
	binary.LittleEndian.PutUint64(locator[8:], uint64(end))
	binary.LittleEndian.PutUint32(locator[16:], 1)
	binary.LittleEndian.PutUint16(eocd[8:], 0xffff)
	binary.LittleEndian.PutUint16(eocd[10:], 0xffff)
	binary.LittleEndian.PutUint32(eocd[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(eocd[16:], 0xffffffff)
	result := append(bytes.Clone(data[:end]), header...)
	result = append(result, locator...)
	return append(result, eocd...)
}

func TestZIP64AndPreallocationLimits(t *testing.T) {
	files, _, _, policy := fixture(t)
	data := zip64Directory(t, zipFS(t, files, true))
	got, err := verifyZIPBytes(data, policy, Limits{})
	if err != nil || got.FileIntegrity != IntegrityPassed || got.DerivedSignature.Status != SignatureValid {
		t.Fatalf("err=%v result=%+v", err, got)
	}
	header := bytes.LastIndex(data, []byte("PK\x06\x06"))
	for _, test := range []struct {
		name string
		edit func([]byte)
		want error
	}{
		{"huge_count", func(b []byte) {
			binary.LittleEndian.PutUint64(b[header+24:], math.MaxUint64)
			binary.LittleEndian.PutUint64(b[header+32:], math.MaxUint64)
		}, ErrLimit},
		{"huge_directory", func(b []byte) { binary.LittleEndian.PutUint64(b[header+40:], math.MaxUint64) }, ErrLimit},
		{"offset_overflow", func(b []byte) { binary.LittleEndian.PutUint64(b[header+48:], math.MaxUint64) }, ErrUnsafe},
		{"record_size", func(b []byte) { binary.LittleEndian.PutUint64(b[header+4:], math.MaxUint64) }, ErrUnsafe},
		{"multi_disk", func(b []byte) { binary.LittleEndian.PutUint32(b[header+16:], 1) }, ErrUnsafe},
		{"locator_overflow", func(b []byte) { binary.LittleEndian.PutUint64(b[header+56+8:], math.MaxUint64) }, ErrUnsafe},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := bytes.Clone(data)
			test.edit(mutated)
			if _, err := verifyZIPBytes(mutated, policy, Limits{}); !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestZIP64LocalOffsetField(t *testing.T) {
	files, _, _, policy := fixture(t)
	original := zipFS(t, files, false)
	central := bytes.Index(original, []byte("PK\x01\x02"))
	nameLen := int(binary.LittleEndian.Uint16(original[central+28:]))
	extraLen := int(binary.LittleEndian.Uint16(original[central+30:]))
	for _, sizes := range []bool{false, true} {
		data := bytes.Clone(original)
		fieldLen := 8
		if sizes {
			fieldLen += 16
		}
		extra := make([]byte, fieldLen+4)
		binary.LittleEndian.PutUint16(extra, 1)
		binary.LittleEndian.PutUint16(extra[2:], uint16(fieldLen))
		position := 4
		if sizes {
			binary.LittleEndian.PutUint64(extra[position:], uint64(binary.LittleEndian.Uint32(data[central+24:])))
			binary.LittleEndian.PutUint64(extra[position+8:], uint64(binary.LittleEndian.Uint32(data[central+20:])))
			binary.LittleEndian.PutUint32(data[central+24:], 0xffffffff)
			binary.LittleEndian.PutUint32(data[central+20:], 0xffffffff)
			position += 16
		}
		binary.LittleEndian.PutUint64(extra[position:], uint64(binary.LittleEndian.Uint32(data[central+42:])))
		binary.LittleEndian.PutUint32(data[central+42:], 0xffffffff)
		binary.LittleEndian.PutUint16(data[central+30:], uint16(extraLen+len(extra)))
		insertAt := central + 46 + nameLen
		data = append(append(bytes.Clone(data[:insertAt]), extra...), data[insertAt:]...)
		end := bytes.LastIndex(data, []byte("PK\x05\x06"))
		binary.LittleEndian.PutUint32(data[end+12:], binary.LittleEndian.Uint32(data[end+12:])+uint32(len(extra)))
		got, err := verifyZIPBytes(data, policy, Limits{})
		if err != nil || got.FileIntegrity != IntegrityPassed || got.DerivedSignature.Status != SignatureValid {
			t.Fatalf("sizes=%v err=%v result=%+v", sizes, err, got)
		}
	}
}

func TestUnindexedLocalFileRejected(t *testing.T) {
	original := zipItems(t, []zipItem{{name: "a", data: []byte("hidden")}, {name: "b", data: []byte("visible")}}, zip.Store, 2026)
	first := bytes.Index(original, []byte("PK\x01\x02"))
	firstSize := 46 + int(binary.LittleEndian.Uint16(original[first+28:])) + int(binary.LittleEndian.Uint16(original[first+30:])) + int(binary.LittleEndian.Uint16(original[first+32:]))
	data := append(bytes.Clone(original[:first]), original[first+firstSize:]...)
	end := bytes.LastIndex(data, []byte("PK\x05\x06"))
	binary.LittleEndian.PutUint16(data[end+8:], 1)
	binary.LittleEndian.PutUint16(data[end+10:], 1)
	binary.LittleEndian.PutUint32(data[end+12:], binary.LittleEndian.Uint32(data[end+12:])-uint32(firstSize))
	if _, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal("test must retain a ZIP accepted by the standard parser", err)
	}
	if _, err := verifyZIPBytes(data, TrustPolicy{}, Limits{}); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
}

func TestDeflateBombBudget(t *testing.T) {
	data := zipItems(t, []zipItem{{name: "bomb", data: make([]byte, 4<<20)}}, zip.Deflate, 2026)
	if len(data) > 16<<10 {
		t.Fatal("fixture did not compress")
	}
	if _, err := verifyZIPBytes(data, TrustPolicy{}, Limits{MaxFileBytes: 1 << 20}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
}

type cancelReaderAt struct {
	r      io.ReaderAt
	cancel context.CancelFunc
	reads  int
}

func (r *cancelReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.r.ReadAt(p, off)
	r.reads++
	if r.reads == 3 {
		r.cancel()
	}
	return n, err
}

func TestZIPCancellationDuringMetadata(t *testing.T) {
	files, _, _, policy := fixture(t)
	data := zipFS(t, files, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &cancelReaderAt{r: bytes.NewReader(data), cancel: cancel}
	got, err := VerifyZIP(ctx, r, int64(len(data)), policy, Limits{})
	if !errors.Is(err, context.Canceled) || got.FileIntegrity == IntegrityPassed || r.reads != 3 {
		t.Fatalf("reads=%d err=%v result=%+v", r.reads, err, got)
	}
}

func TestEOCDInCommentCannotBypassPreflight(t *testing.T) {
	data := zipItems(t, []zipItem{{name: "payload", data: []byte("test")}}, zip.Store, 2026)
	end := bytes.LastIndex(data, []byte("PK\x05\x06"))
	// The standard parser chooses this later fake record despite the remaining
	// comment bytes. A preflight that skips it would inspect a different count.
	comment := make([]byte, 30)
	binary.LittleEndian.PutUint32(comment, 0x06054b50)
	binary.LittleEndian.PutUint16(comment[8:], 60000)
	binary.LittleEndian.PutUint16(comment[10:], 60000)
	data = append(bytes.Clone(data[:end+22]), comment...)
	binary.LittleEndian.PutUint16(data[end+20:], uint16(len(comment)))
	if _, err := verifyZIPBytes(data, TrustPolicy{}, Limits{}); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
}
