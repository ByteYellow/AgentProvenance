package agentcontext

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
)

func transcriptReader(r io.Reader, path string) (io.Reader, func(), error) {
	buffer := bufio.NewReader(r)
	header, _ := buffer.Peek(4)
	compressed := strings.HasSuffix(path, ".zstd") || strings.HasSuffix(path, ".zst") || bytes.Equal(header, []byte{0x28, 0xb5, 0x2f, 0xfd})
	if !compressed {
		return buffer, func() {}, nil
	}
	decoder, err := zstd.NewReader(buffer, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxMemory(64<<20), zstd.WithDecoderMaxWindow(64<<20))
	if err != nil {
		return nil, func() {}, err
	}
	return decoder, decoder.Close, nil
}
