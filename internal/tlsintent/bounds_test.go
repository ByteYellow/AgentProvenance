package tlsintent

import (
	"bytes"
	"testing"
)

func TestReassemblerBoundsConnectionsAndReleasesOnExit(t *testing.T) {
	r := NewReassembler()
	r.MaxStreams = 4
	for pid := uint32(1); pid <= 100; pid++ {
		r.Add(Chunk{PID: pid, Conn: 1, Direction: Request, Data: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")})
		if len(r.streams) > 4 || len(r.h2Conns) > 4 {
			t.Fatal("connection state grew beyond cap")
		}
	}
	if loss := r.TakeLoss(); loss.Streams != 96 {
		t.Fatalf("evictions=%+v", loss)
	}
	for pid := uint32(97); pid <= 100; pid++ {
		r.FlushPID(pid)
	}
	if len(r.streams) != 0 {
		t.Fatalf("empty HTTP1 buffers leaked after process exit: %d", len(r.streams))
	}
}

func TestReassemblerCapsSingleOversizedChunkExactly(t *testing.T) {
	r := NewReassembler()
	r.MaxBytes = 128
	r.Add(Chunk{PID: 1, Conn: 1, Direction: Response, Data: bytes.Repeat([]byte("x"), 10000)})
	if got := r.streams[streamKey{1, 1, Response}].buf.Len(); got != 128 {
		t.Fatalf("oversized chunk bypassed cap: %d", got)
	}
	loss := r.TakeLoss()
	if loss.Bytes != 10000-128 || loss.Streams != 1 {
		t.Fatalf("loss=%+v", loss)
	}
}

func TestHTTP2BoundsAggregatePendingBodiesAndStreamCount(t *testing.T) {
	r := NewReassembler()
	r.MaxBytes = 512
	r.Add(Chunk{PID: 1, Conn: 1, Direction: Request, Data: []byte(h2ClientPreface)})
	for i := uint32(1); i < 100; i += 2 {
		hdr := hpackEncode([2]string{":method", "POST"}, [2]string{":path", "/"})
		data := append(h2Frame(h2FrameHeaders, h2FlagEndHeaders, i, hdr), h2Frame(h2FrameData, 0, i, bytes.Repeat([]byte("x"), 100))...)
		r.Add(Chunk{PID: 1, Conn: 1, Direction: Request, Data: data})
	}
	parser := r.streams[streamKey{1, 1, Request}].h2
	if !parser.failed || parser.retainedBytes() > 512 {
		t.Fatalf("HTTP2 bodies escaped aggregate cap: bytes=%d failed=%v", parser.retainedBytes(), parser.failed)
	}
	if loss := r.TakeLoss(); loss.Streams == 0 || loss.Bytes == 0 {
		t.Fatalf("silent HTTP2 eviction: %+v", loss)
	}

	p := newH2Parser(Response)
	for i := uint32(1); i < 500; i++ {
		p.consume(h2Frame(h2FrameData, 0, i, nil), 1, 1)
	}
	if !p.failed || len(p.streams) > 128 {
		t.Fatalf("empty HTTP2 streams grew without bound: %d", len(p.streams))
	}
}

func TestHTTP2HealthyPersistentConnectionExceedsLifetimeBudget(t *testing.T) {
	r := NewReassembler()
	r.MaxBytes = 512
	r.Add(Chunk{PID: 1, Conn: 1, Direction: Request, Data: []byte(h2ClientPreface)})
	for i := uint32(1); i <= 1000; i += 2 {
		hdr := hpackEncode([2]string{":method", "POST"}, [2]string{":path", "/"})
		data := append(h2Frame(h2FrameHeaders, h2FlagEndHeaders, i, hdr), h2Frame(h2FrameData, h2FlagEndStream, i, bytes.Repeat([]byte("x"), 100))...)
		if msgs := r.Add(Chunk{PID: 1, Conn: 1, Direction: Request, Data: data}); len(msgs) != 1 {
			t.Fatalf("healthy persistent connection was limited by lifetime bytes at stream %d", i)
		}
	}
	if loss := r.TakeLoss(); loss != (CaptureLoss{}) {
		t.Fatalf("healthy persistent connection lost data: %+v", loss)
	}
}

func TestHTTP2HPACKExpansionAndOversizedFrameAreBounded(t *testing.T) {
	p := newH2Parser(Response)
	p.maxBytes = 256
	large := hpackEncode([2]string{":status", "200"}, [2]string{"x-long", string(bytes.Repeat([]byte("a"), 400))})
	p.consume(h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, large), 1, 1)
	if !p.failed {
		t.Fatal("HPACK expanded past memory budget")
	}
	p = newH2Parser(Response)
	p.maxBytes = 256
	frame := h2Frame(h2FrameData, 0, 1, bytes.Repeat([]byte("x"), 257))
	p.consume(frame[:9], 1, 1)
	if !p.failed {
		t.Fatal("oversized frame length waited for unbounded data")
	}
}

func TestChunkedLengthOverflowCannotCrashCollector(t *testing.T) {
	for _, size := range []string{"7fffffffffffffff", "7ffffffffffffff0", "8000000000000000"} {
		if _, _, ok := dechunk([]byte(size + "\r\nx\r\n")); ok {
			t.Fatalf("impossible chunk size accepted: %s", size)
		}
	}
}

func TestHTTP2CaptureTruncationIsVisibleWithoutCompleteMessage(t *testing.T) {
	r := NewReassembler()
	r.Add(Chunk{PID: 1, Conn: 1, Direction: Request, Data: []byte(h2ClientPreface), Truncated: true})
	if loss := r.TakeLoss(); loss.Streams != 1 {
		t.Fatalf("missing capture gap: %+v", loss)
	}
	hdr := hpackEncode([2]string{":method", "GET"}, [2]string{":path", "/"})
	msgs := r.Add(Chunk{PID: 1, Conn: 1, Direction: Request, Data: h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, hdr)})
	if len(msgs) != 1 || !msgs[0].Truncated {
		t.Fatalf("incomplete capture reported complete: %+v", msgs)
	}
}
