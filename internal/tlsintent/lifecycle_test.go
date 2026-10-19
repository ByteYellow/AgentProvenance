package tlsintent

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func lifecycleChunk(epoch uint64, direction string, data []byte) Chunk {
	return Chunk{PID: 7, Conn: 99, ProcessStartNS: 100, Epoch: epoch, Direction: direction, Data: data}
}

func TestLifetimeChangeDropsOldHTTPBuffers(t *testing.T) {
	for _, boundary := range []string{"reset", "missed-reset", "pid-reuse"} {
		t.Run(boundary, func(t *testing.T) {
			r := NewReassembler()
			r.Add(lifecycleChunk(10, Request, []byte("POST /old HTTP/1.1\r\nContent-Length: 10\r\n\r\nold")))
			r.Add(lifecycleChunk(10, Response, []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nold")))
			c := lifecycleChunk(11, Request, []byte("GET /new HTTP/1.1\r\nHost: new.example\r\n\r\n"))
			if boundary == "reset" {
				r.Reset(c)
			} else if boundary == "pid-reuse" {
				c.ProcessStartNS++
				c.Epoch = 1
			}
			got := r.Add(c)
			if len(got) != 1 || got[0].Path != "/new" || got[0].Epoch != c.Epoch || got[0].ProcessStartNS != c.ProcessStartNS {
				t.Fatalf("new lifetime contaminated: %+v", got)
			}
			if tail := r.Flush(c.PID, c.Conn); len(tail) != 0 {
				t.Fatalf("old lifetime emitted under new context: %+v", tail)
			}
			if loss := r.TakeLoss(); loss.Streams != 2 || loss.Bytes == 0 {
				t.Fatalf("discarded partial messages must be reported: %+v", loss)
			}
		})
	}
}

func TestLifetimeChangeResetsHPACKDictionary(t *testing.T) {
	r := NewReassembler()
	var buf bytes.Buffer
	encoder := hpack.NewEncoder(&buf)
	encode := func() []byte {
		buf.Reset()
		for _, f := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/old-private"}, {Name: ":authority", Value: "old.example"}} {
			if err := encoder.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		return append([]byte(nil), buf.Bytes()...)
	}
	first, indexed := encode(), encode()
	if len(indexed) >= len(first) {
		t.Fatal("fixture must reuse the dynamic dictionary")
	}
	frame := func(header []byte) []byte {
		return append([]byte(h2ClientPreface), h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, header)...)
	}
	if got := r.Add(lifecycleChunk(10, Request, frame(first))); len(got) != 1 || got[0].Host != "old.example" {
		t.Fatalf("initial connection failed: %+v", got)
	}
	// No lifecycle event: the generation on the data must still isolate HPACK.
	if got := r.Add(lifecycleChunk(11, Request, frame(indexed))); len(got) != 0 {
		t.Fatalf("new connection decoded a prior connection's dynamic index: %+v", got)
	}
	if loss := r.TakeLoss(); loss.Streams == 0 {
		t.Fatal("undecodable header block must report a gap")
	}
	header := hpackEncode([2]string{":method", "GET"}, [2]string{":path", "/new"}, [2]string{":authority", "new.example"})
	if got := r.Add(lifecycleChunk(12, Request, frame(header))); len(got) != 1 || got[0].Host != "new.example" {
		t.Fatalf("next lifetime did not reset the failed decoder: %+v", got)
	}
	if got := r.Add(lifecycleChunk(13, Request, []byte("GET /h1 HTTP/1.1\r\n\r\n"))); len(got) != 1 || got[0].Protocol != ProtoHTTP11 {
		t.Fatalf("old HTTP/2 detection leaked into HTTP/1: %+v", got)
	}
}

func TestSameLifetimePreservesHPACKAndMultiplexedStreams(t *testing.T) {
	r := NewReassembler()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	header := func() []byte {
		buf.Reset()
		for _, f := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":path", Value: "/shared-path"}, {Name: ":authority", Value: "shared.example"}} {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		return append([]byte(nil), buf.Bytes()...)
	}
	r.Add(lifecycleChunk(10, Request, append([]byte(h2ClientPreface), h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, header())...)))
	r.Add(lifecycleChunk(10, Request, h2Frame(h2FrameHeaders, h2FlagEndHeaders, 3, header())))
	// A boundary record can arrive after chunks on another CPU. Same epoch is
	// idempotent and must not destroy either pending stream.
	r.Reset(lifecycleChunk(10, "", nil))
	for _, id := range []uint32{3, 1} {
		got := r.Add(lifecycleChunk(10, Request, h2Frame(h2FrameData, h2FlagEndStream, id, []byte("body"))))
		if len(got) != 1 || got[0].StreamID != id || got[0].Host != "shared.example" || string(got[0].Body) != "body" || got[0].Epoch != 10 {
			t.Fatalf("same-connection multiplexing regressed: %+v", got)
		}
	}
	if loss := r.TakeLoss(); loss != (CaptureLoss{}) {
		t.Fatalf("normal multiplexing reported a gap: %+v", loss)
	}
}

func TestStaleTLSLifecycleCannotResetNewConnection(t *testing.T) {
	r := NewReassembler()
	r.Add(lifecycleChunk(11, Response, []byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nnew")))
	r.Reset(lifecycleChunk(10, "", nil))
	if got := r.Release(lifecycleChunk(10, "", nil)); len(got) != 0 {
		t.Fatalf("old release flushed the new connection: %+v", got)
	}
	if got := r.Add(lifecycleChunk(10, Response, []byte("old"))); len(got) != 0 {
		t.Fatalf("late read was accepted: %+v", got)
	}
	if got := r.EndProcess(7, 99, false); len(got) != 0 {
		t.Fatal("exit from a reused PID flushed the current process")
	}
	got := r.Add(lifecycleChunk(11, Response, []byte("end")))
	if len(got) != 1 || string(got[0].Body) != "newend" {
		t.Fatalf("new generation lost after stale event: %+v", got)
	}
	r.Release(lifecycleChunk(11, "", nil))
	if got := r.Add(lifecycleChunk(11, Request, []byte("GET /late HTTP/1.1\r\n\r\n"))); len(got) != 0 {
		t.Fatal("late data resurrected a released generation")
	}
	if got := r.Add(lifecycleChunk(12, Request, []byte("GET /alive HTTP/1.1\r\n\r\n"))); len(got) != 1 {
		t.Fatalf("live object reused after a reference release failed: %+v", got)
	}
}

func TestRequestDoesNotTruncatePipelinedResponse(t *testing.T) {
	r := NewReassembler()
	r.Add(lifecycleChunk(10, Response, []byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc")))
	got := r.Add(lifecycleChunk(10, Request, []byte("GET /next HTTP/1.1\r\n\r\n")))
	if len(got) != 1 || got[0].Direction != Request {
		t.Fatalf("request incorrectly terminated response: %+v", got)
	}
	got = r.Add(lifecycleChunk(10, Response, []byte("def")))
	if len(got) != 1 || string(got[0].Body) != "abcdef" || got[0].Truncated {
		t.Fatalf("pipelined response corrupted: %+v", got)
	}
}

func TestLifecycleCacheBoundedAndExecClearsUnknownEpoch(t *testing.T) {
	r := NewReassembler()
	r.MaxStreams = 2
	for i := uint64(1); i <= 1000; i++ {
		r.Release(Chunk{PID: 7, Conn: i, ProcessStartNS: 100, Epoch: i})
	}
	if len(r.connections) > 4 || len(r.streams) != 0 || len(r.h2Conns) != 0 {
		t.Fatalf("unbounded lifetime metadata: %d/%d/%d", len(r.connections), len(r.streams), len(r.h2Conns))
	}
	c := lifecycleChunk(0, Request, []byte("GET /old"))
	r.Add(c)
	r.EndProcess(c.PID, c.ProcessStartNS, true)
	c.Data = []byte("GET /new HTTP/1.1\r\n\r\n")
	if got := r.Add(c); len(got) != 1 || got[0].Path != "/new" {
		t.Fatalf("exec kept old bytes for a producer without epochs: %+v", got)
	}
}
