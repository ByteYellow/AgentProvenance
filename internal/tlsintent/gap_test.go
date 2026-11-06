package tlsintent

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestHTTP1CaptureGapCannotConsumeNextRequest(t *testing.T) {
	r := NewReassembler()
	c := lifecycleChunk(10, Request, []byte("POST /first HTTP/1.1\r\nContent-Length: 6\r\n\r\nabc"))
	c.Truncated = true
	r.Add(c)
	c.Truncated = false
	c.Data = []byte("GET /next HTTP/1.1\r\nHost: next.example\r\n\r\n")
	for _, m := range r.Add(c) {
		if !m.Truncated || m.Method != "" || m.Path != "" || m.Host != "" || bytes.Contains(m.Body, []byte("abcGET")) {
			t.Fatalf("bytes after a capture gap became an HTTP message: %+v", m)
		}
	}
	c.Epoch++
	got := r.Add(c)
	if len(got) != 1 || got[0].Path != "/next" || got[0].Truncated {
		t.Fatalf("new capture generation did not recover: %+v", got)
	}
}

func TestCaptureGapKeepsCompleteMessagesBeforeMissingBytes(t *testing.T) {
	r := NewReassembler()
	c := lifecycleChunk(10, Request, []byte("GET /complete HTTP/1.1\r\n\r\nPOST /partial HTTP/1.1\r\nContent-Length: 20\r\n\r\nprefix"))
	c.Truncated = true
	var found bool
	for _, m := range r.Add(c) {
		if m.Path == "/complete" {
			found = true
			if m.Truncated {
				t.Fatal("a later gap invalidated a complete preceding message")
			}
		}
	}
	if !found {
		t.Fatal("complete message before the gap was discarded")
	}
}

func TestHTTP2CaptureGapCannotReuseStaleDynamicIndex(t *testing.T) {
	r := NewReassembler()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	encode := func(host string) []byte {
		buf.Reset()
		for _, f := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: host}} {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		return append([]byte(nil), buf.Bytes()...)
	}
	first := append([]byte(h2ClientPreface), h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, encode("old.example"))...)
	if got := r.Add(lifecycleChunk(10, Request, first)); len(got) != 1 || got[0].Host != "old.example" {
		t.Fatalf("initial HTTP/2 message failed: %+v", got)
	}
	encode("new.example") // The peer received this table update; the sensor did not.
	gap := lifecycleChunk(10, Request, nil)
	gap.Truncated = true
	r.Add(gap)
	indexed := h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 5, encode("new.example"))
	for _, m := range r.Add(lifecycleChunk(10, Request, indexed)) {
		if !m.Truncated || m.Host != "" || m.Method != "" || m.StreamID != 0 {
			t.Fatalf("unknown HPACK state yielded a decoded message: %+v", m)
		}
	}
}

func TestHTTP2InterruptedHeaderBlockFailsBeforeDecodingNextStream(t *testing.T) {
	r := NewReassembler()
	header := hpackEncode([2]string{":method", "GET"}, [2]string{":path", "/first"})
	first := append([]byte(h2ClientPreface), h2Frame(h2FrameHeaders, 0, 1, header[:1])...)
	r.Add(lifecycleChunk(10, Request, first))
	next := h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 3, hpackEncode([2]string{":method", "GET"}, [2]string{":path", "/next"}))
	for _, m := range r.Add(lifecycleChunk(10, Request, next)) {
		if m.Method != "" || m.Path != "" || !m.Truncated {
			t.Fatalf("interleaved header block accepted after missing CONTINUATION: %+v", m)
		}
	}
}

func TestCaptureLimitBoundaryAndHealthyKeepalive(t *testing.T) {
	for _, bodySize := range []int{0, 4000, 4096, 8192} {
		t.Run(fmt.Sprint(bodySize), func(t *testing.T) {
			r := NewReassembler()
			body := bytes.Repeat([]byte("x"), bodySize)
			data := append([]byte(fmt.Sprintf("POST /body HTTP/1.1\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
			var all []Message
			// Several complete TLS calls can carry one HTTP message larger than 4 KiB.
			for start := 0; start < len(data); start += 256 {
				end := min(start+256, len(data))
				all = append(all, r.Add(lifecycleChunk(10, Request, data[start:end]))...)
			}
			if len(all) != 1 || all[0].Truncated || !bytes.Equal(all[0].Body, body) {
				t.Fatalf("complete large message changed: %+v", all)
			}
			for i := 0; i < 5; i++ {
				got := r.Add(lifecycleChunk(10, Request, []byte("GET /next HTTP/1.1\r\n\r\n")))
				if len(got) != 1 || got[0].Path != "/next" || got[0].Truncated {
					t.Fatalf("healthy keepalive changed: %+v", got)
				}
			}
		})
	}
}

func TestCaptureGapPreservesPrefixAndLaterBinaryChunks(t *testing.T) {
	r := NewReassembler()
	prefix := []byte("POST /partial HTTP/1.1\r\nContent-Length: 10\r\n\r\nfirst")
	c := lifecycleChunk(10, Request, prefix)
	c.Truncated = true
	got := r.Add(c)
	if len(got) != 1 || !bytes.Equal(got[0].Body, prefix) || got[0].CaptureGap != GapCaptureLimit || got[0].DataKind != DataTLSFragment {
		t.Fatalf("pre-gap bytes not preserved: %+v", got)
	}
	tail := []byte{0xff, 0, 0x01, 0xc0}
	got = r.Add(lifecycleChunk(10, Request, tail))
	if len(got) != 1 || !bytes.Equal(got[0].Body, tail) || !got[0].Truncated || got[0].Method != "" {
		t.Fatalf("post-gap bytes not preserved independently: %+v", got)
	}
	if got := r.Flush(7, 99); len(got) != 0 {
		t.Fatalf("already emitted fragments repeated on close: %+v", got)
	}
}

func TestHTTP2CaptureGapPreservesOtherDirectionAndNewEpoch(t *testing.T) {
	r := NewReassembler()
	header := hpackEncode([2]string{":method", "GET"}, [2]string{":path", "/"})
	r.Add(lifecycleChunk(10, Request, append([]byte(h2ClientPreface), h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, header)...)))
	gap := lifecycleChunk(10, Request, nil)
	gap.Truncated = true
	r.Add(gap)
	response := h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, hpackEncode([2]string{":status", "200"}))
	got := r.Add(lifecycleChunk(10, Response, response))
	if len(got) != 1 || got[0].Truncated || got[0].Status != 200 {
		t.Fatalf("unaffected direction lost its independent HPACK context: %+v", got)
	}
	next := append([]byte(h2ClientPreface), h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, header)...)
	got = r.Add(lifecycleChunk(11, Request, next))
	if len(got) != 1 || got[0].Truncated || got[0].Method != "GET" {
		t.Fatalf("new HTTP/2 generation did not recover: %+v", got)
	}
}

func TestEvictedDirectionCannotResumeAsComplete(t *testing.T) {
	r := NewReassembler()
	r.MaxStreams = 1
	r.Add(lifecycleChunk(10, Request, []byte("POST /old HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc")))
	other := lifecycleChunk(10, Request, []byte("GET /other HTTP/1.1\r\n\r\n"))
	other.Conn++
	r.Add(other)
	got := r.Add(lifecycleChunk(10, Request, []byte("GET /body-text HTTP/1.1\r\n\r\n")))
	if len(got) != 1 || got[0].Method != "" || !got[0].Truncated || got[0].CaptureGap != GapStreamLimit {
		t.Fatalf("evicted direction resumed at an invented boundary: %+v", got)
	}
}
