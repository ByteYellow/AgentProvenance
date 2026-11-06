package tlsintent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// Decode the producer fields so these counterexamples also run against the
// pre-sequence consumer, which silently ignores Position.
func positionedChunk(t *testing.T, stream, call uint64, offset, total int, data []byte) Chunk {
	t.Helper()
	c := lifecycleChunk(10, Request, data)
	b, err := json.Marshal(map[string]any{"Position": map[string]any{
		"stream_id": strconv.FormatUint(stream, 10), "call_sequence": strconv.FormatUint(call, 10), "offset": offset, "total_bytes": total,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTLSSequenceMissingTailCannotConsumeNextCall(t *testing.T) {
	r := NewReassembler()
	prefix := []byte("POST /first HTTP/1.1\r\nContent-Length: 6\r\n\r\nabc")
	r.Add(positionedChunk(t, 100, 1, 0, len(prefix)+3, prefix))
	next := []byte("GET /next HTTP/1.1\r\n\r\n")
	got := r.Add(positionedChunk(t, 100, 2, 0, len(next), next))
	if len(got) == 0 {
		t.Fatal("missing call tail was not reported")
	}
	for _, m := range got {
		if !m.Truncated || m.Method != "" || bytes.Contains(m.Body, []byte("abcGET")) {
			t.Fatalf("missing call tail borrowed subsequent plaintext: %+v", m)
		}
	}
}

func TestTLSSequenceEntireCallLossInvalidatesHPACK(t *testing.T) {
	r := NewReassembler()
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	encode := func(host string, id uint32) []byte {
		b.Reset()
		for _, f := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: host}} {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		return h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, id, append([]byte(nil), b.Bytes()...))
	}
	first := append([]byte(h2ClientPreface), encode("old.example", 1)...)
	if got := r.Add(positionedChunk(t, 100, 1, 0, len(first), first)); len(got) != 1 || got[0].Host != "old.example" {
		t.Fatalf("healthy first call: %+v", got)
	}
	encode("new.example", 3) // An entire TLS call is absent from capture.
	next := encode("new.example", 5)
	got := r.Add(positionedChunk(t, 100, 3, 0, len(next), next))
	if len(got) == 0 {
		t.Fatal("whole-call loss was not reported")
	}
	for _, m := range got {
		if !m.Truncated || m.Host != "" || m.Method != "" {
			t.Fatalf("missing HPACK update reused stale table: %+v", m)
		}
	}
}

func TestTLSSequenceMissingFirstCallIsNotFreshHTTP(t *testing.T) {
	r := NewReassembler()
	data := []byte("GET /may-be-body-text HTTP/1.1\r\n\r\n")
	got := r.Add(positionedChunk(t, 100, 2, 0, len(data), data))
	if len(got) != 1 || !got[0].Truncated || got[0].Method != "" {
		t.Fatalf("first observed call was mistaken for stream start: %+v", got)
	}
}

func TestTLSSequenceAggregatesFragmentsPerCall(t *testing.T) {
	r := NewReassembler()
	data := bytes.Repeat([]byte{'x'}, 4096)
	var got []Message
	// Call 1 was lost. The 16 surviving chunks belong to one contiguous call.
	for offset := 0; offset < len(data); offset += 256 {
		got = append(got, r.Add(positionedChunk(t, 100, 2, offset, len(data), data[offset:offset+256]))...)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Body, data) || !got[0].Truncated {
		t.Fatalf("want one retained call fragment, got %d messages", len(got))
	}
}

func TestTLSSequenceHealthyCallsAndDuplicates(t *testing.T) {
	r := NewReassembler()
	body := bytes.Repeat([]byte("x"), 9000)
	data := append([]byte(fmt.Sprintf("POST /large HTTP/1.1\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	var got []Message
	for base, call := 0, uint64(1); base < len(data); call++ {
		total := min(3000, len(data)-base)
		for off := 0; off < total; off += 256 {
			c := positionedChunk(t, 100, call, off, total, data[base+off:base+min(off+256, total)])
			got = append(got, r.Add(c)...)
			got = append(got, r.Add(c)...)
		}
		base += total
	}
	if len(got) != 1 || got[0].Truncated || !bytes.Equal(got[0].Body, body) || r.TakeLoss() != (CaptureLoss{}) {
		t.Fatalf("healthy multi-call HTTP or duplicate delivery changed: %+v", got)
	}
}

func TestTLSSequenceMissingMiddlePreservesSeparateByteRanges(t *testing.T) {
	r := NewReassembler()
	r.Add(positionedChunk(t, 100, 1, 0, 9, []byte("abc")))
	got := r.Add(positionedChunk(t, 100, 1, 6, 9, []byte("ghi")))
	if len(got) != 2 || string(got[0].Body) != "abc" || string(got[1].Body) != "ghi" ||
		got[0].Position.Offset != 0 || got[1].Position.Offset != 6 {
		t.Fatalf("non-contiguous ranges were joined or lost: %+v", got)
	}
	late := r.Add(positionedChunk(t, 100, 1, 3, 9, []byte("def")))
	if len(late) != 1 || string(late[0].Body) != "def" || late[0].Position.Offset != 3 || !late[0].Truncated {
		t.Fatalf("late fragment lost its original position: %+v", late)
	}
}

func TestTLSSequenceOutOfOrderRetainsFragmentsWithoutParsing(t *testing.T) {
	r := NewReassembler()
	data := []byte("GET /ordered HTTP/1.1\r\n\r\n")
	var got []Message
	got = append(got, r.Add(positionedChunk(t, 100, 1, 8, len(data), data[8:]))...)
	got = append(got, r.Add(positionedChunk(t, 100, 1, 0, len(data), data[:8]))...)
	if len(got) != 2 || got[0].Position.Offset != 8 || got[1].Position.Offset != 0 {
		t.Fatalf("out-of-order fragments not retained: %+v", got)
	}
	for _, m := range got {
		if m.Method != "" || !m.Truncated || m.CaptureGap != GapChunkSequence {
			t.Fatalf("out-of-order bytes parsed as HTTP: %+v", m)
		}
	}
}

func TestTLSSequenceCheckpointFindsLostFinalCall(t *testing.T) {
	for _, mode := range []string{"healthy", "tail", "whole", "unseen"} {
		t.Run(mode, func(t *testing.T) {
			r := NewReassembler()
			data := []byte("GET /first HTTP/1.1\r\n\r\n")
			if mode != "unseen" {
				r.Add(positionedChunk(t, 100, 1, 0, len(data), data))
			}
			call := uint64(1)
			if mode == "tail" || mode == "whole" {
				call = 2
			}
			if mode == "tail" {
				r.Add(positionedChunk(t, 100, call, 0, 10, []byte("prefix")))
			}
			c := positionedChunk(t, 100, call, 0, 0, nil)
			c.Checkpoint = true
			got := r.Add(c)
			if mode == "healthy" {
				if len(got) != 0 || r.TakeLoss() != (CaptureLoss{}) {
					t.Fatalf("healthy close became a gap: %+v", got)
				}
			} else if len(got) != 1 || !got[0].Truncated || got[0].Position.CallSequence != call || r.TakeLoss().Streams != 1 {
				t.Fatalf("final call loss not reported: %+v", got)
			}
			if got := r.Add(c); len(got) != 0 {
				t.Fatalf("duplicate checkpoint re-emitted loss: %+v", got)
			}
			if got := r.Release(c); len(got) != 0 {
				t.Fatalf("release duplicated checkpoint fragments: %+v", got)
			}
		})
	}
}

func TestTLSSequenceEvictionAndEpochRecovery(t *testing.T) {
	r := NewReassembler()
	data := []byte("GET /ok HTTP/1.1\r\n\r\n")
	r.Add(positionedChunk(t, 100, 1, 0, len(data), data))
	got := r.Add(positionedChunk(t, 200, 1, 0, len(data), data))
	if len(got) != 1 || got[0].CaptureGap != GapSequenceReset || got[0].Method != "" {
		t.Fatalf("sequence map eviction silently reset parser: %+v", got)
	}
	if got := r.Add(positionedChunk(t, 100, 2, 0, len(data), data)); len(got) != 0 {
		t.Fatalf("stale map generation resurrected: %+v", got)
	}
	c := positionedChunk(t, 300, 1, 0, len(data), data)
	c.Epoch++
	got = r.Add(c)
	if len(got) != 1 || got[0].Path != "/ok" || got[0].Truncated {
		t.Fatalf("explicit new TLS epoch did not recover: %+v", got)
	}
}

func TestTLSSequenceCloseAndBudgets(t *testing.T) {
	r := NewReassembler()
	r.MaxBytes = 32
	data := bytes.Repeat([]byte{'x'}, 200)
	var got []Message
	for off := 0; off < len(data); off += 20 {
		got = append(got, r.Add(positionedChunk(t, 100, 1, off, len(data), data[off:off+20]))...)
		if s := r.streams[streamKey{7, 99, Request}]; len(s.capture.pending) > r.MaxBytes || s.buf.Len() > r.MaxBytes {
			t.Fatal("capture assembly exceeded configured budget")
		}
	}
	var retained []byte
	for _, m := range got {
		if !m.Truncated || m.CaptureGap != GapBufferLimit {
			t.Fatalf("budget gap not preserved: %+v", m)
		}
		retained = append(retained, m.Body...)
	}
	if !bytes.Equal(retained, data) {
		t.Fatal("budget splitting lost retained bytes")
	}
	r = NewReassembler()
	r.Add(positionedChunk(t, 100, 1, 0, 100, []byte("pending")))
	got = r.Flush(7, 99)
	if len(got) != 1 || string(got[0].Body) != "pending" || got[0].CaptureGap != GapChunkSequence {
		t.Fatalf("close lost pending call: %+v", got)
	}
}

func TestTLSSequenceDirectionsAndProcessReuseAreIndependent(t *testing.T) {
	r := NewReassembler()
	data := []byte("GET /fresh HTTP/1.1\r\n\r\n")
	r.Add(positionedChunk(t, 100, 3, 0, len(data), data))
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	c := positionedChunk(t, 200, 1, 0, len(response), response)
	c.Direction = Response
	got := r.Add(c)
	if len(got) != 1 || got[0].Status != 200 || got[0].Truncated {
		t.Fatalf("other direction was invalidated: %+v", got)
	}
	c = positionedChunk(t, 300, 1, 0, len(data), data)
	c.ProcessStartNS++
	got = r.Add(c)
	if len(got) != 1 || got[0].Path != "/fresh" || got[0].Truncated {
		t.Fatalf("new process inherited old gaps: %+v", got)
	}
}

func TestTLSSequenceDelayedCheckpointDoesNotFlushCurrentCall(t *testing.T) {
	r := NewReassembler()
	data := []byte("GET /ok HTTP/1.1\r\n\r\n")
	r.Add(positionedChunk(t, 100, 1, 0, len(data), data))
	r.Add(positionedChunk(t, 100, 2, 0, len(data), data[:8]))
	c := positionedChunk(t, 100, 1, 0, 0, nil)
	c.Checkpoint = true
	if got := r.Add(c); len(got) != 0 {
		t.Fatalf("older watermark invalidated newer pending call: %+v", got)
	}
	got := r.Add(positionedChunk(t, 100, 2, 8, len(data), data[8:]))
	if len(got) != 1 || got[0].Path != "/ok" || got[0].Truncated {
		t.Fatalf("newer call corrupted: %+v", got)
	}
}

func TestTLSSequenceCannotMixUnnumberedChunks(t *testing.T) {
	for _, sequencedFirst := range []bool{true, false} {
		r := NewReassembler()
		prefix := []byte("POST /partial HTTP/1.1\r\nContent-Length: 6\r\n\r\nabc")
		first := lifecycleChunk(10, Request, prefix)
		last := positionedChunk(t, 100, 1, 0, 3, []byte("def"))
		if sequencedFirst {
			first = positionedChunk(t, 100, 1, 0, len(prefix), prefix)
			last = lifecycleChunk(10, Request, []byte("def"))
		}
		r.Add(first)
		got := r.Add(last)
		if len(got) == 0 {
			t.Fatal("missing sequence contract was not reported")
		}
		for _, m := range got {
			if m.Method != "" || !m.Truncated || bytes.Contains(m.Body, []byte("abcdef")) {
				t.Fatalf("mixed producer contracts assembled an HTTP body: %+v", m)
			}
		}
	}
}

func TestTLSSequenceRejectsInvalidPositions(t *testing.T) {
	for _, p := range []ChunkPosition{
		{StreamID: 0, CallSequence: 1, TotalBytes: 32},
		{StreamID: 1, CallSequence: 0, TotalBytes: 32},
		{StreamID: 1, CallSequence: 1, Offset: ^uint32(0), TotalBytes: 32},
		{StreamID: 1, CallSequence: 1, TotalBytes: ^uint32(0)},
	} {
		r := NewReassembler()
		c := lifecycleChunk(10, Request, []byte("GET /fake HTTP/1.1\r\n\r\n"))
		c.Position = &p
		got := r.Add(c)
		if len(got) != 1 || got[0].Method != "" || got[0].CaptureGap != GapChunkMetadata {
			t.Fatalf("invalid producer position parsed: %+v", got)
		}
	}
}

func BenchmarkTLSSequenceFragments(b *testing.B) {
	data := bytes.Repeat([]byte{'x'}, CallCaptureLimit)
	c := lifecycleChunk(10, Request, nil)
	c.Position = &ChunkPosition{StreamID: 100, TotalBytes: CallCaptureLimit}
	r := NewReassembler()
	b.ReportAllocs()
	b.SetBytes(CallCaptureLimit)
	for i := 0; i < b.N; i++ {
		c.Position.CallSequence = uint64(i) + 2
		for off := 0; off < len(data); off += 256 {
			c.Position.Offset = uint32(off)
			c.Data = data[off : off+256]
			got := r.Add(c)
			if (off == len(data)-256 && len(got) != 1) || (off != len(data)-256 && len(got) != 0) {
				b.Fatalf("fragment amplification: off=%d messages=%d", off, len(got))
			}
		}
	}
}

func BenchmarkTLSUnsequencedFragments(b *testing.B) {
	data := bytes.Repeat([]byte{'x'}, CallCaptureLimit)
	c := lifecycleChunk(10, Request, nil)
	c.Truncated = true
	r := NewReassembler()
	r.Add(c)
	c.Truncated = false
	b.ReportAllocs()
	b.SetBytes(CallCaptureLimit)
	for i := 0; i < b.N; i++ {
		for off := 0; off < len(data); off += 256 {
			c.Data = data[off : off+256]
			if got := r.Add(c); len(got) != 1 {
				b.Fatalf("legacy per-chunk fragment: messages=%d", len(got))
			}
		}
	}
}
