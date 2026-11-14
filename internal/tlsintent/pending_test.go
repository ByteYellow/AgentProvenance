package tlsintent

import "testing"

func TestPendingKeepsTLSFramingIntact(t *testing.T) {
	r := NewReassembler()
	first := []byte("POST /chat HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nab")
	chunk := Chunk{PID: 10, Conn: 20, Direction: Request, Data: first}
	if got := r.Add(chunk); len(got) != 0 {
		t.Fatalf("partial request emitted: %+v", got)
	}
	streams, bytes := r.Pending()
	if streams != 1 || bytes == 0 {
		t.Fatalf("buffered request absent: streams=%d bytes=%d", streams, bytes)
	}
	if nextStreams, nextBytes := r.Pending(); nextStreams != streams || nextBytes != bytes {
		t.Fatal("inspection changed retained TLS bytes")
	}
	chunk.Data = []byte("cd")
	got := r.Add(chunk)
	if len(got) != 1 || string(got[0].Body) != "abcd" || got[0].CaptureGap != "" || got[0].Truncated {
		t.Fatalf("checkpoint inspection changed reassembly: %+v", got)
	}
	if streams, bytes := r.Pending(); streams != 0 || bytes != 0 {
		t.Fatalf("empty keep-alive connection counted as pending: %d %d", streams, bytes)
	}
}
