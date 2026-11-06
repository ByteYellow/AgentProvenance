package tlsintent

import "sort"

const CaptureRule = "agentprov.tls_reassembly/v2"

type CaptureIntegrity struct {
	Rule     string `json:"rule"`
	State    string `json:"state"`
	Reason   string `json:"reason"`
	DataKind string `json:"data_kind"`
}

func (c *CaptureIntegrity) Incomplete() bool {
	return c != nil && (c.State != "complete" || c.Reason != "" || (c.DataKind != "" && c.DataKind != DataHTTPBody))
}

const (
	GapCaptureLimit = "capture_limit"
	GapBufferLimit  = "reassembly_limit"
	GapHTTP2Frames  = "http2_frame_sequence"
	GapHTTP2Push    = "unsupported_header_frame"
	GapHPACK        = "hpack_decode_failed"
	GapStreamLimit  = "connection_state_evicted"
	DataHTTPBody    = "http_body"
	DataTLSFragment = "tls_fragment"
	DataHPACK       = "hpack_fragment"
	DataHTTP2Body   = "http2_data_fragment"
)

func (r *Reassembler) connectionGap(c Chunk) string {
	if state := r.connections[connKey{c.PID, c.Conn}]; state != nil {
		return state.gaps[c.Direction]
	}
	return ""
}

func (r *Reassembler) markGap(c Chunk, s *stream, reason string) {
	s.gap = reason
	if state := r.connections[connKey{c.PID, c.Conn}]; state != nil {
		if state.gaps == nil {
			state.gaps = map[string]string{}
		}
		state.gaps[c.Direction] = reason
	}
}

// Unknown framing cannot be recovered by finding an HTTP-looking substring:
// that substring may be body content. Keep subsequent bytes as fragments until
// an explicit newer capture generation supplies a fresh parsing context.
func (r *Reassembler) fragment(c Chunk, data []byte, reason, kind string) []Message {
	if len(data) > r.byteLimit() {
		data = data[:r.byteLimit()]
	}
	protocol := ""
	if _, known := r.h2Conns[connKey{c.PID, c.Conn}]; known {
		protocol = ProtoH2
	}
	return []Message{{PID: c.PID, Conn: c.Conn, Direction: c.Direction, Protocol: protocol,
		Body: append([]byte(nil), data...), Truncated: true, CaptureGap: reason, DataKind: kind}}
}

// Preserve retained bodies, unfinished HPACK blocks and frame bytes separately;
// concatenating these buffers would manufacture a byte order across streams.
func (p *h2Parser) drainGap(pid uint32, conn uint64, reason string) []Message {
	var out []Message
	ids := make([]uint32, 0, len(p.streams))
	for id := range p.streams {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	fragment := func(id uint32, data []byte, kind string) {
		out = append(out, Message{PID: pid, Conn: conn, Direction: p.direction, Protocol: ProtoH2,
			StreamID: id, Body: append([]byte(nil), data...), Truncated: true, CaptureGap: reason, DataKind: kind})
	}
	for _, id := range ids {
		st := p.streams[id]
		if st.headerBlock.Len() > 0 {
			fragment(id, st.headerBlock.Bytes(), DataHPACK)
		}
		if st.haveHeaders {
			st.endStream = true
			if m, ok := p.maybeEmit(id, pid, conn); ok {
				m.Truncated, m.CaptureGap, m.DataKind = true, reason, DataHTTPBody
				m.Model = ""
				out = append(out, m)
			}
		} else if st.body.Len() > 0 {
			fragment(id, st.body.Bytes(), DataHTTP2Body)
		}
	}
	if p.buf.Len() > 0 || len(out) == 0 {
		fragment(0, p.buf.Bytes(), DataTLSFragment)
	}
	p.buf.Reset()
	p.streams = map[uint32]*h2Stream{}
	p.failed = true
	return out
}
