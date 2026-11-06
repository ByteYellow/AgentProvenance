package tlsintent

import "bytes"

// CallCaptureLimit matches SSL_CHUNK * SSL_MAX_CHUNKS in the native producer.
// It bounds call assembly independently of the HTTP message retention budget.
const CallCaptureLimit = 4096

type ChunkPosition struct {
	StreamID     uint64 `json:"stream_id,string"`
	CallSequence uint64 `json:"call_sequence,string"`
	Offset       uint32 `json:"offset"`
	TotalBytes   uint32 `json:"total_bytes"`
	Checkpoint   bool   `json:"checkpoint,omitempty"`
}

type captureSequence struct {
	position ChunkPosition
	next     uint32
	pending  []byte
	ended    bool // last captured byte or checkpoint seen; the stream may still have gaps
}

func (r *Reassembler) invalidateCapture(c Chunk, s *stream, reason string) []Message {
	if s.gap != "" {
		return nil
	}
	r.markGap(c, s, reason)
	r.loss.Streams++
	// These buffers may span several calls. Do not attach the current call's
	// position to bytes accumulated by HTTP/HPACK before the detected gap.
	c.Position = nil
	if s.h2 != nil {
		if s.h2.retainedBytes() > 0 {
			return s.h2.drainGap(c.PID, c.Conn, reason)
		}
		s.h2.failed = true
	}
	if s.buf.Len() > 0 {
		out := r.fragment(c, s.buf.Bytes(), reason, DataTLSFragment)
		s.buf = bytes.Buffer{}
		return out
	}
	return nil
}

func (r *Reassembler) flushCapture(c Chunk, s *stream) []Message {
	q := s.capture
	if q == nil || len(q.pending) == 0 {
		return nil
	}
	c.Position = &q.position
	out := r.fragment(c, q.pending, s.gap, DataTLSFragment)
	q.pending = nil
	q.position.Offset = q.next
	return out
}

func (r *Reassembler) addPositioned(c Chunk, s *stream) []Message {
	p := *c.Position
	end := uint64(p.Offset) + uint64(len(c.Data))
	limit := min(p.TotalBytes, uint32(CallCaptureLimit))
	if p.StreamID == 0 || p.CallSequence == 0 || p.TotalBytes == 0 || p.TotalBytes > 0x7fffffff ||
		len(c.Data) == 0 || end > uint64(limit) {
		out := r.invalidateCapture(c, s, GapChunkMetadata)
		out = append(out, r.flushCapture(c, s)...)
		return append(out, r.fragment(c, c.Data, s.gap, DataTLSFragment)...)
	}
	var out []Message
	q := s.capture
	if q != nil && p.StreamID < q.position.StreamID {
		// Map generations use monotonic kernel time. A delayed older generation
		// cannot replace the current sequence or supply missing bytes.
		r.loss.Bytes += uint64(len(c.Data))
		return nil
	}
	if q == nil || p.StreamID != q.position.StreamID || p.CallSequence > q.position.CallSequence {
		reason := ""
		switch {
		case q != nil && p.StreamID != q.position.StreamID:
			reason = GapSequenceReset
		case q != nil && !q.ended:
			reason = GapChunkSequence
		case q != nil && p.CallSequence-q.position.CallSequence != 1:
			reason = GapCallSequence
		case q == nil && p.CallSequence != 1:
			reason = GapCallSequence
		case q == nil && s.unsequenced:
			reason = GapCallSequence
		case p.Offset != 0:
			reason = GapChunkSequence
		}
		if reason != "" {
			out = append(out, r.invalidateCapture(c, s, reason)...)
		}
		out = append(out, r.flushCapture(c, s)...)
		q = &captureSequence{position: p, next: p.Offset}
		s.capture = q
	} else if p.CallSequence < q.position.CallSequence || q.ended {
		// An already consumed call, or a late chunk from a call previously
		// declared incomplete, must not be replayed into the protocol parser.
		if s.gap != "" {
			return r.fragment(c, c.Data, s.gap, DataTLSFragment)
		}
		return nil
	}
	if p.TotalBytes != q.position.TotalBytes {
		out = append(out, r.invalidateCapture(c, s, GapChunkMetadata)...)
		out = append(out, r.flushCapture(c, s)...)
		return append(out, r.fragment(c, c.Data, s.gap, DataTLSFragment)...)
	}
	if p.Offset != q.next {
		if p.Offset >= q.position.Offset && end <= uint64(q.next) &&
			bytes.Equal(q.pending[p.Offset-q.position.Offset:uint32(end)-q.position.Offset], c.Data) {
			return out // An exact duplicate still retained in this call.
		}
		out = append(out, r.invalidateCapture(c, s, GapChunkSequence)...)
		out = append(out, r.flushCapture(c, s)...)
		q.position.Offset, q.next = p.Offset, p.Offset
	}
	retained := s.buf.Len()
	if s.h2 != nil {
		retained += s.h2.retainedBytes()
	}
	if len(q.pending)+len(c.Data) > r.byteLimit()-retained {
		out = append(out, r.invalidateCapture(c, s, GapBufferLimit)...)
		out = append(out, r.flushCapture(c, s)...)
		if len(c.Data) > r.byteLimit() {
			r.loss.Bytes += uint64(len(c.Data) - r.byteLimit())
			q.next = uint32(end)
			q.position.Offset = q.next
			q.ended = q.next == limit
			return append(out, r.fragment(c, c.Data, s.gap, DataTLSFragment)...)
		}
	}
	if q.pending == nil {
		q.pending = make([]byte, 0, min(int(limit-p.Offset), r.byteLimit()))
	}
	q.pending = append(q.pending, c.Data...)
	q.next = uint32(end)
	if q.next == limit {
		q.ended = true
		c.Data, c.Position = q.pending, &q.position
		c.Truncated = c.Truncated || p.TotalBytes > CallCaptureLimit
		out = append(out, r.addData(c, s)...)
		q.pending = nil
		q.position.Offset = q.next
	}
	return out
}

func (r *Reassembler) captureCheckpoint(c Chunk, s *stream) []Message {
	p := c.Position
	if p == nil || p.StreamID == 0 || p.CallSequence == 0 {
		return nil
	}
	position := *p
	position.Checkpoint = true
	c.Position, p = &position, &position
	q := s.capture
	if q != nil && (p.StreamID < q.position.StreamID ||
		(p.StreamID == q.position.StreamID && (p.CallSequence < q.position.CallSequence ||
			(p.CallSequence == q.position.CallSequence && q.ended)))) {
		return nil
	}
	reason := GapCallSequence
	if q != nil && p.StreamID == q.position.StreamID && p.CallSequence == q.position.CallSequence {
		reason = GapChunkSequence
	}
	out := r.invalidateCapture(c, s, reason)
	out = append(out, r.flushCapture(c, s)...)
	if len(out) == 0 || q == nil || p.StreamID != q.position.StreamID || p.CallSequence != q.position.CallSequence {
		out = append(out, r.fragment(c, nil, s.gap, DataTLSFragment)...)
	}
	s.capture = &captureSequence{position: *p, ended: true}
	return out
}
