package tlsintent

// CaptureLoss counts plaintext that could not be reassembled within the memory
// budget. It is separate from kernel ring-buffer drops.
type CaptureLoss struct {
	Streams uint64
	Bytes   uint64
}

// TakeLoss returns and resets loss counters since the previous call.
func (r *Reassembler) TakeLoss() CaptureLoss { loss := r.loss; r.loss = CaptureLoss{}; return loss }

func (r *Reassembler) byteLimit() int {
	if r.MaxBytes > 0 {
		return r.MaxBytes
	}
	return defaultMaxBytes
}
func (r *Reassembler) streamLimit() int {
	if r.MaxStreams > 0 {
		return r.MaxStreams
	}
	return 128
}

func (r *Reassembler) evictOldest() {
	var oldest streamKey
	var tick uint64
	found := false
	for key, s := range r.streams {
		if !found || s.lastUsed < tick {
			oldest, tick, found = key, s.lastUsed, true
		}
	}
	if !found {
		return
	}
	// Evict both directions: keeping HPACK/HTTP2 context after losing one side
	// would make the surviving state misleading.
	for _, dir := range []string{Request, Response} {
		key := streamKey{oldest.pid, oldest.conn, dir}
		if s := r.streams[key]; s != nil {
			r.loss.Streams++
			r.loss.Bytes += uint64(s.buf.Len())
			if s.h2 != nil {
				r.loss.Bytes += uint64(s.h2.retainedBytes())
			}
			delete(r.streams, key)
		}
	}
	delete(r.h2Conns, connKey{oldest.pid, oldest.conn})
}

// FlushPID frees every TLS connection belonging to an exited process. It also
// emits close-framed or partial messages with their existing truncated marker.
func (r *Reassembler) FlushPID(pid uint32) []Message {
	var out []Message
	for key := range r.streams {
		if key.pid == pid {
			out = append(out, r.Flush(pid, key.conn)...)
		}
	}
	return out
}

func (p *h2Parser) byteLimit() int {
	if p.maxBytes > 0 {
		return p.maxBytes
	}
	return defaultMaxBytes
}
func (p *h2Parser) retainedBytes() int {
	n := p.buf.Len()
	for _, s := range p.streams {
		n += s.body.Len() + s.headerBlock.Len()
		for name, value := range s.headers {
			n += len(name) + len(value)
		}
	}
	return n
}
func (p *h2Parser) fail(extra int) {
	p.loss.Bytes += uint64(p.retainedBytes() + extra)
	p.loss.Streams += uint64(len(p.streams))
	if len(p.streams) == 0 {
		p.loss.Streams++
	}
	p.buf.Reset()
	p.streams = map[uint32]*h2Stream{}
	p.failed = true
}
