package tlsintent

// Closed generations are retained within a bounded cache so a delayed read
// completion cannot resurrect an object released on another thread.
type connectionState struct {
	start, epoch, lastUsed uint64
	closed                 bool
}

func stampIdentity(messages []Message, start, epoch uint64) {
	for i := range messages {
		messages[i].ProcessStartNS = start
		messages[i].Epoch = epoch
	}
}

func (r *Reassembler) acceptConnection(c Chunk) bool {
	if r.connections == nil {
		r.connections = map[connKey]*connectionState{}
	}
	key := connKey{c.PID, c.Conn}
	state := r.connections[key]
	if state != nil && (state.start != c.ProcessStartNS || state.epoch != c.Epoch) {
		if c.ProcessStartNS < state.start || (c.ProcessStartNS == state.start && c.Epoch < state.epoch) {
			return false
		}
		r.discardConnection(key)
		delete(r.connections, key)
		state = nil
	}
	if state == nil {
		for len(r.connections) >= 2*r.streamLimit() {
			var oldest connKey
			var tick uint64
			found := false
			for k, s := range r.connections {
				if !found || s.lastUsed < tick {
					oldest, tick, found = k, s.lastUsed, true
				}
			}
			r.discardConnection(oldest)
			delete(r.connections, oldest)
		}
		state = &connectionState{start: c.ProcessStartNS, epoch: c.Epoch}
		r.connections[key] = state
	}
	r.tick++
	state.lastUsed = r.tick
	return !state.closed
}

// Reset marks a capture boundary, not a proven TCP close. A clear/rebind attempt
// may retain the SSL object while invalidating its HTTP and HPACK context.
func (r *Reassembler) Reset(c Chunk) { r.acceptConnection(c) }

// Release flushes only the matching generation. SSL_free can decrement a live
// object's reference count, so retained data is emitted as best-effort and a
// later use starts a fresh capture generation in the producer.
func (r *Reassembler) Release(c Chunk) []Message {
	if !r.acceptConnection(c) {
		return nil
	}
	key := connKey{c.PID, c.Conn}
	state := r.connections[key]
	out := r.Flush(c.PID, c.Conn)
	state.closed = true
	r.connections[key] = state
	return out
}

func (r *Reassembler) discardConnection(key connKey) {
	for _, dir := range []string{Request, Response} {
		k := streamKey{key.pid, key.conn, dir}
		if s := r.streams[k]; s != nil {
			n := s.buf.Len()
			if s.h2 != nil {
				n += s.h2.retainedBytes()
			}
			if n > 0 {
				r.loss.Streams++
				r.loss.Bytes += uint64(n)
			}
			delete(r.streams, k)
		}
	}
	delete(r.h2Conns, key)
}

// EndProcess matches the kernel process lifetime, not just the reusable PID.
// Exec discards old address-space state; exit can emit remaining partial data.
func (r *Reassembler) EndProcess(pid uint32, start uint64, exec bool) []Message {
	var out []Message
	for key, state := range r.connections {
		if key.pid != pid || state.start != start || state.closed {
			continue
		}
		if exec {
			r.discardConnection(key)
			delete(r.connections, key)
		} else {
			out = append(out, r.Release(Chunk{PID: pid, Conn: key.conn, ProcessStartNS: start, Epoch: state.epoch})...)
		}
	}
	return out
}
