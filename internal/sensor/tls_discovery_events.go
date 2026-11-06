package sensor

import (
	"sort"
	"sync/atomic"
	"time"
)

const tlsDiscoveryQueueCapacity = 128
const tlsDiscoveryBatchSize = 16
const tlsDiscoveryBatchInterval = 10 * time.Millisecond

var tlsDiscoveryRetryDelays = [...]time.Duration{0, 25 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond, 2 * time.Second}

type tlsProcessKey struct {
	pid   uint32
	start uint64
}

type tlsProcessHint struct {
	tlsProcessKey
	observed time.Time
	exec     bool
	library  bool
}

type tlsHintQueue struct {
	items   chan tlsProcessHint
	offered atomic.Uint64
	dropped atomic.Uint64
}

func newTLSHintQueue() *tlsHintQueue {
	return &tlsHintQueue{items: make(chan tlsProcessHint, tlsDiscoveryQueueCapacity)}
}

func (q *tlsHintQueue) offer(pid uint32, start uint64, exec, library bool, now time.Time) {
	if pid == 0 || start == 0 {
		return
	}
	q.offered.Add(1)
	select {
	case q.items <- tlsProcessHint{tlsProcessKey{pid, start}, now, exec, library}:
	default:
		q.dropped.Add(1)
	}
}

type tlsPendingHint struct {
	hint     tlsProcessHint
	attempt  int
	next     time.Time
	finished bool
	identity tlsProcessIdentity
}

type tlsProcessIdentity struct{ ticks, executable string }

// Finite retries cover mappings loaded after exec. Completed entries stay for
// the retry horizon to coalesce high-frequency connect/open hints as well.
type tlsHintSchedule struct {
	pending map[tlsProcessKey]*tlsPendingHint
	stats   TLSEventDiscoveryReport
}

func newTLSHintSchedule() *tlsHintSchedule {
	return &tlsHintSchedule{pending: map[tlsProcessKey]*tlsPendingHint{}, stats: TLSEventDiscoveryReport{QueueCapacity: tlsDiscoveryQueueCapacity}}
}

func (s *tlsHintSchedule) add(hint tlsProcessHint) {
	if old, ok := s.pending[hint.tlsProcessKey]; ok && !hint.exec {
		// A later library load starts a new finite retry cycle. Ordinary
		// connects and a loader's rapid path probes share the existing cycle.
		if !hint.library || hint.observed.Sub(old.hint.observed) < 100*time.Millisecond {
			s.stats.Coalesced++
			return
		}
	}
	if _, ok := s.pending[hint.tlsProcessKey]; !ok && len(s.pending) >= tlsDiscoveryQueueCapacity {
		s.stats.QueueDrops++
		return
	}
	s.pending[hint.tlsProcessKey] = &tlsPendingHint{hint: hint, next: hint.observed}
}

func (s *tlsHintSchedule) due(now time.Time) []*tlsPendingHint {
	var due []*tlsPendingHint
	for key, p := range s.pending {
		if p.next.After(now) {
			continue
		}
		if p.finished || p.attempt == len(tlsDiscoveryRetryDelays) {
			delete(s.pending, key)
			continue
		}
		due = append(due, p)
	}
	sort.Slice(due, func(i, j int) bool { return due[i].next.Before(due[j].next) })
	return due[:min(len(due), tlsDiscoveryBatchSize)]
}

func (s *tlsHintSchedule) advance(p *tlsPendingHint, finished bool) {
	p.attempt++
	p.finished = finished
	if finished || p.attempt == len(tlsDiscoveryRetryDelays) {
		p.next = p.hint.observed.Add(tlsDiscoveryRetryDelays[len(tlsDiscoveryRetryDelays)-1] + tlsDiscoveryBatchInterval)
	} else {
		p.next = p.hint.observed.Add(tlsDiscoveryRetryDelays[p.attempt])
	}
}

func (s *tlsHintSchedule) next(now, throttle time.Time) time.Duration {
	var next time.Time
	for _, p := range s.pending {
		if next.IsZero() || p.next.Before(next) {
			next = p.next
		}
	}
	if next.IsZero() {
		return time.Hour
	}
	if next.Before(throttle) {
		next = throttle
	}
	if next.Before(now) {
		return 0
	}
	return next.Sub(now)
}
