package sensor

import (
	"testing"
	"time"
)

func TestTLSHintQueueNeverBlocksAndCountsOverflow(t *testing.T) {
	q := newTLSHintQueue()
	now := time.Now()
	q.offer(0, 1, true, false, now)
	q.offer(1, 0, true, false, now)
	for i := 0; i < tlsDiscoveryQueueCapacity+7; i++ {
		q.offer(uint32(i+1), 2, true, false, now)
	}
	if q.offered.Load() != tlsDiscoveryQueueCapacity+7 || q.dropped.Load() != 7 || len(q.items) != tlsDiscoveryQueueCapacity {
		t.Fatalf("queue limits: offered=%d dropped=%d len=%d", q.offered.Load(), q.dropped.Load(), len(q.items))
	}
}

func TestTLSHintScheduleFiniteRetriesAndExecIdentity(t *testing.T) {
	now := time.Now()
	s := newTLSHintSchedule()
	h := tlsProcessHint{tlsProcessKey{10, 100}, now, true, false}
	s.add(h)
	duplicate := h
	duplicate.exec = false
	for i := 0; i < 20; i++ {
		s.add(duplicate)
	}
	if s.stats.Coalesced != 20 || len(s.pending) != 1 {
		t.Fatalf("duplicate work: %+v", s.stats)
	}
	for attempt, delay := range tlsDiscoveryRetryDelays {
		if attempt > 0 && len(s.due(now.Add(delay-time.Nanosecond))) != 0 {
			t.Fatal("retry ran before its deadline")
		}
		due := s.due(now.Add(delay))
		if len(due) != 1 || due[0].attempt != attempt {
			t.Fatalf("attempt %d: %+v", attempt, due)
		}
		s.advance(due[0], false)
	}
	if len(s.due(now.Add(3*time.Second))) != 0 || len(s.pending) != 0 {
		t.Fatal("retry horizon did not expire")
	}
	s.add(h)
	p := s.pending[h.tlsProcessKey]
	p.identity = tlsProcessIdentity{"old", "old-executable"}
	s.advance(p, true)
	s.add(duplicate)
	if !p.finished {
		t.Fatal("late connect revived an exited task")
	}
	h.observed = now.Add(time.Second)
	s.add(h)
	if s.pending[h.tlsProcessKey].identity.ticks != "" || s.pending[h.tlsProcessKey].finished {
		t.Fatal("new exec reused the earlier image observation")
	}
	h.start++
	s.add(h)
	if len(s.pending) != 2 {
		t.Fatal("PID reuse was coalesced with a different process lifetime")
	}
}

func TestTLSHintScheduleBoundsWorkAndPendingMemory(t *testing.T) {
	now := time.Now()
	s := newTLSHintSchedule()
	for i := 1; i <= tlsDiscoveryQueueCapacity+5; i++ {
		s.add(tlsProcessHint{tlsProcessKey{uint32(i), 1}, now, true, false})
	}
	if len(s.pending) != tlsDiscoveryQueueCapacity || s.stats.QueueDrops != 5 {
		t.Fatalf("unbounded pending work: %d %+v", len(s.pending), s.stats)
	}
	if due := s.due(now); len(due) != tlsDiscoveryBatchSize {
		t.Fatalf("unbounded batch: %d", len(due))
	}
	if delay := s.next(now, now.Add(tlsDiscoveryBatchInterval)); delay != tlsDiscoveryBatchInterval {
		t.Fatalf("batch throttle bypassed: %v", delay)
	}
}

func TestTLSHintLateLibraryLoadRestartsFiniteRetries(t *testing.T) {
	now := time.Now()
	s := newTLSHintSchedule()
	hint := tlsProcessHint{tlsProcessKey{10, 100}, now, true, false}
	s.add(hint)
	for _, delay := range tlsDiscoveryRetryDelays[:4] {
		for _, p := range s.due(now.Add(delay)) {
			s.advance(p, false)
		}
	}
	hint.exec, hint.library = false, true
	hint.observed = now.Add(700 * time.Millisecond)
	s.add(hint)
	due := s.due(hint.observed)
	if len(due) != 1 || due[0].attempt != 0 {
		t.Fatal("delayed library remained behind the exec retry deadline")
	}
	s.advance(due[0], false)
	hint.observed = hint.observed.Add(time.Millisecond)
	s.add(hint)
	if s.pending[hint.tlsProcessKey].attempt != 1 {
		t.Fatal("rapid loader path attempts reset the retry cycle")
	}
}

func TestTLSDiscoveryGapCountersAreVisible(t *testing.T) {
	d := TLSDiscoveryReport{Enabled: true, EventDiscovery: &TLSEventDiscoveryReport{ExitedProcesses: 2, ChangedProcesses: 1}}
	if d.HasGaps() {
		t.Fatal("normal process churn was classified as a discovery failure")
	}
	d.EventDiscovery.QueueDrops = 1
	if !d.HasGaps() {
		t.Fatal("hint queue loss was hidden")
	}
	d.Enabled = false
	if d.HasGaps() {
		t.Fatal("disabled discovery was reported as enabled but incomplete")
	}
}
