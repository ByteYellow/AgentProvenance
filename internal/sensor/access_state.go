package sensor

import (
	"strconv"
	"sync/atomic"
	"time"

	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
)

const (
	stateQueueCapacity = 128
	stateCacheCapacity = 2048
	stateInterval      = 2 * time.Second
)

type stateTarget struct {
	pid, tid      uint32
	start, cgroup uint64
}

type stateSampler struct {
	queue   chan stateTarget
	done    chan struct{}
	seen    map[stateTarget]time.Time
	order   []stateTarget
	next    int
	dropped atomic.Int64
}

// Only the ring-buffer reader offers work. Filesystem I/O and encoding run in
// the worker, while both scheduling memory and the pending queue are bounded.
func newStateSampler(opts Options, read func(int, int, accesscontrol.Options) accesscontrol.Snapshot, emit func(any)) *stateSampler {
	if !opts.AppArmorState && !opts.SeccompState {
		return nil
	}
	s := &stateSampler{queue: make(chan stateTarget, stateQueueCapacity), done: make(chan struct{}),
		seen: map[stateTarget]time.Time{}, order: make([]stateTarget, 0, stateCacheCapacity)}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		loss := func() {
			if n := s.dropped.Swap(0); n > 0 {
				emit(map[string]any{"source": "agentprov_ebpf", "event_type": "resource_pressure", "resource": "sensor_access_state",
					"signal": "state_snapshot_queue_drop", "dropped_delta": n, "timestamp": time.Now().UTC().Format(time.RFC3339Nano)})
			}
		}
		defer loss()
		for {
			select {
			case target, ok := <-s.queue:
				if !ok {
					return
				}
				snapshot := read(int(target.pid), int(target.tid), accesscontrol.Options{AppArmor: opts.AppArmorState, Seccomp: opts.SeccompState})
				ev := map[string]any{"source": "procfs_access_control", "event_type": "access_control_state", "state": snapshot, "timestamp": snapshot.ObservedAt}
				// PID hints initiate sampling, but do not join the procfs task to the
				// earlier kernel lifetime. Only independently observed membership
				// agreeing with the trigger is eligible for workload attribution.
				if snapshot.Identity.Status == "observed" && snapshot.Identity.CgroupID != "" && snapshot.Identity.CgroupID == strconv.FormatUint(target.cgroup, 10) {
					ev["cgroup_id"] = snapshot.Identity.CgroupID
				}
				emit(ev)
			case <-ticker.C:
				loss()
			}
		}
	}()
	return s
}

func (s *stateSampler) offer(target stateTarget, now time.Time) {
	if s == nil || target.pid == 0 || target.tid == 0 {
		return
	}
	if seen, ok := s.seen[target]; ok && now.Sub(seen) < stateInterval {
		return
	}
	if _, ok := s.seen[target]; !ok {
		if len(s.order) < stateCacheCapacity {
			s.order = append(s.order, target)
		} else {
			delete(s.seen, s.order[s.next])
			s.order[s.next] = target
			s.next = (s.next + 1) % stateCacheCapacity
		}
	}
	s.seen[target] = now
	select {
	case s.queue <- target:
	default:
		s.dropped.Add(1)
	}
}

func (s *stateSampler) close() {
	if s != nil {
		close(s.queue)
		<-s.done
	}
}
