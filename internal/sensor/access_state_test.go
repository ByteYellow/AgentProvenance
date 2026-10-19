package sensor

import (
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
)

func TestStateSamplingIsBoundedAndNeverAliasesKernelIdentity(t *testing.T) {
	blocked := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	var emitted []map[string]any
	s := newStateSampler(Options{AppArmorState: true, SeccompState: true}, func(pid, tid int, opts accesscontrol.Options) accesscontrol.Snapshot {
		once.Do(func() { close(entered) })
		<-blocked
		return accesscontrol.Snapshot{ObservedAt: "2026-10-19T00:00:00Z", Identity: accesscontrol.TaskIdentity{Status: "observed", PID: pid, TID: tid, CgroupID: "5"}}
	}, func(v any) { emitted = append(emitted, v.(map[string]any)) })
	now := time.Now()
	target := stateTarget{pid: 42, tid: 43, start: 100, cgroup: 5}
	s.offer(target, now)
	<-entered
	for i := 0; i < 100; i++ {
		s.offer(target, now.Add(time.Millisecond))
	}
	if len(s.queue) != 0 {
		t.Fatal("rate limiter requeued same task")
	}
	for i := 1; i < stateCacheCapacity+100; i++ {
		s.offer(stateTarget{pid: 42, tid: uint32(i), start: 200, cgroup: 6}, now)
	}
	if len(s.seen) > stateCacheCapacity || len(s.queue) > stateQueueCapacity || s.dropped.Load() == 0 {
		t.Fatal("unbounded sampler or missing drops")
	}
	close(blocked)
	s.close()
	if len(emitted) < 2 || emitted[0]["source"] != "procfs_access_control" || emitted[0]["cgroup_id"] != "5" {
		t.Fatalf("no independent snapshot: %+v", emitted)
	}
	var drops int64
	for i, item := range emitted {
		if _, ok := item["process_instance_id"]; ok {
			t.Fatal("procfs aliased kernel lifetime")
		}
		if _, ok := item["pid"]; ok {
			t.Fatal("procfs numeric pid entered exact runtime attribution")
		}
		if item["event_type"] == "resource_pressure" {
			drops += item["dropped_delta"].(int64)
			continue
		}
		if i > 0 {
			if _, ok := item["cgroup_id"]; ok {
				t.Fatal("mismatched observed cgroup attributed to trigger")
			}
		}
	}
	if drops == 0 {
		t.Fatal("queue loss not emitted")
	}
}

func TestStateSamplingOptOut(t *testing.T) {
	s := newStateSampler(Options{}, nil, nil)
	if s != nil {
		t.Fatal("disabled sampler started")
	}
	s.offer(stateTarget{pid: 1, tid: 1}, time.Now())
	s.close()
}
