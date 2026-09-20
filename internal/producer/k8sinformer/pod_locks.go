package k8sinformer

import "sync"

// Count holders and waiters before acquiring the per-Pod mutex. Removing a
// mutex on Pod deletion while another worker waits on it would permit a third
// worker to create a different mutex for the same UID and run concurrently.
// Entries are removed only after the last holder/waiter finishes, so a long
// lived informer does not retain locks for every Pod it has ever observed.
type podLocks struct {
	mu      sync.Mutex
	entries map[string]*podLock
}

type podLock struct {
	mu   sync.Mutex
	refs int
}

func (s *podLocks) lock(uid string) func() {
	s.mu.Lock()
	if s.entries == nil {
		s.entries = map[string]*podLock{}
	}
	l := s.entries[uid]
	if l == nil {
		l = &podLock{}
		s.entries[uid] = l
	}
	l.refs++
	s.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		s.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(s.entries, uid)
		}
		s.mu.Unlock()
	}
}
