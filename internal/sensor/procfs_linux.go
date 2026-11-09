//go:build linux && (amd64 || arm64)

package sensor

import (
	"os"
	"time"
)

type procTaskKey struct {
	Start, PIDTGID uint64
}

type procTaskIDs struct {
	PID, TID  uint32
	Namespace string
}

// The map is bounded in the kernel and keyed by the original task lifetime.
// Numeric procfs addresses never replace kernel evidence or TLS stream keys.
type procfsResolver struct {
	cache       map[procTaskKey]procTaskIDs
	namespace   *os.File
	lookup      func(procTaskKey) (procTaskIDs, error)
	report      ProcfsIdentityReport
	lastPublish time.Time
}

func (r *procfsResolver) close() {
	if r != nil && r.namespace != nil {
		_ = r.namespace.Close()
	}
}

func (r *procfsResolver) resolve(e sensorbpfSensorEvent) procTaskIDs {
	if r == nil {
		return procTaskIDs{PID: e.Pid, TID: e.Tid}
	}
	key := procTaskKey{e.ThreadStartNs, uint64(e.Pid)<<32 | uint64(e.Tid)}
	ids, ok := r.cache[key]
	var err error
	if !ok {
		ids, err = r.lookup(key)
		if err == nil && e.ThreadStartNs != 0 && ids.PID != 0 && ids.TID != 0 {
			if r.cache == nil || len(r.cache) >= 4096 {
				r.cache = make(map[procTaskKey]procTaskIDs)
			}
			r.cache[key] = ids
		}
	}
	if e.Kind == eventExit || e.Kind == eventThreadExit {
		delete(r.cache, key)
	}
	if err != nil || e.ThreadStartNs == 0 {
		r.report.LookupMisses++
		return procTaskIDs{}
	}
	if ids.PID == 0 || ids.TID == 0 {
		r.report.OutsideNamespace++
		return procTaskIDs{}
	}
	if ids.PID != e.Pid || ids.TID != e.Tid {
		r.report.TranslatedEvents++
	}
	ids.Namespace = r.report.PIDNamespace
	return ids
}

func (r *procfsResolver) publish(reporter *capabilityReporter, force bool) {
	if r != nil && (force || time.Since(r.lastPublish) >= time.Second) {
		r.lastPublish = time.Now()
		reporter.updateProcfs(r.report)
	}
}

func eventProcTask(e sensorbpfSensorEvent, task []procTaskIDs) procTaskIDs {
	if len(task) > 0 {
		return task[0]
	}
	return procTaskIDs{PID: e.Pid, TID: e.Tid}
}

func addProcfsIdentity(ev map[string]any, task procTaskIDs) {
	if task.Namespace != "" && task.PID != 0 && task.TID != 0 {
		ev["procfs_pid"], ev["procfs_tid"] = task.PID, task.TID
		ev["procfs_pid_namespace"] = task.Namespace
	}
}
