package provenance

import "testing"

func TestProcessLabelsUseStableLatestEvidence(t *testing.T) {
	db := newLensTestDB(t)
	for _, ev := range []struct {
		id, kind, command, at string
		pid, tgid             int
	}{
		{"old-exec", "execve", "bash setup.sh", "2026-09-28T10:00:00Z", 42, 42},
		{"new-exec", "execve", "python3 setup.py", "2026-09-28T10:00:00.1Z", 42, 42},
		{"sample", "process_observed", "sample must not replace exec", "2026-09-28T10:00:02Z", 42, 42},
		{"old-sample", "process_observed", "old sample", "2026-09-28T10:00:00Z", 43, 43},
		{"new-sample", "process_observed", "current sample", "2026-09-28T10:00:01+00:00", 43, 43},
		{"leader-old", "network_connect", "old leader", "2026-09-28T10:00:00Z", 44, 44},
		{"leader-new", "network_connect", "current leader", "2026-09-28T10:00:00.5Z", 44, 44},
		{"thread-new", "network_connect", "worker thread", "2026-09-28T10:00:03Z", 45, 44},
	} {
		_, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, pid, tgid, created_at)
			VALUES (?, 'run-label', 'test', ?, ?, ?, ?, ?)`, ev.id, ev.kind, `{"command":"`+ev.command+`"}`, ev.pid, ev.tgid, ev.at)
		if err != nil {
			t.Fatal(err)
		}
	}
	for pass := 0; pass < 20; pass++ {
		nodes, _, err := graphLensNodes(db, "run-label")
		if err != nil {
			t.Fatal(err)
		}
		for id, want := range map[string]string{
			"runtime_process/pid/42":  "python3 setup.py",
			"runtime_process/pid/43":  "current sample",
			"runtime_process/tgid/44": "current leader",
		} {
			if got := nodes[id].Label; got != want {
				t.Fatalf("pass %d: %s label=%q, want %q", pass, id, got, want)
			}
		}
	}
}
