package cost

import (
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestAggregateResourceWindowsAndRetention(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	base := time.Date(2026, 6, 11, 1, 2, 3, 0, time.UTC)
	samples := []struct {
		id        string
		sessionID string
		active    float64
		idle      float64
		createdAt time.Time
	}{
		{"cpu-old", "sbx-1", 0.1, 0.9, base.Add(-20 * time.Minute)},
		{"cpu-1", "sbx-1", 0.2, 0.8, base},
		{"cpu-2", "sbx-1", 0.3, 0.7, base.Add(4 * time.Second)},
		{"cpu-3", "sbx-2", 0.4, 0.6, base.Add(61 * time.Second)},
	}
	for _, sample := range samples {
		if _, err := db.Exec(`INSERT INTO cpu_samples
			(id, run_id, session_id, node_id, active_cpu_seconds, idle_seconds, cpu_percent, ewma_active_cpu, throttling, memory_pressure, created_at)
			VALUES (?, 'run-1', ?, 'local', ?, ?, 10, ?, '', 'low', ?)`,
			sample.id, sample.sessionID, sample.active, sample.idle, sample.active, sample.createdAt.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}

	if err := AggregateResourceWindows(db, WindowOptions{Windows: []int{10, 60}}); err != nil {
		t.Fatal(err)
	}
	var active, idle float64
	if err := db.QueryRow(`SELECT active_cpu_seconds, idle_seconds FROM session_resource_windows
		WHERE session_id = 'sbx-1' AND window_seconds = 10 AND window_start = ?`, base.Truncate(10*time.Second).Format(time.RFC3339Nano)).Scan(&active, &idle); err != nil {
		t.Fatal(err)
	}
	if math.Abs(active-0.5) > 0.000001 || math.Abs(idle-1.5) > 0.000001 {
		t.Fatalf("unexpected 10s aggregate active=%.3f idle=%.3f", active, idle)
	}
	var nodeSamples int64
	if err := db.QueryRow(`SELECT sample_count FROM node_resource_windows
		WHERE node_id = 'local' AND window_seconds = 60 AND window_start = ?`, base.Truncate(60*time.Second).Format(time.RFC3339Nano)).Scan(&nodeSamples); err != nil {
		t.Fatal(err)
	}
	if nodeSamples != 2 {
		t.Fatalf("expected current 60s node window to contain 2 samples, got %d", nodeSamples)
	}

	if err := RetainRawCPUSamples(db, WindowOptions{RawRetention: 10 * time.Minute, MaxRawPerSession: 2}); err != nil {
		t.Fatal(err)
	}
	var rawCount int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM cpu_samples WHERE id = 'cpu-old'`).Scan(&rawCount); err != nil {
		t.Fatal(err)
	}
	if rawCount != 0 {
		t.Fatalf("expected old raw sample to be removed")
	}
}

func TestRetentionUsesInstantsAndRollsBackInvalidTimestamps(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		paths, err := store.Init(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(paths)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		samples := map[string]string{
			"old":    "2026-01-01T00:00:59.999999999Z",
			"whole":  "2026-01-01T00:01:00Z",
			"nano":   "2026-01-01T00:01:00.000000001Z",
			"offset": "2025-12-31T19:01:00.000000002-05:00",
		}
		if malformed {
			samples["invalid"] = "not-a-time"
		}
		for id, timestamp := range samples {
			if _, err := db.Exec(`INSERT INTO cpu_samples(id,run_id,session_id,node_id,active_cpu_seconds,idle_seconds,cpu_percent,ewma_active_cpu,throttling,memory_pressure,created_at) VALUES (?,'run','session','local',0,0,0,0,'','low',?)`, id, timestamp); err != nil {
				t.Fatal(err)
			}
		}
		now := time.Date(2026, 1, 1, 0, 2, 0, 0, time.UTC)
		err = retainRawCPUSamples(db, WindowOptions{RawRetention: time.Minute, MaxRawPerSession: 2}, now)
		if malformed {
			var count int
			if err == nil {
				t.Fatal("invalid timestamp silently accepted")
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM cpu_samples`).Scan(&count); err != nil || count != len(samples) {
				t.Fatalf("retention partially committed: count=%d err=%v", count, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		rows, err := db.Query(`SELECT id FROM cpu_samples ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		var kept []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			kept = append(kept, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		if !reflect.DeepEqual(kept, []string{"nano", "offset"}) {
			t.Fatalf("kept=%v", kept)
		}
	}
}

func TestRetentionAcrossPages(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed=%t", malformed), func(t *testing.T) {
			paths, err := store.Init(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			for i := 0; i < 600; i++ {
				// Alternate old/new times so the retained set spans page boundaries.
				at := base.Add(time.Duration((i*37)%600) * time.Second)
				timestamp := at.Format(time.RFC3339Nano)
				if malformed && i == 599 {
					timestamp = "invalid"
				}
				if _, err := db.Exec(`INSERT INTO cpu_samples
					(id,run_id,session_id,node_id,active_cpu_seconds,idle_seconds,cpu_percent,ewma_active_cpu,throttling,memory_pressure,created_at)
					VALUES (?,'run','session','local',0,0,0,0,'','low',?)`, fmt.Sprintf("sample-%04d", i), timestamp); err != nil {
					t.Fatal(err)
				}
			}
			err = retainRawCPUSamples(db, WindowOptions{RawRetention: time.Hour, MaxRawPerSession: 3}, base.Add(10*time.Minute))
			if malformed {
				var count int
				if err == nil {
					t.Fatal("invalid timestamp accepted")
				}
				if err := db.QueryRow(`SELECT COUNT(*) FROM cpu_samples`).Scan(&count); err != nil || count != 600 {
					t.Fatalf("earlier pages did not roll back: count=%d err=%v", count, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			rows, err := db.Query(`SELECT created_at FROM cpu_samples ORDER BY created_at`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var got []string
			for rows.Next() {
				var timestamp string
				if err := rows.Scan(&timestamp); err != nil {
					t.Fatal(err)
				}
				got = append(got, timestamp)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			var want []string
			for i := 597; i < 600; i++ {
				want = append(want, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("retained samples=%v want=%v", got, want)
			}
		})
	}
}
