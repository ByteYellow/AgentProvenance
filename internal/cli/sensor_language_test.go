package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestSensorStatusLocalizesHistoricalReportWithoutChangingJSON(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`INSERT INTO telemetry_native_counters(name,value) VALUES ('dropped_queue_full',7),('invalid_payload_execve',2),('future_counter',9)`); err != nil {
		t.Fatal(err)
	}
	// An older machine report, including an unknown extension, must survive.
	report := `{"schema_version":"agentprovenance.sensor_capabilities/v1","status":"failed","ready":false,"reason":"load eBPF objects: not an ELF file","probes":[{"name":"Copy","category":"tls","target":"/tmp/Ready","status":"unsupported","reason":"Go TLS Read requires an amd64 ELF"}],"future_extension":"Copy"}`
	path := filepath.Join(paths.Logs, "sensor-capabilities.json")
	if err = os.WriteFile(path, []byte(report), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(lang string, asJSON bool) string {
		cmd := NewRootCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		args := []string{"--data-dir", paths.Root, "--lang", lang, "sensor", "status"}
		if asJSON {
			args = append(args, "--json")
		}
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	var en, zh any
	if err := json.Unmarshal([]byte(run("en", true)), &en); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(run("zh-CN", true)), &zh); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(en, zh) {
		t.Fatal("language changed JSON")
	}
	text := run("zh-CN", false)
	for _, want := range []string{"历史能力快照", "队列满丢弃：7", "事件载荷无效 (execve)：2", "future_counter：9", "加载 eBPF 对象失败：不是 ELF 文件", "探针 Copy", "/tmp/Ready"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "%!") {
		t.Fatal("invalid display format")
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != report {
		t.Fatal("saved capability evidence changed")
	}
}
