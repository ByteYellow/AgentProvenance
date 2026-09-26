package sensor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func TestChineseCapabilitiesPreserveProtocolAndSavedReasons(t *testing.T) {
	var output bytes.Buffer
	var callback CapabilityReport
	r := newCapabilityReporter(Options{Language: i18n.Chinese, Diagnostics: &output, OnCapabilities: func(report CapabilityReport) { callback = report }})
	r.add(ProbeCapability{Name: "Copy", Category: "tls", Target: "/tmp/ready/Copy", Status: "unsupported", Reason: "Go TLS Read requires an amd64 ELF"})
	r.updateTLS(nil, TLSDiscoveryReport{Enabled: true, UnreadableProcesses: 2, Reason: "read process directory: permission denied", Limitations: []string{"polling can miss TLS activity before attachment and processes shorter than the scan interval"}})
	line, _, ok := strings.Cut(output.String(), "\n")
	const prefix = "agentprov-sensor: capabilities "
	if !ok || !strings.HasPrefix(line, prefix) {
		t.Fatal("protocol prefix lost")
	}
	var saved CapabilityReport
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, prefix)), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Probes[0].Reason != "Go TLS Read requires an amd64 ELF" || saved.Probes[0].Name != "Copy" || saved.Probes[0].Target != "/tmp/ready/Copy" {
		t.Fatalf("wire evidence changed: %+v", saved)
	}
	before, _ := json.Marshal(saved)
	var human bytes.Buffer
	PrintCapabilities(&human, saved, i18n.Chinese)
	after, _ := json.Marshal(saved)
	if !bytes.Equal(before, after) {
		t.Fatal("render changed saved evidence")
	}
	for _, want := range []string{"传感器状态：覆盖不足", "不支持", "Go TLS Read 需要 amd64 ELF 文件", "不可读进程=2", "轮询可能遗漏", "/tmp/ready/Copy", "探针 Copy"} {
		if !strings.Contains(human.String(), want) {
			t.Errorf("missing %q: %s", want, human.String())
		}
	}
	if callback.Probes[0].Reason != saved.Probes[0].Reason {
		t.Fatal("callback translated")
	}
	output.Reset()
	r.publish(false)
	if output.Len() != 0 {
		t.Fatal("localization changed snapshot deduplication")
	}
}
