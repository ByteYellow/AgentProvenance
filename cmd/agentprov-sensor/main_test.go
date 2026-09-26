package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/sensor"
)

func TestSensorHelpAndInvalidFlagsDoNotStartCapture(t *testing.T) {
	for _, tt := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--lang", "zh-CN", "--help"}, 0, "发现并跟踪可见容器"},
		{[]string{"--help", "--lang=zh-CN"}, 0, "用法：agentprov-sensor"},
		{[]string{"--help"}, 0, "Usage: agentprov-sensor"},
		{[]string{"--lang", "zh-CN", "--tls-max-targets", "Copy"}, 2, "无法解析"},
		{[]string{"--unknown", "--lang", "zh-CN"}, 2, "未定义选项：-unknown"},
		{[]string{"--lang", "zh-CN", "--tls-max-targets"}, 2, "缺少参数"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(tt.args, &stdout, &stderr, func(io.Writer, sensor.Options) error { t.Fatal("started capture on help/parse failure"); return nil })
		if code != tt.code || !strings.Contains(stderr.String(), tt.want) || stdout.Len() != 0 {
			t.Errorf("args %v code=%d out=%s err=%s", tt.args, code, stdout.String(), stderr.String())
		}
	}
}

func TestSensorLanguageLeavesTelemetryAndReadyUnchanged(t *testing.T) {
	for _, lang := range []i18n.Locale{i18n.English, i18n.Chinese} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"--lang", string(lang), "--auto-tls=false"}, &stdout, &stderr, func(out io.Writer, opts sensor.Options) error {
			if opts.Language != lang || opts.AutoTLS {
				t.Fatal("options changed")
			}
			opts.OnReady()
			io.WriteString(out, "{\"event\":\"Copy\"}\n")
			return i18n.Errorf("load eBPF objects: %w", i18n.Errorf("not an ELF file"))
		})
		if code != 1 || stdout.String() != "{\"event\":\"Copy\"}\n" || !strings.HasPrefix(stderr.String(), "agentprov-sensor: ready\n") {
			t.Fatal("protocol changed")
		}
		want := "load eBPF objects: not an ELF file"
		if lang == i18n.Chinese {
			want = "加载 eBPF 对象失败：不是 ELF 文件"
		}
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("wrong error: %s", stderr.String())
		}
	}
}
