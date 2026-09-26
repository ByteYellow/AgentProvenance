package i18n

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPersistedDiagnosticsKeepOpaqueValues(t *testing.T) {
	tests := []struct{ source, want string }{
		{"remove memlock: failed to set memlock rlimit: operation not permitted", "解除锁定内存限制失败：设置锁定内存限制失败：权限不足（operation not permitted）"},
		{"attach Go TLS Read return +0x12: not an ELF file", "挂载 Go TLS Read 返回点 +0x12 失败：不是 ELF 文件"},
		{`native capture file /tmp/Copy/ready is missing; captured evidence cannot be recovered`, `原生采集文件 /tmp/Copy/ready 缺失，无法恢复其中的证据`},
		{`unsupported Go TLS Read ABI "go1.27\"Copy" (supported: Go 1.23–1.26 amd64 ABIInternal)`, `不支持 Go TLS Read ABI "go1.27\"Copy"，支持 Go 1.23–1.26 amd64 ABIInternal`},
		{`load eBPF objects: third-party verifier diagnostic`, `加载 eBPF 对象失败：third-party verifier diagnostic`},
		{`invalid value "Copy" for flag -tls-max-targets: parse error`, `选项值 "Copy" 无效，选项为 -tls-max-targets：无法解析`},
	}
	for _, tt := range tests {
		if got := RuntimeDiagnostics.Text(Chinese, tt.source); got != tt.want {
			t.Errorf("got %q want %q", got, tt.want)
		}
		if got := RuntimeDiagnostics.Text(English, tt.source); got != tt.source {
			t.Errorf("English changed: %s", got)
		}
	}
	for _, source := range []string{"Copy", "some prefix: not an ELF file", "not an ELF file plus suffix", strings.Repeat("attach x: ", 20) + "not an ELF file"} {
		got := RuntimeDiagnostics.Text(Chinese, source)
		if strings.HasPrefix(source, "attach ") {
			if !strings.Contains(got, "not an ELF file") {
				t.Fatal("recursion was not bounded")
			}
			continue
		}
		if got != source {
			t.Errorf("rewrote unknown message: %q", got)
		}
	}
	if got := NewDiagnosticCatalog("%s").Text(Chinese, "Copy"); got != "Copy" {
		t.Fatal("catch-all changed arbitrary text")
	}
}

func TestRuntimeDiagnosticFormatsHaveMatchingCopy(t *testing.T) {
	for _, format := range RuntimeDiagnostics.formats {
		if !HasChinese(format.source) {
			t.Errorf("missing copy: %s", format.source)
		}
		if strings.Join(format.verbs, ",") != strings.Join(diagnosticVerb.FindAllString(T(Chinese, format.source), -1), ",") {
			t.Errorf("changed placeholders: %s", format.source)
		}
	}
	// Both live typed errors and JSON-decoded diagnostics render identically.
	leaf := errors.New("external: /tmp/Copy")
	err := Errorf("attach %s: %w", "probe", Errorf("load eBPF objects: %w", leaf))
	if !errors.Is(err, leaf) {
		t.Fatal("lost error chain")
	}
	if got, want := RuntimeDiagnostics.Text(Chinese, err.Error()), ErrorText(Chinese, err); got != want {
		t.Fatalf("persisted %q != live %q", got, want)
	}
	if err.Error() != fmt.Sprintf("attach probe: load eBPF objects: %s", leaf) {
		t.Fatal("original changed")
	}
}
