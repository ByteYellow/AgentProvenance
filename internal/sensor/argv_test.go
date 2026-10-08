package sensor

import (
	"reflect"
	"strings"
	"testing"
)

func TestCapturedArgsReportsLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		limited bool
	}{
		{"empty", nil, false},
		{"complete", []string{"python3", "task.py", "--check"}, false},
		{"argument_boundary", []string{"python3", strings.Repeat("a", 31)}, true},
		{"argument_count", strings.Fields(strings.Repeat("a ", 16)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, 16*32)
			for i, arg := range tc.args {
				copy(buf[i*32:i*32+31], arg)
			}
			args, limited := capturedArgs(buf)
			if len(args) != len(tc.args) || len(args) > 0 && !reflect.DeepEqual(args, tc.args) || limited != tc.limited {
				t.Fatalf("argv=%v limited=%v", args, limited)
			}
			if got := joinArgs(buf); got != strings.Join(tc.args, " ") {
				t.Fatalf("legacy command changed: %q", got)
			}
		})
	}
}
