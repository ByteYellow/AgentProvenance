//go:build linux && (amd64 || arm64)

package sensor

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestSensorDecoderMatchesKernelLayout(t *testing.T) {
	if binary.Size(sensorbpfSensorEvent{}) != sensorEventBytes {
		t.Fatal("kernel event layout changed; update decoder")
	}
	rng := rand.New(rand.NewSource(19))
	for i := 0; i < 100; i++ {
		raw := make([]byte, sensorEventBytes)
		rng.Read(raw)
		var want sensorbpfSensorEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &want); err != nil {
			t.Fatal(err)
		}
		got, err := decodeSensorEvent(raw)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("record %d: got=%+v want=%+v err=%v", i, got, want, err)
		}
	}
	for _, n := range []int{0, sensorEventBytes - 1, sensorEventBytes + 1} {
		if _, err := decodeSensorEvent(make([]byte, n)); err == nil {
			t.Fatalf("accepted malformed record size %d", n)
		}
	}
}
func BenchmarkSensorDecode(b *testing.B) {
	raw := make([]byte, sensorEventBytes)
	b.Run("reflection", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var e sensorbpfSensorEvent
			_ = binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e)
		}
	})
	b.Run("bounded", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = decodeSensorEvent(raw)
		}
	})
}

func TestSensorRejectsInvalidBufferBudgetBeforeLoading(t *testing.T) {
	for _, mib := range []int{-1, 3, 255, 257} {
		if err := RunWithOptions(io.Discard, Options{RingBufferMiB: mib}); err == nil || !strings.Contains(err.Error(), "ring-buffer-mib") {
			t.Fatalf("budget %d: %v", mib, err)
		}
	}
}
