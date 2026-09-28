package launch

import (
	"strings"
	"testing"
)

func TestSensorReadinessDrainsLargeDiagnosticsWithBoundedTail(t *testing.T) {
	input := strings.Repeat(strings.Repeat("x", 10000)+"\n", 100) + "agentprov sensor stream: ready probes-attached\nlast failure\n"
	ready := make(chan struct{}, 1)
	var tail strings.Builder
	scanReady(strings.NewReader(input), ready, &tail)
	select {
	case <-ready:
	default:
		t.Fatal("ready banner lost after large diagnostic lines")
	}
	if tail.Len() > 73728 || lastLine(tail.String()) != "last failure" {
		t.Fatalf("unbounded/lost diagnostic tail: %d", tail.Len())
	}
}

func TestSensorAlreadyExitedIsNotAHealthyStop(t *testing.T) {
	done := make(chan struct{})
	close(done)
	s := sensorProcess{done: done}
	if s.stop() || s.stop() {
		t.Fatal("early sensor exit claimed complete coverage")
	}
}
