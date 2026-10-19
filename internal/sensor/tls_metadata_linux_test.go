//go:build linux && (amd64 || arm64)

package sensor

import (
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/tlsintent"
)

func TestTLSMessageMapPreservesParsedMetadata(t *testing.T) {
	r := newCgroupResolver()
	r.byID[7] = "container-test"
	r.lastRefresh = time.Now()
	for _, dir := range []string{tlsintent.Request, tlsintent.Response} {
		msg := tlsintent.Message{
			PID: 42, Conn: 99, Direction: dir, Protocol: tlsintent.ProtoH2, StreamID: 3,
			Method: "POST", Path: "/v1/messages", Host: "api.example", Status: 200,
			Headers: map[string]string{"content-type": "text/event-stream", "authorization": "secret"},
			Body:    []byte(`{"model":"m"}`), Model: "m", Truncated: true,
		}
		got := tlsMessageMap(msg, sensorbpfSensorEvent{Pid: 42, CgroupId: 7}, r)
		if got["protocol"] != "h2" || got["stream_id"] != uint32(3) || got["content_type"] != "text/event-stream" || got["headers_decoded"] != true || got["truncated"] != true {
			t.Fatalf("metadata was lost: %#v", got)
		}
		if got["headers"] != nil || got["authorization"] != nil {
			t.Fatalf("arbitrary headers copied to sensor output: %#v", got)
		}
		if dir == tlsintent.Request && (got["method"] != "POST" || got["path"] != "/v1/messages" || got["host"] != "api.example") {
			t.Fatalf("request metadata: %#v", got)
		}
		if dir == tlsintent.Response && (got["status"] != 200 || got["method"] != nil) {
			t.Fatalf("response metadata: %#v", got)
		}
	}
}

func TestTLSMessageMapConnectionIdentity(t *testing.T) {
	r := newCgroupResolver()
	r.byID[7] = "container-test"
	r.lastRefresh = time.Now()
	msg := tlsintent.Message{PID: 42, ProcessStartNS: 100, Conn: 99, Epoch: 10, Protocol: tlsintent.ProtoH2, StreamID: 1, Direction: tlsintent.Request}
	e := sensorbpfSensorEvent{Pid: 42, CgroupId: 7, ProcessStartNs: 100}
	get := func() string {
		id, _ := tlsMessageMap(msg, e, r)["connection_id"].(string)
		return id
	}
	first := get()
	if len(first) != 71 || !strings.HasPrefix(first, "tls-v1:") {
		t.Fatalf("missing generation identity: %q", first)
	}
	msg.Direction, msg.StreamID = tlsintent.Response, 3
	if get() != first {
		t.Fatal("direction or stream changed the connection identity")
	}
	msg.Epoch++
	if get() == first {
		t.Fatal("SSL address reuse retained the old identity")
	}
	msg.Epoch = 0
	if get() != "" {
		t.Fatal("unknown lifecycle received a tracked identity")
	}
}
