package provenance

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	tlsPairRule       = "agentprov.tls_connection_exchange/v2"
	tlsPairEdgePrefix = "tls-pair-v2-"
)

type tlsEvent struct {
	id, etype, payload, timestamp string
	at                            time.Time
	scope                         llmScope
	pid                           int64
	http                          tlsHTTPIdentity
	truncated                     bool
}

type tlsHTTPIdentity struct {
	ConnectionID   string `json:"connection_id,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	StreamID       uint32 `json:"stream_id,omitempty"`
	HeadersDecoded bool   `json:"headers_decoded,omitempty"`
	Method         string `json:"method,omitempty"`
	Status         int    `json:"status,omitempty"`
}

type tlsPairing struct {
	Status      string  `json:"status"`
	Reason      string  `json:"reason,omitempty"`
	Rule        string  `json:"rule"`
	Method      string  `json:"method,omitempty"`
	PeerEventID string  `json:"peer_event_id,omitempty"`
	Confidence  float64 `json:"confidence"`
}

type tlsPair struct{ request, response int }

func readTLSIdentity(r *tlsEvent) {
	data := []byte(r.payload)
	for depth := 0; depth < 4; depth++ {
		var body struct {
			HTTP      tlsHTTPIdentity `json:"http"`
			Truncated bool            `json:"truncated"`
			Payload   json.RawMessage `json:"payload"`
			Raw       json.RawMessage `json:"raw"`
		}
		if json.Unmarshal(data, &body) != nil {
			return
		}
		r.truncated = r.truncated || body.Truncated
		switch {
		case len(body.Payload) > 0:
			data = body.Payload
		case len(body.Raw) > 0:
			data = body.Raw
		default:
			r.http = body.HTTP
			return
		}
	}
}

func validTLSConnectionID(id string) bool {
	if len(id) != 71 || !strings.HasPrefix(id, "tls-v1:") {
		return false
	}
	_, err := hex.DecodeString(id[7:])
	return err == nil
}

// Read the saved run interval, never today's node counters. Known node loss or
// backlog invalidates the H1 serial inference; explicit H2 stream identities
// can still associate the complete messages that were actually saved.
func tlsCaptureGap(db contentObjectReader, runID string) (bool, error) {
	var ref string
	err := db.QueryRow(`SELECT hash FROM provenance_objects WHERE run_id=? AND object_type='runtime_capture'
		ORDER BY created_at DESC, hash DESC LIMIT 1`, runID).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var obj struct {
		Payload struct {
			SchemaVersion    string           `json:"schema_version"`
			RunID            string           `json:"run_id"`
			Issues           []string         `json:"issues"`
			NodeCounterDelta map[string]int64 `json:"node_counter_delta"`
		} `json:"payload"`
	}
	if err := readContentObject(db, runID, ref, &obj); err != nil {
		return false, err
	}
	if obj.Payload.SchemaVersion != "agentprovenance.runtime_capture/v1" || obj.Payload.RunID != runID {
		return false, fmt.Errorf("TLS pairing: runtime capture report identity mismatch")
	}
	for _, issue := range obj.Payload.Issues {
		switch issue {
		case "node_loss_during_capture", "node_backlog_at_seal", "node_processing_error", "node_counters_reset", "collector_exit_unconfirmed":
			return true, nil
		}
	}
	for _, name := range []string{"dropped_queue_full", "dropped_oversize", "dropped_partial_recovery", "dropped_partial_shutdown",
		"expired_uncorrelated", "invalid", "kernel_dropped_events", "tls_reassembly_dropped_streams", "tls_reassembly_dropped_bytes", "tls_truncated_messages"} {
		if obj.Payload.NodeCounterDelta[name] > 0 {
			return true, nil
		}
	}
	return false, nil
}

// Recompute over all saved messages, independent of ingestion order and old
// nearest-request edges. H1 has no stream ID: only a strictly alternating,
// complete serial exchange is inferred. A broken sequence invalidates the
// connection rather than shifting subsequent responses onto other requests.
func pairTLSMessages(events []tlsEvent, captureGap bool) ([]tlsPair, map[string]tlsPairing) {
	reports := make(map[string]tlsPairing, len(events))
	type connectionKey struct{ source, connection string }
	groups := map[connectionKey][]int{}
	set := func(indices []int, status, reason string) {
		for _, i := range indices {
			reports[events[i].id] = tlsPairing{Status: status, Reason: reason, Rule: tlsPairRule}
		}
	}
	for i, e := range events {
		reason := "peer_not_observed"
		switch {
		case !validTLSConnectionID(e.http.ConnectionID):
			reason = "missing_connection_identity"
		case e.scope.source == "":
			reason = "missing_capture_source"
		default:
			groups[connectionKey{e.scope.source, e.http.ConnectionID}] = append(groups[connectionKey{e.scope.source, e.http.ConnectionID}], i)
		}
		set([]int{i}, "unknown", reason)
	}
	var pairs []tlsPair
	match := func(req, resp int, method string, confidence float64) {
		pairs = append(pairs, tlsPair{req, resp})
		reports[events[req].id] = tlsPairing{Status: "matched", Rule: tlsPairRule, Method: method, PeerEventID: events[resp].id, Confidence: confidence}
		reports[events[resp].id] = tlsPairing{Status: "matched", Rule: tlsPairRule, Method: method, PeerEventID: events[req].id, Confidence: confidence}
	}
	for _, group := range groups {
		first := events[group[0]]
		protocol, invalid := first.http.Protocol, ""
		for _, i := range group {
			e := events[i]
			switch {
			case e.http.Protocol != protocol || (protocol != "h2" && protocol != "http/1.1" && protocol != "http/1.0"):
				invalid = "protocol_conflict"
			case e.pid <= 0 || e.pid != first.pid || !llmScopesMatch(first.scope, e.scope):
				invalid = "capture_scope_conflict"
			case e.at.IsZero():
				invalid = "invalid_capture_time"
			}
		}
		if invalid != "" {
			set(group, "unknown", invalid)
			continue
		}
		if protocol != "h2" && captureGap {
			set(group, "unknown", "capture_gap_during_run")
			continue
		}
		streams := map[uint32][]int{}
		for _, i := range group {
			e := events[i]
			if protocol == "h2" && (e.http.StreamID == 0 || e.http.StreamID > 0x7fffffff) {
				set([]int{i}, "unknown", "missing_stream_identity")
				continue
			}
			stream := uint32(0)
			if protocol == "h2" {
				stream = e.http.StreamID
			}
			streams[stream] = append(streams[stream], i)
		}
		for _, indices := range streams {
			var usable []int
			incomplete := false
			for _, i := range indices {
				e := events[i]
				if e.truncated || !e.http.HeadersDecoded ||
					(e.etype == "tls_write" && e.http.Method == "") ||
					(e.etype == "tls_read" && (e.http.Status < 100 || e.http.Status > 599 || e.http.Status == 101)) {
					incomplete = true
				}
				if e.etype == "tls_read" && e.http.Status >= 100 && e.http.Status < 200 && e.http.Status != 101 {
					set([]int{i}, "unknown", "informational_response")
					continue
				}
				usable = append(usable, i)
			}
			if incomplete {
				set(indices, "unknown", "incomplete_http_message")
				continue
			}
			if protocol == "h2" {
				var requests, responses []int
				for _, i := range usable {
					if events[i].etype == "tls_write" {
						requests = append(requests, i)
					} else {
						responses = append(responses, i)
					}
				}
				switch {
				case len(requests) > 1 || len(responses) > 1:
					set(usable, "ambiguous", "multiple_stream_candidates")
				case len(requests) == 1 && len(responses) == 1:
					if events[responses[0]].at.Before(events[requests[0]].at) {
						set(usable, "unknown", "response_precedes_request")
					} else {
						match(requests[0], responses[0], "http2_stream", 1)
					}
				}
				continue
			}
			if len(usable) < 2 {
				continue
			}
			sort.Slice(usable, func(i, j int) bool { return events[usable[i]].at.Before(events[usable[j]].at) })
			ambiguous := false
			for j, i := range usable {
				want := "tls_write"
				if j%2 == 1 {
					want = "tls_read"
				}
				if events[i].etype != want || (j > 0 && events[i].at.Equal(events[usable[j-1]].at)) {
					ambiguous = true
				}
			}
			if ambiguous {
				set(usable, "ambiguous", "http1_sequence_not_unique")
				continue
			}
			for j := 0; j+1 < len(usable); j += 2 {
				match(usable[j], usable[j+1], "http1_serial", 0.8)
			}
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return events[pairs[i].request].id < events[pairs[j].request].id })
	return pairs, reports
}
