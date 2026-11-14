package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"mime"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	HARAttachmentSchema = "agentprovenance.har_attachment/v1"
	HARMediaType        = "application/har+json"
	MaxHAREntries       = 4096
)

// HAR retains a projected HTTP archive, not response bodies or a browser profile.
// Native identities remain independent from operation IDs and page titles.
type HAR struct {
	Log HARLog `json:"log"`
}
type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Meta    HARCapture `json:"_agentprovenance"`
	Entries []HAREntry `json:"entries"`
}
type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type HARCapture struct {
	Scope   map[string]string `json:"scope"`
	State   string            `json:"capture_state"`
	Omitted int64             `json:"omitted_entries"`
	Privacy string            `json:"privacy"`
	Timing  string            `json:"timing_policy"`
}
type HAREntry struct {
	Started  string      `json:"startedDateTime"`
	Time     float64     `json:"time"`
	Request  HARRequest  `json:"request"`
	Response HARResponse `json:"response"`
	Cache    struct{}    `json:"cache"`
	Timings  HARTimings  `json:"timings"`
	Native   HARNative   `json:"_agentprovenance"`
}

func (e *HAREntry) UnmarshalJSON(raw []byte) error {
	type plain HAREntry
	v := plain{Timings: HARTimings{-1, -1, -1, -1, -1, -1, -1}}
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	*e = HAREntry(v)
	return nil
}

type HARRequest struct {
	Method     string     `json:"method"`
	URL        string     `json:"url"`
	Version    string     `json:"httpVersion"`
	Cookies    []struct{} `json:"cookies"`
	Headers    []struct{} `json:"headers"`
	Query      []struct{} `json:"queryString"`
	HeaderSize int64      `json:"headersSize"`
	BodySize   int64      `json:"bodySize"`
}
type HARResponse struct {
	Status     int        `json:"status"`
	StatusText string     `json:"statusText"`
	Version    string     `json:"httpVersion"`
	Cookies    []struct{} `json:"cookies"`
	Headers    []struct{} `json:"headers"`
	Content    HARContent `json:"content"`
	Redirect   string     `json:"redirectURL"`
	HeaderSize int64      `json:"headersSize"`
	BodySize   int64      `json:"bodySize"`
}
type HARContent struct {
	Size int64  `json:"size"`
	MIME string `json:"mimeType"`
}
type HARTimings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	SSL     float64 `json:"ssl"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

func (t *HARTimings) UnmarshalJSON(raw []byte) error {
	type plain HARTimings
	v := plain{-1, -1, -1, -1, -1, -1, -1}
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	*t = HARTimings(v)
	return nil
}

type HARNative struct {
	Target       string   `json:"target_id"`
	TargetType   string   `json:"target_type"`
	Session      string   `json:"cdp_session_id"`
	Request      string   `json:"request_id"`
	Hop          int      `json:"redirect_index"`
	Frame        string   `json:"frame_id,omitempty"`
	Loader       string   `json:"loader_id,omitempty"`
	Outcome      string   `json:"outcome"`
	Duration     *float64 `json:"observed_duration_ms"`
	EncodedBytes *int64   `json:"encoded_bytes"`
}

func harID(s string) bool {
	return len(s) > 0 && len(s) <= 512 && s == strings.TrimSpace(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

func harURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || len(s) > 16384 || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return ""
	}
	u.User, u.Fragment, u.RawFragment = nil, "", ""
	if u.RawQuery != "" || u.ForceQuery {
		u.RawQuery, u.ForceQuery = "__redacted__", false
	}
	return u.String()
}

func harVersion(s string) string {
	switch s {
	case "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3":
		return s
	case "h2":
		return "HTTP/2"
	case "h3":
		return "HTTP/3"
	}
	return ""
}

// ProjectHAR is deliberately allowlisted: decoded unknown fields never enter
// chunks, even when an imported capture bypassed the local Python producer.
func ProjectHAR(ctx context.Context, data []byte) (HAR, []byte, error) {
	bad := func(reason string) (HAR, []byte, error) { return HAR{}, nil, &AttachmentError{Reason: reason} }
	if err := ctx.Err(); err != nil {
		return HAR{}, nil, err
	}
	if len(data) > MaxAttachmentBytes {
		return bad("attachment_size_limit")
	}
	var h HAR
	if json.Unmarshal(data, &h) != nil || h.Log.Version != "1.2" || h.Log.Entries == nil {
		return bad("invalid_har")
	}
	if len(h.Log.Entries) > MaxHAREntries {
		return bad("har_entry_limit")
	}
	if len(h.Log.Meta.Scope) != 6 {
		return bad("har_scope_invalid")
	}
	for _, key := range []string{"producer_id", "namespace", "instance_id", "generation", "browser_id", "context_id"} {
		if !harID(h.Log.Meta.Scope[key]) {
			return bad("har_scope_invalid")
		}
	}
	if (h.Log.Meta.State != "closed" && h.Log.Meta.State != "incomplete") || h.Log.Meta.Omitted < 0 {
		return bad("har_capture_invalid")
	}
	if h.Log.Meta.Omitted > 0 {
		h.Log.Meta.State = "incomplete"
	}
	h.Log.Creator = HARCreator{Name: "AgentProvenance", Version: "har_projection/v1"}
	h.Log.Meta.Privacy = "headers_cookies_query_bodies_omitted"
	h.Log.Meta.Timing = "sum_observed_phases; unknown=-1; duration=observed_duration_ms"
	seen := map[string]bool{}
	owners := map[string]string{}
	empty := []struct{}{}
	for i := range h.Log.Entries {
		if err := ctx.Err(); err != nil {
			return HAR{}, nil, err
		}
		e := &h.Log.Entries[i]
		n := &e.Native
		if !harID(n.Target) || !harID(n.Session) || !harID(n.Request) || n.Hop < 0 || n.Hop >= MaxHAREntries {
			return bad("har_identity_invalid")
		}
		if (n.Frame != "" && !harID(n.Frame)) || (n.Loader != "" && !harID(n.Loader)) {
			return bad("har_identity_invalid")
		}
		switch n.TargetType {
		case "page", "iframe", "worker", "service_worker":
		default:
			return bad("har_identity_invalid")
		}
		switch n.Outcome {
		case "pending", "finished", "failed", "redirected":
		default:
			return bad("har_outcome_invalid")
		}
		key, _ := json.Marshal([]any{n.Session, n.Request, n.Hop})
		if seen[string(key)] {
			return bad("har_identity_conflict")
		}
		seen[string(key)] = true
		owner := n.Target + "\x00" + n.TargetType
		if previous, ok := owners[n.Session]; ok && previous != owner {
			return bad("har_identity_conflict")
		}
		owners[n.Session] = owner
		t, err := time.Parse(time.RFC3339Nano, e.Started)
		if err != nil {
			return bad("har_time_invalid")
		}
		e.Started = t.UTC().Format(time.RFC3339Nano)
		e.Request.URL = harURL(e.Request.URL)
		if e.Request.URL == "" || len(e.Request.Method) == 0 || len(e.Request.Method) > 32 || strings.ContainsAny(e.Request.Method, " \t\r\n") {
			return bad("har_request_invalid")
		}
		e.Request.Version = harVersion(e.Request.Version)
		e.Request.Cookies, e.Request.Headers, e.Request.Query = empty, empty, empty
		e.Request.HeaderSize, e.Request.BodySize = -1, -1
		if e.Response.Status < 0 || e.Response.Status > 599 {
			return bad("har_response_invalid")
		}
		e.Response.Version, e.Response.StatusText = harVersion(e.Response.Version), ""
		e.Response.Cookies, e.Response.Headers = empty, empty
		e.Response.Redirect = harURL(e.Response.Redirect)
		e.Response.HeaderSize, e.Response.BodySize = -1, -1
		media, _, err := mime.ParseMediaType(e.Response.Content.MIME)
		if err != nil {
			media = ""
		}
		e.Response.Content = HARContent{Size: -1, MIME: media}
		e.Time = 0
		for _, timing := range []float64{e.Timings.Blocked, e.Timings.DNS, e.Timings.Connect, e.Timings.Send, e.Timings.Wait, e.Timings.Receive} {
			if math.IsNaN(timing) || math.IsInf(timing, 0) || timing < -1 || (timing < 0 && timing != -1) || timing > 1e12 {
				return bad("har_time_invalid")
			}
			if timing >= 0 {
				e.Time += timing
			}
		}
		if e.Timings.SSL < -1 || (e.Timings.SSL < 0 && e.Timings.SSL != -1) || e.Timings.SSL > 1e12 {
			return bad("har_time_invalid")
		}
		if n.Duration != nil && (*n.Duration < 0 || *n.Duration > 1e12) {
			return bad("har_time_invalid")
		}
		if n.EncodedBytes != nil && *n.EncodedBytes < 0 {
			return bad("har_size_invalid")
		}
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return bad("invalid_har")
	}
	if len(raw) > MaxAttachmentBytes {
		return bad("attachment_size_limit")
	}
	return h, raw, nil
}

func PrepareHARAttachment(ctx context.Context, data []byte) (PreparedAttachment, error) {
	_, raw, err := ProjectHAR(ctx, data)
	if err != nil {
		return PreparedAttachment{}, err
	}
	source, saved := sha256.Sum256(data), sha256.Sum256(raw)
	m := AttachmentManifest{SchemaVersion: HARAttachmentSchema, MediaType: HARMediaType, Bytes: int64(len(raw)), SHA256: hex.EncodeToString(saved[:]),
		SourceMediaType: HARMediaType, SourceBytes: int64(len(data)), SourceSHA256: hex.EncodeToString(source[:]),
		Transformation: "har_projection/v1", Privacy: "headers_cookies_query_bodies_omitted", Chunks: []TextChunk{}}
	return PreparedAttachment{manifest: m, data: raw}, nil
}

func verifyHAR(ctx context.Context, data []byte) error {
	_, projected, err := ProjectHAR(ctx, data)
	if err == nil && !bytes.Equal(projected, data) {
		return &AttachmentError{Reason: "har_projection_mismatch"}
	}
	return err
}
