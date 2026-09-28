package agentcontext

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ParserVersion = "context-parser/v7"
	MaxInputBytes = 128 << 20
	MaxLineBytes  = 40 << 20
	MaxRecords    = 25000
)

type ParseOptions struct {
	Harness         string
	Path            string
	SessionID       string
	ParentSessionID string
	AgentID         string
	Binding         string
	BindingEvidence []string
	// AfterLine is a physical source cursor captured before a resumed execution.
	// Earlier records are retained as prior context, never current execution.
	AfterLine int64
	Cursor    *SourceCursor
	Budget    *ParseBudget
}

type Parsed struct {
	Source   Source
	Records  []Record
	Coverage Coverage
}

type row map[string]json.RawMessage

type parser struct {
	Parsed
	opts             ParseOptions
	line             int64
	objectOrdinal    int
	sourceOrdinal    int64
	callNames        map[string]string
	startedCalls     map[string]bool
	identityConflict bool
	unsupported      bool
	known            int64
	recordsCreated   int
	budgetLimited    bool
}

// Parse reads a bounded physical transcript without consulting current agent
// configuration. Diagnostics intentionally contain codes/positions, never input.
func Parse(ctx context.Context, r io.Reader, opts ParseOptions) (Parsed, error) {
	opts.Harness = canonicalHarness(opts.Harness)
	switch opts.Harness {
	case "claude", "codex", "kimi", "grok", "deepseek":
	default:
		return Parsed{}, fmt.Errorf("unsupported context harness %q", opts.Harness)
	}
	if opts.AfterLine < 0 {
		return Parsed{}, fmt.Errorf("invalid source cursor")
	}
	if opts.Budget != nil {
		if opts.Budget.InputBytes < 0 || opts.Budget.Records < 0 {
			return Parsed{}, fmt.Errorf("invalid capture budget")
		}
		r = captureBudgetReader{r: r, budget: opts.Budget}
	}
	var prefix *prefixReader
	if opts.Cursor != nil {
		if !opts.Cursor.Valid || opts.Cursor.Bytes < 0 || opts.Cursor.Bytes > MaxInputBytes || opts.Cursor.Lines != opts.AfterLine {
			return Parsed{}, fmt.Errorf("invalid source checkpoint")
		}
		prefix = &prefixReader{r: r, hash: sha256.New(), remaining: opts.Cursor.Bytes}
		r = prefix
	}
	p := parser{opts: opts, callNames: map[string]string{}, startedCalls: map[string]bool{}}
	if opts.Budget != nil {
		defer func() { opts.Budget.Records -= p.recordsCreated }()
	}
	p.Source = Source{Harness: opts.Harness, Path: opts.Path, SessionID: opts.SessionID,
		Channel:         "transcript",
		ParentSessionID: opts.ParentSessionID, AgentID: opts.AgentID, ParserVersion: ParserVersion,
		Binding: opts.Binding, BindingEvidence: opts.BindingEvidence}
	p.Coverage = Coverage{Status: Empty, FirstLine: opts.AfterLine + 1,
		Counts: processingCounts()}
	p.Coverage.Counts.Discovered = Number(1)
	if opts.AfterLine > 0 {
		p.Coverage.PriorContext = &PriorRange{FirstLine: 1, Counts: processingCounts()}
	}
	limited := &io.LimitedReader{R: r, N: MaxInputBytes + 1}
	reader := bufio.NewReaderSize(limited, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return Parsed{}, err
		}
		if p.recordLimit() == 0 {
			p.truncateInput(p.recordLimitCode())
			break
		}
		line, ended, err := readLine(reader)
		if errors.Is(err, errCaptureInputBudget) {
			p.truncateInput("capture_input_budget")
			break
		}
		if limited.N == 0 {
			p.issue("input_size_limit", "input")
			*p.counts().Truncated++
			break
		}
		if len(line) == 0 && errors.Is(err, io.EOF) {
			break
		}
		p.line++
		p.sourceOrdinal = 0
		p.Coverage.LastLine = p.line
		if p.line <= opts.AfterLine {
			p.Coverage.PriorContext.LastLine = p.line
		}
		*p.counts().Read++
		if errors.Is(err, errLineLimit) {
			p.issue("line_size_limit", "input")
			*p.counts().Truncated++
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			p.issue("read_failed", "input")
			*p.counts().Failed++
			break
		}
		line = bytes.TrimSpace(line)
		if !utf8.Valid(line) {
			p.issue("invalid_utf8", "input")
			*p.counts().Failed++
			if err != nil {
				break
			}
			continue
		}
		if len(line) == 0 {
			if err != nil {
				break
			}
			continue
		}
		if opts.Harness == "deepseek" && !ended {
			p.issue("incomplete_tail", "input")
			*p.counts().Deferred++
			break
		}
		knownBefore := p.known
		decodeErr := visitSourceObjects(line, opts.Harness, func(top row, raw []byte, ordinal int) bool {
			p.objectOrdinal = ordinal
			start := len(p.Records)
			known := p.consume(top)
			if !known && len(p.Records) == start && !p.unsupported {
				p.add("session", p.positionKey("unrecognized"), "", "", "", "unrecognized", eventTime(top), whole(top))
			}
			if known {
				p.known++
			} else {
				*p.counts().Unrecognized++
				p.issue("unrecognized_record", "type")
			}
			rawBody := string(raw)
			for i := start; i < len(p.Records); i++ {
				p.Records[i].RawBody = &rawBody
			}
			return !p.unsupported && len(p.Records) < p.recordLimit()
		})
		if p.known > knownBefore {
			*p.counts().Parsed++
		}
		if decodeErr != nil {
			if !ended && errors.Is(err, io.EOF) {
				p.issue("incomplete_tail", "input")
				*p.counts().Deferred++
			} else {
				p.issue("malformed_json", "input")
				*p.counts().Failed++
			}
		}
		if p.unsupported {
			break
		}
		if len(p.Records) >= p.recordLimit() {
			p.truncateInput(p.recordLimitCode())
			break
		}
		if err != nil {
			break
		}
	}
	if (opts.ParentSessionID != "" && p.Source.ParentSessionID != opts.ParentSessionID) ||
		(opts.AgentID != "" && p.Source.AgentID != opts.AgentID) {
		p.identityConflict = true
		p.issue("source_lineage_changed", "parent_session_id")
	}
	if p.identityConflict {
		p.Records = nil
		p.Source.Binding = "ambiguous"
		p.Coverage.Status = Ambiguous
		p.Coverage.Counts.Matched = Number(0)
	} else if p.unsupported {
		p.Records = nil
		p.Coverage.Status = Failed
	} else if p.budgetLimited {
		p.Coverage.Status = Partial
		if p.Source.SessionID == "" {
			p.Records = nil
			p.Coverage.Counts.Matched = Number(0)
		}
	} else if p.Source.SessionID == "" {
		p.Records = nil
		p.Coverage.Status = Ambiguous
		p.issue("session_identity_missing", "session_id")
		p.Coverage.Counts.Matched = Number(0)
	} else if len(p.Coverage.Issues) > 0 {
		p.Coverage.Status = Partial
		if p.known == 0 {
			p.Coverage.Status = Failed
		}
	} else if len(p.Records) > 0 && p.Records[len(p.Records)-1].ExecutionScope != PriorContext {
		p.Coverage.Status = OK
	}
	if p.Coverage.Counts.Matched == nil && p.Source.SessionID != "" {
		p.Coverage.Counts.Matched = Number(1)
	}
	if p.line < opts.AfterLine {
		p.Records = nil
		if !p.budgetLimited {
			p.Coverage.Status = Failed
			p.issue("source_cursor_out_of_range", "after_line")
		}
	}
	if prefix != nil && !prefix.matches(*opts.Cursor) {
		p.Records = nil
		p.Source.Binding = "ambiguous"
		p.Coverage.Status = Ambiguous
		p.Coverage.Counts.Matched = Number(0)
		if p.budgetLimited && prefix.remaining > 0 {
			p.issue("resume_checkpoint_unverified", "cursor")
		} else {
			p.issue("source_changed_before_resume", "cursor")
		}
	}
	if p.Coverage.Status == OK || p.Coverage.Status == Empty {
		p.Coverage.LastSuccessAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	p.Coverage.Source = p.Source
	var current, prior []Record
	for _, record := range p.Records {
		started, ended := &p.Coverage.StartedAt, &p.Coverage.EndedAt
		if record.ExecutionScope == PriorContext {
			prior = append(prior, record)
			started, ended = &p.Coverage.PriorContext.StartedAt, &p.Coverage.PriorContext.EndedAt
		} else {
			current = append(current, record)
		}
		t, err := time.Parse(time.RFC3339Nano, record.RecordedAt)
		if err != nil {
			continue
		}
		start, _ := time.Parse(time.RFC3339Nano, *started)
		end, _ := time.Parse(time.RFC3339Nano, *ended)
		if start.IsZero() || t.Before(start) {
			*started = record.RecordedAt
		}
		if end.IsZero() || t.After(end) {
			*ended = record.RecordedAt
		}
	}
	p.Coverage.MissingFields = missingSnapshots(p.Source.Harness, current)
	if p.Coverage.PriorContext != nil {
		p.Coverage.PriorContext.MissingFields = missingSnapshots(p.Source.Harness, prior)
	}
	return p.Parsed, nil
}

func (s Service) ImportFile(ctx context.Context, runID string, opts ParseOptions) (SaveResult, error) {
	f, err := os.Open(opts.Path)
	if err != nil {
		code, status := "input_unreadable", Failed
		if os.IsNotExist(err) {
			code, status = "input_not_found", NoInput
		}
		return s.Save(ctx, runID, Source{Harness: opts.Harness, Path: opts.Path,
			SessionID: opts.SessionID, Binding: opts.Binding, ParserVersion: ParserVersion}, nil,
			Coverage{Status: status, Issues: []Issue{{Code: code}}})
	}
	defer f.Close()
	r, closeReader, err := transcriptReader(f, opts.Path)
	if err != nil {
		return s.Save(ctx, runID, Source{Harness: opts.Harness, Path: opts.Path,
			SessionID: opts.SessionID, Binding: opts.Binding, ParserVersion: ParserVersion}, nil,
			Coverage{Status: Failed, Issues: []Issue{{Code: "decompression_failed"}}})
	}
	defer closeReader()
	parsed, err := Parse(ctx, r, opts)
	if err != nil {
		return SaveResult{}, err
	}
	return s.Save(ctx, runID, parsed.Source, parsed.Records, parsed.Coverage)
}

var errLineLimit = errors.New("source line limit")

func readLine(r *bufio.Reader) ([]byte, bool, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > MaxLineBytes {
			return nil, false, errLineLimit
		}
		line = append(line, part...)
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err == nil, err
		}
	}
}

func (p *parser) consume(top row) bool {
	switch p.opts.Harness {
	case "codex":
		return p.codex(top)
	case "claude":
		return p.claude(top)
	case "kimi":
		return p.kimi(top)
	case "grok":
		return p.grok(top)
	case "deepseek":
		return p.deepseek(top)
	}
	return false
}

func (p *parser) identify(id string) {
	if id == "" {
		return
	}
	if p.Source.SessionID != "" && p.Source.SessionID != id {
		p.identityConflict = true
		p.issue("session_identity_conflict", "session_id")
		return
	}
	p.Source.SessionID = id
}

func (p *parser) issue(code, field string) {
	if len(p.Coverage.Issues) < 100 {
		issue := Issue{Code: code, Line: p.line, Field: field}
		if p.line > 0 && p.line <= p.opts.AfterLine {
			issue.Scope = PriorContext
		}
		p.Coverage.Issues = append(p.Coverage.Issues, issue)
	}
}

func processingCounts() Counts {
	return Counts{Read: Number(0), Parsed: Number(0), Failed: Number(0),
		Unrecognized: Number(0), Truncated: Number(0), Deferred: Number(0)}
}

func (p *parser) counts() *Counts {
	if p.Coverage.PriorContext != nil && p.line <= p.opts.AfterLine {
		return &p.Coverage.PriorContext.Counts
	}
	return &p.Coverage.Counts
}

func (p *parser) add(kind, key, role, callID, name, status, timestamp string, body json.RawMessage) {
	if len(p.Records) >= p.recordLimit() {
		p.truncateInput(p.recordLimitCode())
		return
	}
	if key == "" {
		key = p.positionKey("line")
	}
	workdir, version := p.Source.Workdir, p.Source.ApplicationVersion
	p.sourceOrdinal++
	r := Record{Key: key, Sequence: p.line, SourceOrdinal: p.sourceOrdinal, Kind: kind, Role: role,
		ToolCallID: callID, ToolName: name, Status: status, RecordedAt: timestamp,
		Workdir: &workdir, ApplicationVersion: &version, ExecutionScope: CurrentExecution}
	if p.line <= p.opts.AfterLine {
		r.ExecutionScope = PriorContext
	}
	if name != "" && callID != "" {
		p.callNames[callID] = name
	}
	if kind == "tool_result" && name == "" {
		r.ToolName = p.callNames[callID]
	}
	if len(body) != 0 && string(body) != "null" {
		value := string(body)
		r.MediaType = "application/json"
		if json.Unmarshal(body, &value) == nil {
			r.MediaType = "text/plain"
		}
		r.Body = &value
	} else {
		r.MissingReason = "source_not_recorded"
	}
	if timestamp == "" {
		r.MissingFields = append(r.MissingFields, "timestamp")
	}
	if (kind == "tool_call" || kind == "tool_result") && callID == "" {
		r.MissingFields = append(r.MissingFields, "tool_call_id")
		p.issue("tool_identity_missing", "tool_call_id")
	}
	p.Records = append(p.Records, r)
	p.recordsCreated++
}

func obj(raw json.RawMessage) row { var o row; _ = json.Unmarshal(raw, &o); return o }
func text(o row, keys ...string) string {
	for _, key := range keys {
		var s string
		if json.Unmarshal(o[key], &s) == nil && s != "" {
			return s
		}
	}
	return ""
}
func flag(o row, key string) bool { var v bool; _ = json.Unmarshal(o[key], &v); return v }
func whole(o row) json.RawMessage { b, _ := json.Marshal(o); return b }
func content(o row, keys ...string) json.RawMessage {
	for _, key := range keys {
		if v, ok := o[key]; ok {
			return v
		}
	}
	return nil
}
func eventTime(o row) string {
	if s := text(o, "timestamp", "created_at", "_ts", "ts"); s != "" {
		return normalizedTime(s)
	}
	for _, key := range []string{"time", "ts", "createdAt"} {
		if n, err := strconv.ParseInt(string(o[key]), 10, 64); err == nil && n > 0 {
			return time.UnixMilli(n).UTC().Format(time.RFC3339Nano)
		}
	}
	return ""
}
func stableKey(prefix, id string, line int64) string {
	if id == "" {
		return fmt.Sprintf("%s:line:%d", prefix, line)
	}
	return prefix + ":" + id
}
func canonicalHarness(h string) string {
	switch strings.ToLower(h) {
	case "dsh", "deepseek-harness":
		return "deepseek"
	case "claude-code":
		return "claude"
	default:
		return strings.ToLower(h)
	}
}
