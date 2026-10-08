package agentcontext

import (
	"errors"
	"io"
)

// ParseBudget bounds a sequence of source imports, including decompressed input
// and records that are later rejected or deduplicated. It is not concurrency-safe.
// A nil budget keeps the normal per-source limits; zero means exhausted.
type ParseBudget struct {
	InputBytes int64
	Records    int
}

var errCaptureInputBudget = errors.New("capture input budget exhausted")

type captureBudgetReader struct {
	r      io.Reader
	budget *ParseBudget
}

func (r captureBudgetReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.budget.InputBytes <= 0 {
		return 0, errCaptureInputBudget
	}
	if int64(len(p)) > r.budget.InputBytes {
		p = p[:r.budget.InputBytes]
	}
	n, err := r.r.Read(p)
	r.budget.InputBytes -= int64(n)
	return n, err
}

func (p *parser) recordLimitCode() string {
	if p.opts.Budget != nil && p.opts.Budget.Records <= MaxRecords {
		return "capture_record_budget"
	}
	return "record_count_limit"
}

func (p *parser) recordLimit() int {
	if p.opts.Budget != nil {
		return min(MaxRecords, p.opts.Budget.Records)
	}
	return MaxRecords
}

func (p *parser) truncateInput(code string) {
	if code == "capture_input_budget" || code == "capture_record_budget" {
		p.budgetLimited = true
	}
	if *p.counts().Truncated == 0 {
		p.issue(code, "input")
		*p.counts().Truncated++
	}
}
