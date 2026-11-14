package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/byteyellow/agentprovenance/internal/handoff"
)

func (c Client) SubmitExecution(ctx context.Context, request handoff.Request) (ExecutionAdmission, error) {
	var result ExecutionAdmission
	err := c.executionJSON(ctx, http.MethodPost, "/v1/executions", request, &result)
	return result, err
}

func (c Client) Execution(ctx context.Context, id string) (handoff.Report, error) {
	var result handoff.Report
	err := c.executionJSON(ctx, http.MethodGet, "/v1/executions/"+url.PathEscape(id), nil, &result)
	return result, err
}

func (c Client) Executions(ctx context.Context, source handoff.Source, after int64, limit int) (handoff.Page, error) {
	var result handoff.Page
	q := url.Values{"run": {source.RunID}, "harness": {source.Harness}, "session": {source.SessionID},
		"tool_call": {source.ToolCallID}, "after": {fmt.Sprint(after)}, "limit": {fmt.Sprint(limit)}}
	err := c.executionJSON(ctx, http.MethodGet, "/v1/executions?"+q.Encode(), nil, &result)
	return result, err
}

func (c Client) ExecutionLinks(ctx context.Context, opts handoff.ExecutionLinksOptions) (handoff.ExecutionLinksPage, error) {
	var result handoff.ExecutionLinksPage
	q := url.Values{"run": {opts.RunID}, "direction": {opts.Direction}, "harness": {opts.Harness},
		"session": {opts.SessionID}, "tool_call": {opts.ToolCallID}, "cursor": {opts.Cursor}}
	if opts.Limit != 0 {
		q.Set("limit", fmt.Sprint(opts.Limit))
	}
	err := c.executionJSON(ctx, http.MethodGet, "/v1/execution-links?"+q.Encode(), nil, &result)
	return result, err
}

func (c Client) StopExecution(ctx context.Context, id, operation string) (handoff.StopReceipt, error) {
	var result handoff.StopReceipt
	err := c.executionJSON(ctx, http.MethodPost, "/v1/executions/"+url.PathEscape(id)+"/stop",
		map[string]string{"operation_id": operation}, &result)
	return result, err
}

func (c Client) executionJSON(ctx context.Context, method, path string, input, output any) error {
	var raw []byte
	var err error
	if input != nil {
		raw, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return c.do(r, output)
}
