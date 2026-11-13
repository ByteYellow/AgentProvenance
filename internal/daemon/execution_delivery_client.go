package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/handoff"
)

const maxDeliveryResponseBytes = 256 << 10

func (c Client) PrepareExecutionDelivery(ctx context.Context, attempt, operation string) (ExecutionDeliveryResponse, error) {
	var out ExecutionDeliveryResponse
	raw, err := json.Marshal(map[string]string{"operation_id": operation})
	if err != nil {
		return out, err
	}
	err = c.deliveryJSON(ctx, http.MethodPost, "/v1/executions/"+url.PathEscape(attempt)+"/deliveries", raw, &out)
	return out, err
}

func (c Client) ExecutionDelivery(ctx context.Context, id string) (ExecutionDeliveryResponse, error) {
	var out ExecutionDeliveryResponse
	err := c.deliveryJSON(ctx, http.MethodGet, "/v1/execution-deliveries/"+url.PathEscape(id), nil, &out)
	return out, err
}

func (c Client) AcknowledgeExecutionDelivery(ctx context.Context, id string, receipt []byte) (ExecutionDeliveryResponse, error) {
	var out ExecutionDeliveryResponse
	if len(receipt) > handoff.MaxEnvelopeBytes {
		return out, handoff.ErrInvalid
	}
	err := c.deliveryJSON(ctx, http.MethodPost, "/v1/execution-deliveries/"+url.PathEscape(id)+"/receipt", receipt, &out)
	return out, err
}

type ExecutionCollection struct {
	SchemaVersion  string          `json:"schema_version"`
	DeliveryID     string          `json:"delivery_id"`
	LocalRunID     string          `json:"local_run_id"`
	ManifestSHA256 string          `json:"manifest_sha256"`
	BundleSHA256   string          `json:"bundle_sha256"`
	Status         string          `json:"status"`
	Receipt        json.RawMessage `json:"receipt,omitempty"`
}

// CollectExecution verifies and persists before acknowledging the sender. The
// stable operation and independently saved admission make retries restartable.
func (c Client) CollectExecution(ctx context.Context, expected handoff.ExecutionIdentity, operation string, receiver *handoff.DeliveryReceiver) (ExecutionCollection, error) {
	out := ExecutionCollection{SchemaVersion: handoff.DeliverySchema, LocalRunID: expected.LocalRunID, Status: "pending"}
	if receiver == nil {
		return out, handoff.ErrInvalid
	}
	prepared, err := c.PrepareExecutionDelivery(ctx, expected.AttemptID, operation)
	if err != nil {
		return out, err
	}
	manifest, err := receiver.VerifyManifest(expected, prepared.Delivery.Envelope)
	if err != nil {
		return out, err
	}
	out.DeliveryID, out.BundleSHA256 = manifest.ID, manifest.BundleSHA256
	out.ManifestSHA256 = attest.DigestSHA256(prepared.Delivery.Envelope)
	response, err := c.deliveryHTTP(ctx, http.MethodGet, "/v1/execution-deliveries/"+url.PathEscape(manifest.ID)+"/bundle", nil)
	if err != nil {
		return out, err
	}
	defer response.Body.Close()
	if response.ContentLength >= 0 && response.ContentLength != manifest.BundleBytes {
		return out, fmt.Errorf("execution delivery content length mismatch")
	}
	receipt, err := receiver.Receive(ctx, expected, prepared.Delivery.Envelope, response.Body)
	if err != nil {
		return out, err
	}
	out.Status, out.Receipt = "receipt_persisted", receipt
	ack, err := c.AcknowledgeExecutionDelivery(ctx, manifest.ID, receipt)
	if err != nil {
		return out, err
	}
	if ack.Delivery.ManifestSHA256 != out.ManifestSHA256 || !bytes.Equal(ack.Delivery.Receipt, receipt) {
		return out, fmt.Errorf("execution delivery acknowledgment mismatch")
	}
	out.Status = "acknowledged"
	return out, nil
}

func (c Client) deliveryJSON(ctx context.Context, method, path string, raw []byte, out *ExecutionDeliveryResponse) error {
	r, err := c.deliveryHTTP(ctx, method, path, raw)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDeliveryResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxDeliveryResponseBytes {
		return fmt.Errorf("execution delivery response exceeds limit")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return err
	}
	if out.SchemaVersion != handoff.DeliverySchema {
		return fmt.Errorf("unsupported execution delivery response")
	}
	return nil
}

func (c Client) deliveryHTTP(ctx context.Context, method, path string, raw []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.authorize(req)
	client := http.Client{Timeout: executionTransferTimeout}
	if c.HTTP != nil {
		client = *c.HTTP
		if client.Timeout <= 0 || client.Timeout > executionTransferTimeout {
			client.Timeout = executionTransferTimeout
		}
	}
	// The configured endpoint is the sole transport authority. Never replay a
	// signed receipt or forward bearer credentials to a redirected destination.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var result struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result)
		if result.Error == "" {
			result.Error = resp.Status
		}
		return nil, fmt.Errorf("execution delivery: %s", result.Error)
	}
	return resp, nil
}
