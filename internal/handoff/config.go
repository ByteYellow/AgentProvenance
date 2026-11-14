package handoff

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// Config is operator-owned. The existing daemon bearer credential authenticates
// this single trusted router; request bodies cannot select another principal.
type Config struct {
	Target Target `json:"target"`
	Caller struct {
		PrincipalID string `json:"principal_id"`
		ProducerID  string `json:"producer_id"`
		Namespace   string `json:"namespace"`
	} `json:"caller"`
	Concurrency int             `json:"concurrency"`
	Delivery    *DeliveryConfig `json:"delivery,omitempty"`
	Capture     *CaptureConfig  `json:"capture,omitempty"`
}

// CaptureConfig enables a shared native collector owned by the daemon, not by
// individual requests. Omitting it preserves the separate sensor deployment.
type CaptureConfig struct {
	Mode                  string   `json:"mode"`
	RingBufferMiB         int      `json:"ring_buffer_mib,omitempty"`
	TLSTargets            []string `json:"tls_targets,omitempty"`
	AutoTLS               *bool    `json:"auto_tls,omitempty"`
	AppArmorState         *bool    `json:"apparmor_state,omitempty"`
	SeccompState          *bool    `json:"seccomp_state,omitempty"`
	NoPolicy              bool     `json:"no_policy,omitempty"`
	StartupTimeoutSeconds int      `json:"startup_timeout_seconds,omitempty"`
	CloseTimeoutSeconds   int      `json:"close_timeout_seconds,omitempty"`
}

func (c *CaptureConfig) Validate() error {
	if c.Mode != "native" {
		return fmt.Errorf("execution capture mode must be native")
	}
	if c.RingBufferMiB == 0 {
		c.RingBufferMiB = 64
	}
	if c.StartupTimeoutSeconds == 0 {
		c.StartupTimeoutSeconds = 15
	}
	if c.CloseTimeoutSeconds == 0 {
		c.CloseTimeoutSeconds = 3
	}
	if c.RingBufferMiB < 1 || c.RingBufferMiB > 256 || c.RingBufferMiB&(c.RingBufferMiB-1) != 0 ||
		c.StartupTimeoutSeconds < 1 || c.StartupTimeoutSeconds > 120 || c.CloseTimeoutSeconds < 1 || c.CloseTimeoutSeconds > 30 || len(c.TLSTargets) > 128 {
		return fmt.Errorf("invalid execution capture limits: power-of-two ring 1..256 MiB, startup 1..120s, close 1..30s, at most 128 TLS targets")
	}
	for _, path := range c.TLSTargets {
		if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			return fmt.Errorf("execution capture TLS targets require absolute paths")
		}
	}
	return nil
}

type DeliveryConfig struct {
	ReceiverID            string `json:"receiver_id"`
	SignKeyFile           string `json:"sign_key_file"`
	ReceiverPublicKeyFile string `json:"receiver_public_key_file"`
	RetentionHours        int64  `json:"retention_hours,omitempty"`
}

func ReadConfig(r io.Reader) (Config, error) {
	var c Config
	limited := &io.LimitedReader{R: r, N: (64 << 10) + 1}
	d := json.NewDecoder(limited)
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("decode execution configuration: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("execution configuration must contain one JSON object")
	}
	if limited.N == 0 {
		return c, fmt.Errorf("execution configuration exceeds 64 KiB")
	}
	if !validID(c.Caller.PrincipalID) || !validID(c.Caller.ProducerID) || !validID(c.Caller.Namespace) || c.Target.Validate() != nil {
		return c, fmt.Errorf("execution configuration requires caller and target identities")
	}
	if c.Concurrency == 0 {
		c.Concurrency = 2
	}
	if c.Concurrency < 1 || c.Concurrency > 32 {
		return c, fmt.Errorf("execution concurrency must be between 1 and 32")
	}
	if c.Delivery != nil && (!validID(c.Delivery.ReceiverID) || c.Delivery.SignKeyFile == "" || c.Delivery.ReceiverPublicKeyFile == "") {
		return c, fmt.Errorf("delivery configuration requires receiver identity and key files")
	}
	if c.Delivery != nil && (c.Delivery.RetentionHours < 0 || c.Delivery.RetentionHours > int64((1<<63-1)/time.Hour)) {
		return c, fmt.Errorf("delivery retention_hours must be a nonnegative, representable duration")
	}
	if c.Capture != nil {
		if err := c.Capture.Validate(); err != nil {
			return c, err
		}
	}
	return c, nil
}

// DeliveryService resolves key paths relative to the operator's configuration.
// A missing or invalid key aborts startup instead of disabling verification.
func (c Config) DeliveryService(baseDir string, ledger Ledger, paths store.Paths) (*DeliveryService, error) {
	if c.Delivery == nil {
		return nil, nil
	}
	resolve := func(path string) string {
		if filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(baseDir, path)
	}
	key, err := attest.LoadPrivateKeyHex(resolve(c.Delivery.SignKeyFile))
	if err != nil {
		return nil, err
	}
	pub, err := attest.LoadPublicKeyHex(resolve(c.Delivery.ReceiverPublicKeyFile))
	if err != nil {
		return nil, err
	}
	if c.Delivery.RetentionHours < 0 || c.Delivery.RetentionHours > int64((1<<63-1)/time.Hour) {
		return nil, fmt.Errorf("invalid delivery retention_hours")
	}
	s := &DeliveryService{Ledger: ledger, Paths: paths, SignKey: key, ReceiverID: c.Delivery.ReceiverID, ReceiverKey: pub,
		Retention: time.Duration(c.Delivery.RetentionHours) * time.Hour}
	return s, s.validate()
}

func (c Config) Principal() Principal {
	return Principal{ID: c.Caller.PrincipalID, ProducerID: c.Caller.ProducerID,
		Namespace: c.Caller.Namespace, AllowedTargets: []Target{c.Target}}
}
