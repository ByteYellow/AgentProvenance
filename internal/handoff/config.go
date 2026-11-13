package handoff

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

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
}

type DeliveryConfig struct {
	ReceiverID            string `json:"receiver_id"`
	SignKeyFile           string `json:"sign_key_file"`
	ReceiverPublicKeyFile string `json:"receiver_public_key_file"`
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
	s := &DeliveryService{Ledger: ledger, Paths: paths, SignKey: key, ReceiverID: c.Delivery.ReceiverID, ReceiverKey: pub}
	return s, s.validate()
}

func (c Config) Principal() Principal {
	return Principal{ID: c.Caller.PrincipalID, ProducerID: c.Caller.ProducerID,
		Namespace: c.Caller.Namespace, AllowedTargets: []Target{c.Target}}
}
