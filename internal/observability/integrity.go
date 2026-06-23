package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func digestObservation(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
