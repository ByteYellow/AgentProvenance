package provenance

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const cursorVersion = 1

type cursorToken struct {
	Version int            `json:"v"`
	Kind    string         `json:"kind"`
	Data    map[string]any `json:"data"`
}

func encodeCursor(kind string, data map[string]any) (string, error) {
	raw, err := json.Marshal(cursorToken{Version: cursorVersion, Kind: kind, Data: data})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeCursor(kind, token string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid %s cursor", kind)
	}
	var decoded cursorToken
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("invalid %s cursor", kind)
	}
	if decoded.Version != cursorVersion || decoded.Kind != kind || decoded.Data == nil {
		return nil, fmt.Errorf("invalid %s cursor", kind)
	}
	return decoded.Data, nil
}

func cursorString(data map[string]any, key string) (string, error) {
	value, ok := data[key].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("invalid cursor")
	}
	return value, nil
}

func cursorInt(data map[string]any, key string) (int, error) {
	value, ok := data[key].(float64)
	if !ok || value < 0 || value != float64(int(value)) {
		return 0, fmt.Errorf("invalid cursor")
	}
	return int(value), nil
}

func stableDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
