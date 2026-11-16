package browserlink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// encoding/json accepts duplicate keys and case-folded field aliases. Reject
// both before reading a wire view, including in fields the view does not use.
func decodeRecord(raw []byte, out any) error {
	if len(raw) > MaxRecordBytes {
		return fmt.Errorf("browser record exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("browser record nesting exceeds limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok {
					return fmt.Errorf("invalid JSON key")
				}
				key = strings.ToLower(key)
				if seen[key] {
					return fmt.Errorf("duplicate JSON key")
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return json.Unmarshal(raw, out)
}
