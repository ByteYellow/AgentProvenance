package agentcontext

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Some Claude writers append complete objects without a newline separator.
// Only separators outside JSON may contain NUL padding. Never repair message
// bytes, join physical lines or scan past malformed input looking for a brace.
func visitSourceObjects(line []byte, harness string, visit func(row, []byte, int) bool) error {
	if harness != "claude" {
		var top row
		if err := json.Unmarshal(line, &top); err != nil {
			return err
		}
		if top == nil {
			return errors.New("source record is not an object")
		}
		visit(top, line, 1)
		return nil
	}
	for ordinal := 1; ; ordinal++ {
		line = bytes.TrimLeft(line, " \t\r\n\x00")
		if len(line) == 0 {
			return nil
		}
		var top row
		decoder := json.NewDecoder(bytes.NewReader(line))
		if err := decoder.Decode(&top); err != nil {
			return err
		}
		if top == nil {
			return errors.New("source record is not an object")
		}
		end := int(decoder.InputOffset())
		if !visit(top, line[:end], ordinal) {
			return nil
		}
		line = line[end:]
	}
}

func (p *parser) positionKey(prefix string) string {
	key := fmt.Sprintf("%s:%d", prefix, p.line)
	if p.objectOrdinal > 1 {
		key += fmt.Sprintf(":object:%d", p.objectOrdinal)
	}
	return key
}

func (p *parser) sourceKey(prefix, id string) string {
	if id != "" {
		return prefix + ":" + id
	}
	return p.positionKey(prefix + ":line")
}
