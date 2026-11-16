package agentcontext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// The receipt contract uses Python json.dumps(sort_keys=True, ensure_ascii=True,
// separators=(",", ":"), allow_nan=False), not Go's HTML-escaping JSON encoder.
// Receipt/input/result objects contain integers, never floating-point numbers.
func canonicalBrowserJSON(raw []byte) ([]byte, error) {
	if !nativeResultJSON(raw) {
		return nil, browserImportError("invalid_json")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, browserImportError("invalid_json")
	}
	var output bytes.Buffer
	quote := func(value string) {
		output.WriteByte('"')
		for _, char := range value {
			switch char {
			case '"', '\\':
				output.WriteByte('\\')
				output.WriteRune(char)
			case '\b':
				output.WriteString(`\b`)
			case '\f':
				output.WriteString(`\f`)
			case '\n':
				output.WriteString(`\n`)
			case '\r':
				output.WriteString(`\r`)
			case '\t':
				output.WriteString(`\t`)
			default:
				switch {
				case char < 32 || char > 127 && char <= 0xffff:
					fmt.Fprintf(&output, `\u%04x`, char)
				case char > 0xffff:
					hi, lo := utf16.EncodeRune(char)
					fmt.Fprintf(&output, `\u%04x\u%04x`, hi, lo)
				default:
					output.WriteRune(char)
				}
			}
		}
		output.WriteByte('"')
	}
	var write func(any) error
	write = func(value any) error {
		switch value := value.(type) {
		case nil:
			output.WriteString("null")
		case bool:
			output.WriteString(strconv.FormatBool(value))
		case string:
			quote(value)
		case json.Number:
			n, err := value.Int64()
			if err != nil {
				return browserImportError("noninteger_json_number")
			}
			output.WriteString(strconv.FormatInt(n, 10))
		case []any:
			output.WriteByte('[')
			for i, item := range value {
				if i > 0 {
					output.WriteByte(',')
				}
				if err := write(item); err != nil {
					return err
				}
			}
			output.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(value))
			for key := range value {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			output.WriteByte('{')
			for i, key := range keys {
				if i > 0 {
					output.WriteByte(',')
				}
				quote(key)
				output.WriteByte(':')
				if err := write(value[key]); err != nil {
					return err
				}
			}
			output.WriteByte('}')
		default:
			return browserImportError("unsupported_json_value")
		}
		return nil
	}
	if err := write(value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func browserValueDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", browserImportError("invalid_json")
	}
	canonical, err := canonicalBrowserJSON(raw)
	if err != nil {
		return "", err
	}
	return browserBytesDigest(canonical), nil
}
