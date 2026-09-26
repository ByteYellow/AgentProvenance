package i18n

import (
	"regexp"
	"sort"
	"strings"
)

// DiagnosticCatalog translates a bounded set of application-owned diagnostic
// formats after a JSON round trip has discarded their original error types.
// It must only receive diagnostic fields, never evidence bodies or file names.
// Captured values retain their exact spelling; only error placeholders recurse.
type DiagnosticCatalog struct{ formats []diagnosticFormat }

type diagnosticFormat struct {
	source        string
	match         *regexp.Regexp
	verbs         []string
	literalLength int
}

var diagnosticVerb = regexp.MustCompile(`%(?:#x|[sdqwv])`)

func NewDiagnosticCatalog(sources ...string) DiagnosticCatalog {
	var result DiagnosticCatalog
	for _, source := range sources {
		positions := diagnosticVerb.FindAllStringIndex(source, -1)
		var expression strings.Builder
		expression.WriteString(`(?s)^`)
		format := diagnosticFormat{source: source}
		last := 0
		for _, position := range positions {
			literal := source[last:position[0]]
			expression.WriteString(regexp.QuoteMeta(literal))
			format.literalLength += len(literal)
			verb := source[position[0]:position[1]]
			format.verbs = append(format.verbs, verb)
			switch verb {
			case "%d":
				expression.WriteString(`(-?[0-9]+)`)
			case "%#x":
				expression.WriteString(`(0x[0-9a-fA-F]+)`)
			case "%q":
				expression.WriteString(`("(?:\\.|[^"\\])*")`)
			default:
				expression.WriteString(`(.*?)`)
			}
			last = position[1]
		}
		expression.WriteString(regexp.QuoteMeta(source[last:]))
		format.literalLength += len(source[last:])
		expression.WriteString(`$`)
		// A catch-all such as "%s" must never reinterpret arbitrary text.
		if format.literalLength == 0 {
			continue
		}
		format.match = regexp.MustCompile(expression.String())
		result.formats = append(result.formats, format)
	}
	// More specific diagnostics win over generic enclosing errors.
	sort.SliceStable(result.formats, func(i, j int) bool {
		return result.formats[i].literalLength > result.formats[j].literalLength
	})
	return result
}

func (c DiagnosticCatalog) Text(lang Locale, message string) string {
	return c.text(lang, message, 0)
}

func (c DiagnosticCatalog) text(lang Locale, message string, depth int) string {
	if lang != Chinese || depth >= 8 || len(message) > 16<<10 {
		return message
	}
	for _, format := range c.formats {
		values := format.match.FindStringSubmatch(message)
		if values == nil {
			continue
		}
		translation := T(lang, format.source)
		verbs := diagnosticVerb.FindAllString(translation, -1)
		if len(verbs) != len(format.verbs) {
			return message
		}
		for i, verb := range verbs {
			if verb != format.verbs[i] {
				return message
			}
		}
		index := 0
		return diagnosticVerb.ReplaceAllStringFunc(translation, func(_ string) string {
			index++
			if index >= len(values) {
				return ""
			}
			value := values[index]
			if format.verbs[index-1] == "%w" || format.verbs[index-1] == "%v" {
				value = c.text(lang, value, depth+1)
			}
			return value
		})
	}
	return message
}
