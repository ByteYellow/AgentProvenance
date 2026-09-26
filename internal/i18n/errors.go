package i18n

import "fmt"

// messageError keeps the original diagnostic for storage, JSON, errors.Is/As and
// programmatic callers. Translation happens only at a human-facing boundary.
type messageError struct {
	source   string
	args     []any
	original error
}

func Errorf(source string, args ...any) error {
	return &messageError{source: source, args: append([]any(nil), args...), original: fmt.Errorf(source, args...)}
}
func (e *messageError) Error() string { return e.original.Error() }
func (e *messageError) Unwrap() error { return e.original }

// ErrorText translates tagged application errors. Unrecognized external errors
// retain their original diagnostic, instead of rewriting arbitrary paths/text.
func ErrorText(lang Locale, err error) string {
	if err == nil {
		return ""
	}
	if lang == English {
		return err.Error()
	}
	if message, ok := err.(*messageError); ok {
		args := append([]any(nil), message.args...)
		for i, arg := range args {
			if cause, ok := arg.(error); ok {
				args[i] = displayError{ErrorText(lang, cause)}
			}
		}
		return fmt.Errorf(T(lang, message.source), args...).Error()
	}
	return err.Error()
}

type displayError struct{ text string }

func (e displayError) Error() string { return e.text }
