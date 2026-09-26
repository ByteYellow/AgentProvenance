package launch

import (
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

// message retains a format and its original arguments. It never tries to
// recover a format by matching a runtime path, command, or diagnostic string.
type message struct {
	source string
	args   []any
}

func messagef(source string, args ...any) message {
	return message{source: source, args: append([]any(nil), args...)}
}
func (m message) text(lang i18n.Locale) string {
	args := append([]any(nil), m.args...)
	for i, arg := range args {
		if err, ok := arg.(error); ok {
			args[i] = i18n.ErrorText(lang, err)
		}
	}
	if len(args) == 0 {
		return i18n.T(lang, m.source)
	}
	return fmt.Sprintf(i18n.T(lang, m.source), args...)
}
func (m message) original() string { return m.text(i18n.English) }
func (m message) orOriginal(lang i18n.Locale, original string) string {
	if m.source == "" {
		return original
	}
	return m.text(lang)
}
func makeCheck(name string, status CheckStatus, detail message, fix ...message) Check {
	c := Check{Name: name, Status: status, Detail: detail.original(), detail: detail}
	if len(fix) > 0 {
		c.fix = fix[0]
		c.Fix = fix[0].original()
	}
	return c
}
