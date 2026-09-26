package i18n

import (
	"errors"
	"io/fs"
	"testing"
)

func TestErrorTranslationPreservesOriginalAndUnwrapping(t *testing.T) {
	underlying := &fs.PathError{Op: "open", Path: "/tmp/Copy", Err: fs.ErrNotExist}
	err := Errorf("open guide: %w", underlying)
	// A fixture-specific catalog entry is unnecessary; untranslated formats
	// still exercise error wrapping and the external diagnostic boundary.
	for _, lang := range []Locale{English, Chinese} {
		if got := ErrorText(lang, err); got != "open guide: "+underlying.Error() {
			t.Fatalf("changed diagnostic: %s", got)
		}
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("lost error identity")
	}
	var target *fs.PathError
	if !errors.As(err, &target) || target != underlying {
		t.Fatal("lost typed error")
	}
	if err.Error() != "open guide: "+underlying.Error() {
		t.Fatal("changed stored error")
	}
}

func TestErrorTranslationChangesOnlyMarkedMessage(t *testing.T) {
	err := Errorf("status: %s", "Copy")
	if got := ErrorText(Chinese, err); got != "状态：Copy" {
		t.Fatalf("wrong translation: %s", got)
	}
	if err.Error() != "status: Copy" {
		t.Fatal("changed original error")
	}
	if got := ErrorText(Chinese, errors.New("status: Copy")); got != "status: Copy" {
		t.Fatalf("rewrote unmarked data: %s", got)
	}
}
