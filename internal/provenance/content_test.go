package provenance

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestTextContentRedactsEscapedJSONWithoutChangingNumbers(t *testing.T) {
	s := contentTestStore(t)
	input := `{"key":"\u0073k-123456789012345678901234567890","password":"abcd\u0065f12345","count":9007199254740993}`
	stored, err := s.PutTextContent(TextContentInput{RunID: "run", SourceID: "raw", Text: input, MediaType: "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := ReadTextContentPage(s.DB, "run", stored.Ref, 0, 4096)
	if err != nil || !page.Redacted || !json.Valid([]byte(page.Content)) {
		t.Fatalf("page: %+v %v", page, err)
	}
	if strings.Contains(page.Content, "1234567890") || strings.Contains(page.Content, "abcdef") || !strings.Contains(page.Content, "9007199254740993") {
		t.Fatalf("unsafe content: %s", page.Content)
	}
	if err := VerifyTextContent(s.DB, "run", stored.Ref); err != nil {
		t.Fatal(err)
	}
}

func contentTestStore(t *testing.T) ObjectStore {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return ObjectStore{DB: db, Paths: paths}
}

func TestTextPagesPreserveUTF8AndTail(t *testing.T) {
	s := contentTestStore(t)
	// Multi-byte characters deliberately cross both chunk and page boundaries.
	body := strings.Repeat("\u4e2d\u6587-abcd\n", 30000) + "THE-END"
	ref, err := s.PutTextContent(TextContentInput{RunID: "run", SourceID: "source", Text: body})
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for offset := int64(0); ; {
		page, err := ReadTextContentPage(s.DB, "run", ref.Ref, offset, 701)
		if err != nil {
			t.Fatal(err)
		}
		if !utf8.ValidString(page.Content) {
			t.Fatal("split UTF-8 page")
		}
		out.WriteString(page.Content)
		if !page.HasMore {
			break
		}
		if page.NextOffset <= offset {
			t.Fatal("non-advancing page")
		}
		offset = page.NextOffset
	}
	if out.String() != body {
		t.Fatal("paged body differs")
	}
	if _, err := ReadTextContentPage(s.DB, "run", ref.Ref, 1, 100); err == nil {
		t.Fatal("mid-rune cursor accepted")
	}
}

func TestTextContentRejectsTamperedChunk(t *testing.T) {
	s := contentTestStore(t)
	ref, err := s.PutTextContent(TextContentInput{RunID: "run", SourceID: "source", Text: "original"})
	if err != nil {
		t.Fatal(err)
	}
	var path string
	if err := s.DB.QueryRow(`SELECT path FROM provenance_objects WHERE hash=?`, ref.Chunks[0].Ref).Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"payload":{"content":"changed"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTextContentPage(s.DB, "run", ref.Ref, 0, 100); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tamper err=%v", err)
	}
}

func TestTextContentEnforcesCaptureLimit(t *testing.T) {
	s := contentTestStore(t)
	if _, err := s.PutTextContent(TextContentInput{RunID: "run", SourceID: "source", Text: strings.Repeat("x", MaxTextContentBytes+1)}); err == nil {
		t.Fatal("oversized content accepted")
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("limit wrote objects: %d %v", count, err)
	}
}
