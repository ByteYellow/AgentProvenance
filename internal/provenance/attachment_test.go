package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/rand"
	"strings"
	"testing"
)

func rasterFixture(t *testing.T, large bool) []byte {
	t.Helper()
	n := 9
	if large {
		n = 400
	}
	im := image.NewNRGBA(image.Rect(0, 0, n, n))
	r := rand.New(rand.NewSource(42))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			im.SetNRGBA(x, y, color.NRGBA{uint8(r.Intn(256)), uint8(r.Intn(256)), uint8(r.Intn(256)), 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, im); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestRasterAttachmentPagingAndPortableVerification(t *testing.T) {
	s := contentTestStore(t)
	ctx := context.Background()
	source := append(rasterFixture(t, true), []byte("password=not-retained-source-metadata")...)
	p, err := PrepareRasterAttachment(ctx, "image/png", source)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.PutAttachment(ctx, "run", p)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Chunks) < 2 || a.SourceSHA256 == a.SHA256 || a.Transformation != "raster_reencode/v1" {
		t.Fatalf("bad manifest: %+v", a)
	}
	var full bytes.Buffer
	for at := int64(0); ; {
		page, err := ReadAttachmentPage(ctx, s.DB, "run", a.Ref, at, 7193)
		if err != nil {
			t.Fatal(err)
		}
		full.Write(page.Data)
		if !page.HasMore {
			break
		}
		if page.NextOffset <= at {
			t.Fatal("page stalled")
		}
		at = page.NextOffset
	}
	sum := sha256.Sum256(full.Bytes())
	if hex.EncodeToString(sum[:]) != a.SHA256 || bytes.Contains(full.Bytes(), []byte("not-retained")) {
		t.Fatal("wrong derived image bytes")
	}
	if err := VerifyAttachment(ctx, s.DB, "run", a.Ref); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAttachmentPage(ctx, s.DB, "other", a.Ref, 0, 4); err == nil {
		t.Fatal("cross-run read")
	}
	for _, r := range [][2]int64{{-1, 1}, {0, 0}, {a.Bytes + 1, 1}, {0, MaxContentPageBytes + 1}} {
		if _, err := ReadAttachmentPage(ctx, s.DB, "run", a.Ref, r[0], r[1]); !errors.Is(err, ErrContentRange) {
			t.Fatal("invalid range accepted", r, err)
		}
	}
	bad := a.AttachmentManifest
	bad.SHA256 = strings.Repeat("0", 64)
	parents := []string{}
	for _, c := range bad.Chunks {
		parents = append(parents, c.Ref)
	}
	obj, err := s.PutExternalObject(ExternalObjectInput{Type: "attachment_content", RunID: "run", SourceID: "bad", Parents: parents,
		Payload: map[string]any{"kind": "stored_raster", "attachment_manifest": bad}})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttachment(ctx, s.DB, "run", obj.Hash); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	verified, err := Verify(s.DB, "run")
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, verified, "attachment_content_invalid")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := ReadAttachmentPage(cancelled, s.DB, "run", a.Ref, 0, 5); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRasterAttachmentTypeAndSize(t *testing.T) {
	ctx := context.Background()
	im := image.NewGray(image.Rect(0, 0, 8193, 1))
	var wide bytes.Buffer
	_ = png.Encode(&wide, im)
	for _, test := range []struct {
		media  string
		data   []byte
		reason string
	}{
		{"image/svg+xml", []byte(`<svg onload="fetch('https://invalid.example')"/>`), "unsupported_media_type"},
		{"image/png", []byte("<html>not an image</html>"), "invalid_image"},
		{"image/jpeg", rasterFixture(t, false), "invalid_image"},
		{"image/png", make([]byte, MaxAttachmentBytes+1), "attachment_size_limit"},
		{"image/png", wide.Bytes(), "attachment_pixel_limit"},
	} {
		_, err := PrepareRasterAttachment(ctx, test.media, test.data)
		var invalid *AttachmentError
		if !errors.As(err, &invalid) || invalid.Reason != test.reason {
			t.Fatalf("got %v, want %s", err, test.reason)
		}
	}
	var jpg bytes.Buffer
	_ = jpeg.Encode(&jpg, image.NewGray(image.Rect(0, 0, 4, 3)), nil)
	p, err := PrepareRasterAttachment(ctx, "image/jpeg", jpg.Bytes())
	if err != nil || p.Manifest().MediaType != "image/png" || p.Manifest().SourceMediaType != "image/jpeg" {
		t.Fatalf("JPEG: %+v %v", p.Manifest(), err)
	}
	s := contentTestStore(t)
	a, err := s.PutAttachment(ctx, "run", p)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttachment(ctx, s.DB, "run", a.Ref); err != nil {
		t.Fatal(err)
	}
}
