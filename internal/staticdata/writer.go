// Package staticdata writes content-addressed, compressed public replay assets.
package staticdata

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Ref struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}
type Writer struct {
	Root  string
	Bytes int64
}

func (w *Writer) JSON(value any) (Ref, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return Ref{}, err
	}
	if len(data) > 64<<20 {
		return Ref{}, fmt.Errorf("replay asset exceeds 64 MiB; split this view before publishing")
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	ref := Ref{Path: "data/" + hash + ".json.gz", SHA256: hash, Bytes: len(data)}
	name := filepath.Join(w.Root, ref.Path)
	if _, err := os.Stat(name); err == nil {
		return ref, nil
	}
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		return Ref{}, err
	}
	f, err := os.Create(name)
	if err != nil {
		return Ref{}, err
	}
	z, _ := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if _, err = z.Write(data); err != nil {
		f.Close()
		return Ref{}, err
	}
	if err = z.Close(); err != nil {
		f.Close()
		return Ref{}, err
	}
	if err = f.Close(); err != nil {
		return Ref{}, err
	}
	info, err := os.Stat(name)
	if err != nil {
		return Ref{}, err
	}
	w.Bytes += info.Size()
	if w.Bytes > 900<<20 {
		return Ref{}, fmt.Errorf("static replay exceeds 900 MiB; split the public catalog")
	}
	return ref, nil
}
