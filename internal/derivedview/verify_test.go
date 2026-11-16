package derivedview

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
)

func fixture(t testing.TB) (fstest.MapFS, Manifest, ed25519.PrivateKey, TrustPolicy) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	files := fstest.MapFS{
		"reader/index.html":             {Data: []byte("<html><script src='assets/app.js'></script></html>")},
		"reader/assets/app.js":          {Data: []byte("throw new Error('never execute evidence');")},
		"reader/assets/app.css":         {Data: []byte("body { color: black; }")},
		"reader/data/events.json":       {Data: []byte(`[{"id":"selected-1"}]`)},
		"reader/attachments/body.bin":   {Data: []byte{0, 1, 2, 3}},
		"record-selection.json":         {Data: []byte(`{"include":["selected-1"]}`)},
		"export-inventory.json":         {Data: []byte(`{"schema_version":"agentprovenance.replay_inventory/v1"}`)},
		"verification/policy.json":      {Data: []byte(`{"requested_policy":"recipient-policy"}`)},
		"verification/public-key.json":  {Data: []byte(`{"description":"not a trust root"}`)},
		"verification/source.dsse.json": {Data: []byte(`{"description":"source signature is checked separately"}`)},
	}
	list, err := InventoryFS(context.Background(), files, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{
		Sources: []Source{{ID: "run-1", Kind: "bundle", Digest: Reference{SHA256: attest.DigestSHA256([]byte("original bundle commitment"))},
			Signature: &Reference{Path: "verification/source.dsse.json", SHA256: attest.DigestSHA256(files["verification/source.dsse.json"].Data)}, TrustPolicyID: "source-policy"}},
		Selection:  Reference{Path: "record-selection.json", SHA256: attest.DigestSHA256(files["record-selection.json"].Data)},
		Projection: Rules{Version: "replay/v1", SHA256: attest.DigestSHA256([]byte("rules")), ImplementationSHA256: attest.DigestSHA256([]byte("implementation"))},
		Coverage: Coverage{State: CoverageGaps, Scope: "selected run", Gaps: []Gap{{Category: "collector_drop", Count: 2, Reason: "buffer_full"}},
			Capabilities: []Capability{{Name: "process-events", Status: "available"}}},
		Exclusions: []Gap{{Category: "attachments", Count: 1, Reason: "privacy"}},
		Files:      list, Exporter: Exporter{ID: "exporter-1", KeyID: attest.KeyID(pub), Role: RoleExporter},
		CreatedAt: "2026-11-16T10:00:00Z", TrustPolicyID: "recipient-policy",
	}
	policy := TrustPolicy{ID: "recipient-policy", Keys: map[string]TrustedKey{attest.KeyID(pub): {PublicKey: pub, Roles: []string{RoleExporter}}}}
	seal(t, files, m, key)
	return files, m, key, policy
}

func seal(t testing.TB, files fstest.MapFS, m Manifest, key ed25519.PrivateKey) {
	t.Helper()
	manifest, signature, err := Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	files[ManifestPath] = &fstest.MapFile{Data: manifest}
	files[SignaturePath] = &fstest.MapFile{Data: signature}
}

type zipItem struct {
	name string
	data []byte
	mode fs.FileMode
}

func zipItems(t testing.TB, items []zipItem, method uint16, year int) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	if err := z.SetComment("container metadata has no signed identity"); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		header := &zip.FileHeader{Name: item.name, Method: method, Modified: time.Date(year, 1, 2, 3, 4, 5, 0, time.UTC)}
		mode := item.mode
		if mode == 0 {
			mode = 0600
		}
		header.SetMode(mode)
		w, err := z.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(item.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipFS(t testing.TB, files fstest.MapFS, reverse bool) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	method, year := uint16(zip.Store), 2025
	if reverse {
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		method, year = zip.Deflate, 2026
	}
	items := make([]zipItem, 0, len(files))
	for _, name := range names {
		items = append(items, zipItem{name: name, data: files[name].Data, mode: files[name].Mode})
	}
	return zipItems(t, items, method, year)
}

func verifyZIPBytes(data []byte, policy TrustPolicy, limits Limits) (Result, error) {
	return VerifyZIP(context.Background(), bytes.NewReader(data), int64(len(data)), policy, limits)
}

func writeDirectory(t *testing.T, files fstest.MapFS) string {
	t.Helper()
	root := t.TempDir()
	for name, file := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, file.Data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRoundTripZIPFSAndDirectory(t *testing.T) {
	files, _, _, policy := fixture(t)
	want, err := VerifyFS(context.Background(), files, policy, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if want.FileIntegrity != IntegrityPassed || want.DerivedSignature.Status != SignatureValid || !want.DerivedSignature.Trusted || want.DerivedSignature.Cryptographic != IntegrityPassed {
		t.Fatalf("unexpected verification: %+v", want)
	}
	if want.Derivation != "not_checked" || want.SourceSignatures[0].Status != SignatureNotChecked || want.DeclaredCoverage.State != CoverageGaps || want.DeclaredCoverage.Gaps[0].Count != 2 {
		t.Fatalf("source, derivation or gap claim changed: %+v", want)
	}
	for _, reverse := range []bool{false, true} {
		got, err := verifyZIPBytes(zipFS(t, files, reverse), policy, Limits{})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("ZIP reverse=%v: err=%v\ngot=%+v\nwant=%+v", reverse, err, got, want)
		}
	}
	got, err := VerifyDirectory(context.Background(), writeDirectory(t, files), policy, Limits{})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("directory: err=%v\ngot=%+v\nwant=%+v", err, got, want)
	}
}

func TestPayloadTampering(t *testing.T) {
	for _, name := range []string{
		"reader/index.html", "reader/assets/app.js", "reader/assets/app.css", "reader/data/events.json", "reader/attachments/body.bin",
		"record-selection.json", "export-inventory.json", "verification/policy.json", "verification/public-key.json", "verification/source.dsse.json",
	} {
		t.Run(name, func(t *testing.T) {
			files, _, _, policy := fixture(t)
			files[name].Data[0] ^= 1
			got, err := verifyZIPBytes(zipFS(t, files, false), policy, Limits{})
			if err != nil || got.FileIntegrity != IntegrityFailed || got.DerivedSignature.Status != SignatureValid {
				t.Fatalf("err=%v result=%+v", err, got)
			}
			if len(got.Issues) != 1 || got.Issues[0] != (Issue{Code: "digest_mismatch", Path: name}) || got.SourceSignatures[0].Status != SignatureNotChecked {
				t.Fatalf("wrong independent results: %+v", got)
			}
		})
	}
}

func TestMissingExtraAndLength(t *testing.T) {
	for _, kind := range []string{"missing_file", "extra_file", "length_mismatch"} {
		t.Run(kind, func(t *testing.T) {
			files, _, _, policy := fixture(t)
			name := "reader/assets/app.js"
			switch kind {
			case "missing_file":
				delete(files, name)
			case "extra_file":
				name = "hidden-secret.db"
				files[name] = &fstest.MapFile{Data: []byte("never implicitly attach originals")}
			case "length_mismatch":
				files[name].Data = append(files[name].Data, 'x')
			}
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if err != nil || got.FileIntegrity != IntegrityFailed || len(got.Issues) != 1 || got.Issues[0] != (Issue{Code: kind, Path: name}) || got.DerivedSignature.Status != SignatureValid {
				t.Fatalf("err=%v result=%+v", err, got)
			}
		})
	}
}

func TestSignatureAndTrust(t *testing.T) {
	for _, kind := range []string{"trusted", "no_policy", "unknown_key", "wrong_role", "no_roles", "wrong_external_key", "invalid_external_key", "bad_signature", "signature_missing", "manifest_only", "key_id_mismatch", "wrong_type", "wrong_statement_type", "zero_signatures", "multiple_signatures", "public_key_absent"} {
		t.Run(kind, func(t *testing.T) {
			files, _, key, policy := fixture(t)
			var env attest.Envelope
			if err := json.Unmarshal(files[SignaturePath].Data, &env); err != nil {
				t.Fatal(err)
			}
			want, crypto := SignatureValid, IntegrityPassed
			switch kind {
			case "no_policy", "unknown_key":
				policy = TrustPolicy{}
				if kind == "unknown_key" {
					policy.Keys = map[string]TrustedKey{"different-id": {PublicKey: key.Public().(ed25519.PublicKey), Roles: []string{RoleExporter}}}
				}
				want = SignatureUnknownKey
			case "wrong_role", "no_roles":
				k := policy.Keys[env.Signatures[0].KeyID]
				k.Roles = []string{"capture"}
				if kind == "no_roles" {
					k.Roles = nil
				}
				policy.Keys[env.Signatures[0].KeyID] = k
				want = SignatureUntrustedRole
			case "wrong_external_key", "invalid_external_key":
				k := policy.Keys[env.Signatures[0].KeyID]
				k.PublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)
				want, crypto = SignatureInvalid, IntegrityFailed
				if kind == "invalid_external_key" {
					k.PublicKey, crypto = []byte{1}, IntegrityNotChecked
				}
				policy.Keys[env.Signatures[0].KeyID] = k
			case "bad_signature":
				env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				want, crypto = SignatureInvalid, IntegrityFailed
			case "signature_missing", "manifest_only":
				delete(files, SignaturePath)
				want, crypto = SignatureUnsigned, IntegrityNotChecked
			case "key_id_mismatch":
				env.Signatures[0].KeyID = "different"
				want, crypto = SignatureInvalid, IntegrityNotChecked
			case "wrong_type":
				env.PayloadType = "application/json"
				want, crypto = SignatureInvalid, IntegrityNotChecked
			case "wrong_statement_type":
				m, err := parseManifest(files[ManifestPath].Data)
				if err != nil {
					t.Fatal(err)
				}
				stmt := statement(m.Exporter, files[ManifestPath].Data)
				stmt.PredicateType = attest.DefaultPredicateType
				env, err = attest.Sign(stmt, key, m.Exporter.KeyID)
				if err != nil {
					t.Fatal(err)
				}
				want, crypto = SignatureInvalid, IntegrityNotChecked
			case "zero_signatures":
				env.Signatures = []attest.Signature{}
				want, crypto = SignatureInvalid, IntegrityNotChecked
			case "multiple_signatures":
				env.Signatures = append(env.Signatures, env.Signatures[0])
				want, crypto = SignatureInvalid, IntegrityNotChecked
			case "public_key_absent":
				m, err := parseManifest(files[ManifestPath].Data)
				if err != nil {
					t.Fatal(err)
				}
				m.Exporter.PublicKey = ""
				files[ManifestPath].Data, err = CanonicalManifest(m)
				if err != nil {
					t.Fatal(err)
				}
				env, err = attest.Sign(statement(m.Exporter, files[ManifestPath].Data), key, m.Exporter.KeyID)
				if err != nil {
					t.Fatal(err)
				}
				policy, want, crypto = TrustPolicy{}, SignatureUnknownKey, IntegrityNotChecked
			}
			if files[SignaturePath] != nil {
				files[SignaturePath].Data, _ = json.Marshal(env)
			}
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if err != nil || got.FileIntegrity != IntegrityPassed || got.DerivedSignature.Status != want || got.DerivedSignature.Cryptographic != crypto || got.DerivedSignature.Trusted != (want == SignatureValid) {
				t.Fatalf("want=%s/%s err=%v result=%+v", want, crypto, err, got)
			}
		})
	}
}

func TestReplacingPackagePolicyAndResigningCannotGrantTrust(t *testing.T) {
	files, m, _, policy := fixture(t)
	attacker := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	attackerPub := attacker.Public().(ed25519.PublicKey)
	m.Exporter.KeyID = attest.KeyID(attackerPub)
	files["verification/policy.json"].Data = []byte(`{"trusted":true,"roles":["exporter"]}`)
	files["verification/public-key.json"].Data = []byte(base64.StdEncoding.EncodeToString(attackerPub))
	var err error
	m.Files, err = InventoryFS(context.Background(), files, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	seal(t, files, m, attacker)
	got, err := VerifyFS(context.Background(), files, policy, Limits{})
	if err != nil || got.FileIntegrity != IntegrityPassed || got.DerivedSignature.Status != SignatureUnknownKey || got.DerivedSignature.Cryptographic != IntegrityPassed || got.DerivedSignature.Trusted {
		t.Fatalf("err=%v result=%+v", err, got)
	}
}

func TestManifestClaimsAreSigned(t *testing.T) {
	for _, claim := range []string{"source", "selection", "projection", "coverage", "exporter", "time", "policy", "files_digest"} {
		t.Run(claim, func(t *testing.T) {
			files, _, _, policy := fixture(t)
			m, err := parseManifest(files[ManifestPath].Data)
			if err != nil {
				t.Fatal(err)
			}
			switch claim {
			case "source":
				m.Sources[0].Digest.SHA256 = attest.DigestSHA256([]byte("different source"))
			case "selection":
				m.Selection = Reference{SHA256: attest.DigestSHA256([]byte("different private selection"))}
			case "projection":
				m.Projection.Version = "changed"
			case "coverage":
				m.Coverage = Coverage{State: CoverageComplete, Scope: "all"}
			case "exporter":
				m.Exporter.ID = "different exporter"
			case "time":
				m.CreatedAt = "2026-11-17T10:00:00Z"
			case "policy":
				m.TrustPolicyID = "new policy"
			case "files_digest":
				m.FilesSHA256 = strings.Repeat("0", 64)
			}
			if claim == "files_digest" {
				files[ManifestPath].Data, _ = json.Marshal(m)
			} else {
				files[ManifestPath].Data, err = CanonicalManifest(m)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if claim == "files_digest" {
				if !errors.Is(err, ErrInvalid) || got.FileIntegrity != IntegrityFailed {
					t.Fatalf("err=%v result=%+v", err, got)
				}
			} else if err != nil || got.DerivedSignature.Status != SignatureInvalid || got.FileIntegrity != IntegrityPassed {
				t.Fatalf("err=%v result=%+v", err, got)
			}
		})
	}
}

func TestLegacyUnsignedAndOrphanSignature(t *testing.T) {
	files, _, _, policy := fixture(t)
	delete(files, ManifestPath)
	delete(files, SignaturePath)
	for _, asZIP := range []bool{false, true} {
		var got Result
		var err error
		if asZIP {
			got, err = verifyZIPBytes(zipFS(t, files, false), policy, Limits{})
		} else {
			got, err = VerifyFS(context.Background(), files, policy, Limits{})
		}
		if err != nil || got.ManifestStatus != "missing" || got.FileIntegrity != IntegrityNotChecked || got.DerivedSignature.Status != SignatureUnsigned || got.DerivedSignature.Trusted || got.Derivation != "not_checked" {
			t.Fatalf("err=%v result=%+v", err, got)
		}
	}
	files[SignaturePath] = &fstest.MapFile{Data: []byte(`{}`)}
	got, err := VerifyFS(context.Background(), files, policy, Limits{})
	if !errors.Is(err, ErrInvalid) || got.DerivedSignature.Status != SignatureInvalid || got.FileIntegrity != IntegrityFailed {
		t.Fatalf("err=%v result=%+v", err, got)
	}
}

func TestLimits(t *testing.T) {
	for name, limits := range map[string]Limits{
		"entries": {MaxEntries: 2}, "file": {MaxFileBytes: 2}, "total": {MaxTotalBytes: 2},
		"manifest": {MaxManifestBytes: 2}, "signature": {MaxSignatureBytes: 2},
		"path": {MaxPathBytes: 2}, "depth": {MaxPathDepth: 1}, "negative": {MaxTotalBytes: -1},
	} {
		t.Run(name, func(t *testing.T) {
			files, _, _, policy := fixture(t)
			if _, err := VerifyFS(context.Background(), files, policy, limits); !errors.Is(err, ErrLimit) {
				t.Fatalf("expected limit, got %v", err)
			}
			if _, err := verifyZIPBytes(zipFS(t, files, false), policy, limits); !errors.Is(err, ErrLimit) {
				t.Fatalf("expected ZIP limit, got %v", err)
			}
		})
	}
	files, _, _, policy := fixture(t)
	for _, limits := range []Limits{{MaxZIPBytes: 2}, {MaxZIPMetadataBytes: 2}} {
		if _, err := verifyZIPBytes(zipFS(t, files, false), policy, limits); !errors.Is(err, ErrLimit) {
			t.Fatal(err)
		}
	}
}

type cancelFS struct {
	fs.FS
	cancel context.CancelFunc
	name   string
}

func (f cancelFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil || name != f.name {
		return file, err
	}
	return &cancelFile{File: file, cancel: f.cancel}, nil
}

type cancelFile struct {
	fs.File
	cancel context.CancelFunc
}

func (f *cancelFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	f.cancel()
	return n, err
}

func TestCancellation(t *testing.T) {
	files, _, _, policy := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyFS(ctx, files, policy, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := VerifyZIP(ctx, bytes.NewReader(nil), 0, policy, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(ctx, t.TempDir(), policy, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, name := range []string{ManifestPath, SignaturePath, "reader/assets/app.js"} {
		ctx, cancel := context.WithCancel(context.Background())
		got, err := VerifyFS(ctx, cancelFS{FS: files, cancel: cancel, name: name}, policy, Limits{})
		cancel()
		if !errors.Is(err, context.Canceled) || got.FileIntegrity == IntegrityPassed {
			t.Fatalf("name=%s err=%v result=%+v", name, err, got)
		}
	}
}

func TestZIPUnsafePathsAndTypes(t *testing.T) {
	for _, name := range []string{"../outside", "/absolute", "C:/absolute", `a\b`, "a//b", "a/./b", "a/../b", "a\x00b", "a. ", "a.", "a ", "CON.txt", "CON .txt", "COM1", "LPT\u00b2", "a:b", "a?b", "MANIFEST.JSON", "manifest.json/a"} {
		t.Run(name, func(t *testing.T) {
			data := zipItems(t, []zipItem{{name: name, data: []byte("x")}}, zip.Store, 2026)
			if got, err := verifyZIPBytes(data, TrustPolicy{}, Limits{}); err == nil || got.FileIntegrity != IntegrityFailed {
				t.Fatalf("accepted %q: err=%v result=%+v", name, err, got)
			}
		})
	}
	for _, mode := range []fs.FileMode{fs.ModeSymlink | 0777, fs.ModeNamedPipe | 0600, fs.ModeDevice | 0600, fs.ModeSocket | 0600} {
		data := zipItems(t, []zipItem{{name: "link", data: []byte("/outside"), mode: mode}}, zip.Store, 2026)
		if _, err := verifyZIPBytes(data, TrustPolicy{}, Limits{}); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("mode=%s err=%v", mode, err)
		}
	}
}

func TestDuplicateAndConflictingZIPPaths(t *testing.T) {
	for _, names := range [][]string{{"a", "a"}, {"a", "A"}, {"a", "a/b"}, {"a/b", "a"}, {"a/", "a/"}, {"a/", "A/b"}, {"caf\u00e9", "cafe\u0301"}, {"s", "\u017f"}, {ManifestPath, ManifestPath}, {SignaturePath, SignaturePath}} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			var items []zipItem
			for _, name := range names {
				items = append(items, zipItem{name: name})
			}
			if _, err := verifyZIPBytes(zipItems(t, items, zip.Store, 2026), TrustPolicy{}, Limits{}); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("names=%q err=%v", names, err)
			}
		})
	}
}

func TestZIPDirectoryEntries(t *testing.T) {
	files, _, _, policy := fixture(t)
	files["reader/"] = &fstest.MapFile{Mode: fs.ModeDir | 0700}
	files["reader/assets/"] = &fstest.MapFile{Mode: fs.ModeDir | 0700}
	for _, reverse := range []bool{false, true} {
		got, err := verifyZIPBytes(zipFS(t, files, reverse), policy, Limits{})
		if err != nil || got.FileIntegrity != IntegrityPassed || got.DerivedSignature.Status != SignatureValid {
			t.Fatalf("reverse=%v err=%v result=%+v", reverse, err, got)
		}
	}
}

func TestNativeDirectoryRejectsSymlinks(t *testing.T) {
	files, _, _, policy := fixture(t)
	for _, path := range []string{"reader/assets/app.js", "reader/assets", "reader", "extra-link"} {
		t.Run(path, func(t *testing.T) {
			root := writeDirectory(t, files)
			target := filepath.Join(root, filepath.FromSlash(path))
			if err := os.RemoveAll(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), target); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyDirectory(context.Background(), root, policy, Limits{}); !errors.Is(err, ErrUnsafe) {
				t.Fatal(err)
			}
		})
	}
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(writeDirectory(t, files), link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, link + string(os.PathSeparator)} {
		if _, err := VerifyDirectory(context.Background(), path, policy, Limits{}); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("path=%s err=%v", path, err)
		}
	}
}

func TestLocalCentralPathMismatchAndZIPCorruption(t *testing.T) {
	files, _, _, policy := fixture(t)
	original := zipFS(t, files, false)
	for _, mutation := range []string{"local_name", "local_method", "local_crc", "descriptor", "central_count", "central_size", "trailing", "truncate", "crc"} {
		t.Run(mutation, func(t *testing.T) {
			data := bytes.Clone(original)
			central := bytes.Index(data, []byte("PK\x01\x02"))
			end := bytes.LastIndex(data, []byte("PK\x05\x06"))
			switch mutation {
			case "local_name":
				data[30] ^= 1
			case "local_method":
				data[8] ^= 1
			case "local_crc":
				data[6] &^= 8
				data[central+8] &^= 8
			case "descriptor":
				data[bytes.Index(data, []byte("PK\x07\x08"))+4] ^= 1
			case "central_count":
				binary.LittleEndian.PutUint16(data[end+8:], 1)
				binary.LittleEndian.PutUint16(data[end+10:], 1)
			case "central_size":
				binary.LittleEndian.PutUint32(data[end+12:], 1)
			case "trailing":
				data = append(data, 0)
			case "truncate":
				data = data[:len(data)-50]
			case "crc":
				reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
				if err != nil {
					t.Fatal(err)
				}
				offset, err := reader.File[0].DataOffset()
				if err != nil {
					t.Fatal(err)
				}
				data[offset] ^= 1
			}
			got, err := verifyZIPBytes(data, policy, Limits{})
			if err == nil || got.FileIntegrity != IntegrityFailed {
				t.Fatalf("mutation=%s err=%v result=%+v", mutation, err, got)
			}
		})
	}
}

func TestStreamBoundsAndClose(t *testing.T) {
	for _, actual := range []int{1, 8, 1 << 20} {
		closed, read := false, 0
		e := entry{name: "data", size: 8, open: func() (io.ReadCloser, error) {
			return &trackingReader{Reader: bytes.NewReader(make([]byte, actual)), closed: &closed, read: &read}, nil
		}}
		_, err := streamEntry(context.Background(), e, nil)
		if !closed || read > 9 || (err == nil) != (actual == 8) {
			t.Fatalf("actual=%d read=%d closed=%v err=%v", actual, read, closed, err)
		}
	}
}

type trackingReader struct {
	io.Reader
	closed *bool
	read   *int
}

func (r *trackingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	*r.read += n
	return n, err
}

func (r *trackingReader) Close() error { *r.closed = true; return nil }
