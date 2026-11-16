package derivedview

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/byteyellow/agentprovenance/internal/attest"
)

func TestCanonicalManifestIsDeterministicAndDoesNotMutate(t *testing.T) {
	files, m, key, _ := fixture(t)
	first, signature, err := Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, files[ManifestPath].Data) || !bytes.Equal(signature, files[SignaturePath].Data) {
		t.Fatal("signing the same assertion is not deterministic")
	}
	for i, j := 0, len(m.Files)-1; i < j; i, j = i+1, j-1 {
		m.Files[i], m.Files[j] = m.Files[j], m.Files[i]
	}
	firstName := m.Files[0].Path
	second, _, err := Sign(m, key)
	if err != nil || !bytes.Equal(first, second) || m.Files[0].Path != firstName || m.SchemaVersion != "" || m.FilesSHA256 != "" || m.Exporter.PublicKey != "" {
		t.Fatalf("canonicalization mutated caller input or depends on file order: %v", err)
	}
	parsed, err := parseManifest(first)
	if err != nil {
		t.Fatal(err)
	}
	rawFiles, err := json.Marshal(parsed.Files)
	if err != nil || attest.DigestSHA256(rawFiles) != parsed.FilesSHA256 {
		t.Fatal("file-list digest does not cover canonical files")
	}
	for _, f := range parsed.Files {
		if f.Path == ManifestPath || f.Path == SignaturePath {
			t.Fatal("cyclic manifest")
		}
	}
	var env attest.Envelope
	if err := json.Unmarshal(signature, &env); err != nil {
		t.Fatal(err)
	}
	stmt, err := attest.Verify(env, key.Public().(ed25519.PublicKey))
	if err != nil || stmt.PredicateType != SchemaVersion || len(stmt.Subject) != 1 || stmt.Subject[0].Name != ManifestPath || stmt.Subject[0].Digest["sha256"] != attest.DigestSHA256(first) {
		t.Fatalf("existing attest verifier failed: %v %+v", err, stmt)
	}
}

func TestRejectAmbiguousManifestJSON(t *testing.T) {
	for _, mutation := range []string{"duplicate", "nested_duplicate", "escaped_duplicate", "case_alias", "unknown", "null", "invalid_utf8", "surrogate", "trailing", "whitespace", "unsorted", "omitted_schema", "omitted_digest", "numeric_exponent", "depth"} {
		t.Run(mutation, func(t *testing.T) {
			files, _, _, policy := fixture(t)
			raw := files[ManifestPath].Data
			switch mutation {
			case "duplicate":
				raw = append([]byte(`{"schema_version":"bad",`), raw[1:]...)
			case "nested_duplicate":
				raw = bytes.Replace(raw, []byte(`"id":"run-1"`), []byte(`"id":"other","id":"run-1"`), 1)
			case "escaped_duplicate":
				raw = bytes.Replace(raw, []byte(`"id":"run-1"`), []byte(`"\u0069d":"other","id":"run-1"`), 1)
			case "case_alias":
				raw = bytes.Replace(raw, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1)
			case "unknown":
				raw = append([]byte(`{"unknown":1,`), raw[1:]...)
			case "null":
				raw = bytes.Replace(raw, []byte(`"included_records"`), []byte(`"unused"`), 1)
				raw = append([]byte(`{"included_records":null,`), raw[1:]...)
			case "invalid_utf8":
				raw = bytes.Replace(raw, []byte("run-1"), []byte{'x', 0xff}, 1)
			case "surrogate":
				raw = bytes.Replace(raw, []byte(`"run-1"`), []byte(`"\ud800"`), 1)
			case "trailing":
				raw = append(raw, []byte(` {}`)...)
			case "whitespace":
				raw = append(raw, '\n')
			case "unsorted":
				m, err := parseManifest(raw)
				if err != nil {
					t.Fatal(err)
				}
				m.Files[0], m.Files[1] = m.Files[1], m.Files[0]
				raw, _ = json.Marshal(m)
			case "omitted_schema":
				raw = bytes.Replace(raw, []byte(`"schema_version":"`+SchemaVersion+`",`), nil, 1)
			case "omitted_digest":
				m, err := parseManifest(raw)
				if err != nil {
					t.Fatal(err)
				}
				raw = bytes.Replace(raw, []byte(`"files_sha256":"`+m.FilesSHA256+`",`), nil, 1)
			case "numeric_exponent":
				raw = bytes.Replace(raw, []byte(`"count":2`), []byte(`"count":2e0`), 1)
			case "depth":
				raw = []byte(strings.Repeat("[", 66) + "1" + strings.Repeat("]", 66))
			}
			files[ManifestPath].Data = raw
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if !errors.Is(err, ErrInvalid) || got.ManifestStatus != "invalid" || got.FileIntegrity != IntegrityFailed || got.DerivedSignature.Status != SignatureInvalid {
				t.Fatalf("err=%v result=%+v", err, got)
			}
		})
	}
}

func TestRejectAmbiguousEnvelopeAndSignedPayload(t *testing.T) {
	for _, mutation := range []string{"duplicate", "nested_duplicate", "case_alias", "unknown", "trailing", "whitespace", "null", "bad_base64", "bad_signature_base64", "payload_duplicate", "payload_extra_subject", "payload_extra_digest"} {
		t.Run(mutation, func(t *testing.T) {
			files, _, _, policy := fixture(t)
			raw := files[SignaturePath].Data
			var env attest.Envelope
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "duplicate":
				raw = append([]byte(`{"payload":"bad",`), raw[1:]...)
			case "nested_duplicate":
				raw = bytes.Replace(raw, []byte(`"keyid":`), []byte(`"keyid":"bad","keyid":`), 1)
			case "case_alias":
				raw = bytes.Replace(raw, []byte(`"payloadType":`), []byte(`"PayloadType":`), 1)
			case "unknown":
				raw = append([]byte(`{"extra":true,`), raw[1:]...)
			case "trailing":
				raw = append(raw, []byte(` {}`)...)
			case "whitespace":
				raw = append(raw, '\n')
			case "null":
				env.Signatures = nil
				raw, _ = json.Marshal(env)
			case "bad_base64":
				env.Payload = "!"
				raw, _ = json.Marshal(env)
			case "bad_signature_base64":
				env.Signatures[0].Sig = "!"
				raw, _ = json.Marshal(env)
			case "payload_duplicate", "payload_extra_subject", "payload_extra_digest":
				payload, _ := base64.StdEncoding.DecodeString(env.Payload)
				switch mutation {
				case "payload_duplicate":
					payload = append([]byte(`{"_type":"bad",`), payload[1:]...)
				case "payload_extra_subject":
					payload = bytes.Replace(payload, []byte(`"subject":[`), []byte(`"subject":[{"name":"extra","digest":{}},`), 1)
				case "payload_extra_digest":
					payload = bytes.Replace(payload, []byte(`"digest":{`), []byte(`"digest":{"md5":"bad",`), 1)
				}
				env.Payload = base64.StdEncoding.EncodeToString(payload)
				raw, _ = json.Marshal(env)
			}
			files[SignaturePath].Data = raw
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if err != nil || got.FileIntegrity != IntegrityPassed || got.DerivedSignature.Status != SignatureInvalid || got.DerivedSignature.Trusted {
				t.Fatalf("err=%v result=%+v", err, got)
			}
		})
	}
}

func TestInvalidClaimsRejectedBeforeSigning(t *testing.T) {
	for _, mutation := range []string{"schema", "time", "exporter_id", "role", "public_key", "private_key", "private_key_suffix", "invalid_utf8", "projection", "rules_digest", "implementation_digest", "no_sources", "source_id", "source_duplicate", "source_digest", "source_signature", "selection_digest", "selection_path", "records", "attachments", "file_digest", "file_length", "file_duplicate", "file_alias", "file_traversal", "manifest_cycle", "signature_cycle", "files_digest", "coverage", "complete_with_gap", "complete_no_scope", "gaps_empty", "unknown_with_gap", "negative_gap", "exclusion", "capability_duplicate", "capability_empty"} {
		t.Run(mutation, func(t *testing.T) {
			_, m, key, _ := fixture(t)
			switch mutation {
			case "schema":
				m.SchemaVersion = "future/v2"
			case "time":
				m.CreatedAt = "bad"
			case "exporter_id":
				m.Exporter.ID = ""
			case "role":
				m.Exporter.Role = "capture"
			case "public_key":
				m.Exporter.PublicKey = "wrong"
			case "private_key":
				key = nil
			case "private_key_suffix":
				key[len(key)-1] ^= 1
			case "invalid_utf8":
				m.Exporter.ID = string([]byte{0xff})
			case "projection":
				m.Projection.Version = ""
			case "rules_digest":
				m.Projection.SHA256 = "bad"
			case "implementation_digest":
				m.Projection.ImplementationSHA256 = "bad"
			case "no_sources":
				m.Sources = nil
			case "source_id":
				m.Sources[0].ID = ""
			case "source_duplicate":
				m.Sources = append(m.Sources, m.Sources[0])
			case "source_digest":
				m.Sources[0].Digest.SHA256 = "bad"
			case "source_signature":
				m.Sources[0].Signature.SHA256 = "bad"
			case "selection_digest":
				m.Selection.SHA256 = "bad"
			case "selection_path":
				m.Selection.Path = "missing"
			case "records":
				m.IncludedRecords = &Reference{SHA256: "bad"}
			case "attachments":
				m.IncludedAttachments = &Reference{SHA256: "bad"}
			case "file_digest":
				m.Files[0].SHA256 = "bad"
			case "file_length":
				m.Files[0].Bytes = -1
			case "file_duplicate":
				m.Files = append(m.Files, m.Files[0])
			case "file_alias":
				f := m.Files[0]
				f.Path = strings.ToUpper(f.Path)
				m.Files = append(m.Files, f)
			case "file_traversal":
				m.Files[0].Path = "../outside"
			case "manifest_cycle":
				m.Files[0].Path = ManifestPath
			case "signature_cycle":
				m.Files[0].Path = SignaturePath
			case "files_digest":
				m.FilesSHA256 = strings.Repeat("0", 64)
			case "coverage":
				m.Coverage.State = "bogus"
			case "complete_with_gap":
				m.Coverage.State = CoverageComplete
			case "complete_no_scope":
				m.Coverage = Coverage{State: CoverageComplete}
			case "gaps_empty":
				m.Coverage.Gaps = nil
			case "unknown_with_gap":
				m.Coverage.State = CoverageUnknown
			case "negative_gap":
				m.Coverage.Gaps[0].Count = -1
			case "exclusion":
				m.Exclusions[0].Reason = ""
			case "capability_duplicate":
				m.Coverage.Capabilities = append(m.Coverage.Capabilities, m.Coverage.Capabilities[0])
			case "capability_empty":
				m.Coverage.Capabilities[0].Status = ""
			}
			if _, _, err := Sign(m, key); err == nil {
				t.Fatal("invalid claim was signed")
			}
		})
	}
}

func TestOptionalCommitmentsAndUnsignedSource(t *testing.T) {
	files, m, key, policy := fixture(t)
	m.Sources[0].Signature = nil
	m.IncludedRecords = &Reference{SHA256: attest.DigestSHA256([]byte("private records manifest"))}
	m.IncludedAttachments = &Reference{Path: "reader/attachments/body.bin", SHA256: attest.DigestSHA256(files["reader/attachments/body.bin"].Data)}
	m.Coverage = Coverage{State: CoverageUnknown}
	seal(t, files, m, key)
	got, err := VerifyFS(context.Background(), files, policy, Limits{})
	if err != nil || got.FileIntegrity != IntegrityPassed || got.SourceSignatures[0].Status != SignatureUnsigned || got.DeclaredCoverage.State != CoverageUnknown {
		t.Fatalf("err=%v result=%+v", err, got)
	}
}

func TestInventoryAllPayloadsAndSpecialFileRejection(t *testing.T) {
	files, m, _, _ := fixture(t)
	list, err := InventoryFS(context.Background(), files, Limits{})
	if err != nil || len(list) != len(m.Files) {
		t.Fatalf("reserved metadata must be excluded: %v", err)
	}
	files["verification/extra.policy.json"] = &fstest.MapFile{Data: []byte(`{}`)}
	list, err = InventoryFS(context.Background(), files, Limits{})
	if err != nil || len(list) != len(m.Files)+1 {
		t.Fatalf("package policy was implicitly excluded: %v", err)
	}
	for _, mode := range []fs.FileMode{fs.ModeSymlink, fs.ModeNamedPipe, fs.ModeSocket, fs.ModeDir | fs.ModeSymlink} {
		files["special"] = &fstest.MapFile{Data: []byte("outside"), Mode: mode}
		if _, err := InventoryFS(context.Background(), files, Limits{}); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("mode=%s err=%v", mode, err)
		}
	}
}

func FuzzParseManifest(f *testing.F) {
	files, _, _, _ := fixture(f)
	f.Add(files[ManifestPath].Data)
	f.Add([]byte(`{"files":[],"files":[]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128<<10 {
			t.Skip()
		}
		m, err := parseManifest(raw)
		if err != nil {
			return
		}
		canonical, err := CanonicalManifest(m)
		if err != nil || !bytes.Equal(raw, canonical) {
			t.Fatalf("accepted noncanonical manifest: %v", err)
		}
	})
}

func FuzzVerifyZIP(f *testing.F) {
	files, _, _, policy := fixture(f)
	f.Add(zipFS(f, files, false))
	f.Add(zipFS(f, files, true))
	f.Add([]byte("PK"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128<<10 {
			t.Skip()
		}
		result, err := verifyZIPBytes(raw, policy, Limits{MaxEntries: 64, MaxZIPBytes: 128 << 10, MaxTotalBytes: 256 << 10, MaxFileBytes: 128 << 10, MaxZIPMetadataBytes: 256 << 10})
		if err != nil && result.FileIntegrity == IntegrityPassed {
			t.Fatal("incomplete verification reported success")
		}
	})
}
