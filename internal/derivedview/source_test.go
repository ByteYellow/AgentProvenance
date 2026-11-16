package derivedview

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/byteyellow/agentprovenance/internal/attest"
)

func sourceFixture(t testing.TB) (fstest.MapFS, Manifest, ed25519.PrivateKey, ed25519.PrivateKey, TrustPolicy) {
	t.Helper()
	files, m, exporter, policy := fixture(t)
	producer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, ed25519.SeedSize))
	pub := producer.Public().(ed25519.PublicKey)
	keyID := attest.KeyID(pub)
	policy.Keys[keyID] = TrustedKey{PublicKey: pub, Roles: []string{RoleProducer}}
	raw := []byte("{\n  \"schema_version\": \"agentprovenance.forensics_export/v1\",\n  \"run_id\": \"run-1\",\n  \"events\": []\n}")
	digest := attest.DigestSHA256(raw)
	name := "originals/" + digest + ".json"
	sigName := "signatures/bundle-1.dsse.json"
	stmt := attest.NewStatement("forensics/run-1", digest, map[string]any{
		"run_id": "run-1", "kind": KindForensicsBundle, "bundle_id": "bundle-1",
		"schema_version": "agentprovenance.forensics_export/v1", "created_at": "2026-11-16T10:00:00Z",
	})
	env, err := attest.Sign(stmt, producer, keyID)
	if err != nil {
		t.Fatal(err)
	}
	sigRaw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files[name] = &fstest.MapFile{Data: raw}
	files[sigName] = &fstest.MapFile{Data: sigRaw}
	m.Sources = []Source{{ID: "bundle-1", Kind: KindForensicsBundle, Digest: Reference{Path: name, SHA256: digest}, Signature: &Reference{Path: sigName, SHA256: attest.DigestSHA256(sigRaw)}}}
	m = resealSourceView(t, files, m, exporter)
	return files, m, exporter, producer, policy
}

func resealSourceView(t testing.TB, files fstest.MapFS, m Manifest, exporter ed25519.PrivateKey) Manifest {
	t.Helper()
	for i := range m.Sources {
		source := &m.Sources[i]
		if file := files[source.Digest.Path]; file != nil {
			source.Digest.SHA256 = attest.DigestSHA256(file.Data)
		}
		if source.Signature != nil {
			if file := files[source.Signature.Path]; file != nil {
				source.Signature.SHA256 = attest.DigestSHA256(file.Data)
			}
		}
	}
	var err error
	m.Files, err = InventoryFS(context.Background(), files, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	seal(t, files, m, exporter)
	return m
}

func sourceEnvelope(t testing.TB, files fstest.MapFS, m Manifest) (attest.Envelope, attest.Statement) {
	t.Helper()
	var env attest.Envelope
	if err := json.Unmarshal(files[m.Sources[0].Signature.Path].Data, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var stmt attest.Statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatal(err)
	}
	return env, stmt
}

func writeSourceEnvelope(t testing.TB, files fstest.MapFS, m Manifest, env attest.Envelope) {
	t.Helper()
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files[m.Sources[0].Signature.Path].Data = raw
}

func requireSource(t testing.TB, r Result, status SignatureStatus, crypto IntegrityStatus, trusted bool) SourceResult {
	t.Helper()
	if len(r.SourceSignatures) != 1 {
		t.Fatalf("expected one original source: %+v", r)
	}
	source := r.SourceSignatures[0]
	if source.Status != status || source.Cryptographic != crypto || source.Trusted != trusted || source.Role != RoleProducer {
		t.Fatalf("expected %s/%s/trusted=%v, got %+v", status, crypto, trusted, source)
	}
	if r.Derivation != "not_checked" {
		t.Fatal("source verification changed derivation status")
	}
	return source
}

func TestOriginalSourceRoundTrip(t *testing.T) {
	files, _, _, producer, policy := sourceFixture(t)
	want, err := VerifyFS(context.Background(), files, policy, Limits{})
	if err != nil || want.FileIntegrity != IntegrityPassed || want.DerivedSignature.Status != SignatureValid {
		t.Fatalf("err=%v result=%+v", err, want)
	}
	source := requireSource(t, want, SignatureValid, IntegrityPassed, true)
	if source.KeyID != attest.KeyID(producer.Public().(ed25519.PublicKey)) || source.SourceID != "bundle-1" {
		t.Fatalf("unexpected source identity: %+v", source)
	}
	for _, reverse := range []bool{false, true} {
		got, err := verifyZIPBytes(zipFS(t, files, reverse), policy, Limits{})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("ZIP err=%v result=%+v", err, got)
		}
	}
	got, err := VerifyDirectory(context.Background(), writeDirectory(t, files), policy, Limits{})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("directory err=%v result=%+v", err, got)
	}
}

func TestOriginalRemainsValidWhenViewTampered(t *testing.T) {
	for _, mutation := range []string{"reader", "missing_reader", "derived_signature", "missing_derived_signature", "inventory_commitment", "reader_crc"} {
		t.Run(mutation, func(t *testing.T) {
			files, m, _, _, policy := sourceFixture(t)
			switch mutation {
			case "reader", "reader_crc":
				if mutation == "reader" {
					files["reader/assets/app.js"].Data[0] ^= 1
				}
			case "missing_reader":
				delete(files, "reader/assets/app.js")
			case "derived_signature":
				var env attest.Envelope
				if err := json.Unmarshal(files[SignaturePath].Data, &env); err != nil {
					t.Fatal(err)
				}
				env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				files[SignaturePath].Data, _ = json.Marshal(env)
			case "missing_derived_signature":
				delete(files, SignaturePath)
			case "inventory_commitment":
				// Original DSSE remains genuine after envelope whitespace changes;
				// the exporter's exact-file commitment must fail independently.
				files[m.Sources[0].Signature.Path].Data = append(files[m.Sources[0].Signature.Path].Data, '\n')
			}
			data := zipFS(t, files, false)
			if mutation == "reader_crc" {
				z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range z.File {
					if f.Name == "reader/assets/app.js" {
						offset, err := f.DataOffset()
						if err != nil {
							t.Fatal(err)
						}
						data[offset] ^= 1
					}
				}
			}
			got, err := verifyZIPBytes(data, policy, Limits{})
			if mutation == "reader_crc" {
				if err == nil || got.FileIntegrity != IntegrityFailed {
					t.Fatalf("err=%v result=%+v", err, got)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			requireSource(t, got, SignatureValid, IntegrityPassed, true)
			switch mutation {
			case "derived_signature":
				if got.DerivedSignature.Status != SignatureInvalid || got.FileIntegrity != IntegrityPassed {
					t.Fatalf("wrong derived result: %+v", got)
				}
			case "missing_derived_signature":
				if got.DerivedSignature.Status != SignatureUnsigned || got.FileIntegrity != IntegrityPassed {
					t.Fatalf("wrong derived result: %+v", got)
				}
			default:
				if got.FileIntegrity != IntegrityFailed {
					t.Fatalf("view mutation was accepted: %+v", got)
				}
			}
		})
	}
}

func TestOriginalExternalTrustAndLegacyKeyID(t *testing.T) {
	for _, mode := range []string{"unknown", "exporter_only", "no_roles", "both_roles", "wrong_key", "invalid_key", "legacy", "legacy_exporter_only", "legacy_unknown", "legacy_no_policy", "known_id_does_not_fallback"} {
		t.Run(mode, func(t *testing.T) {
			files, m, exporter, producer, policy := sourceFixture(t)
			env, stmt := sourceEnvelope(t, files, m)
			id := attest.KeyID(producer.Public().(ed25519.PublicKey))
			want, crypto, trusted := SignatureValid, IntegrityPassed, true
			if strings.HasPrefix(mode, "legacy") {
				var err error
				env, err = attest.Sign(stmt, producer, "")
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "unknown", "legacy_unknown":
				delete(policy.Keys, id)
				want, crypto, trusted = SignatureUnknownKey, IntegrityNotChecked, false
			case "legacy_no_policy":
				policy = TrustPolicy{}
				want, crypto, trusted = SignatureUnknownKey, IntegrityNotChecked, false
			case "exporter_only", "legacy_exporter_only", "no_roles":
				k := policy.Keys[id]
				k.Roles = []string{RoleExporter}
				if mode == "no_roles" {
					k.Roles = nil
				}
				policy.Keys[id] = k
				want, trusted = SignatureUntrustedRole, false
			case "both_roles":
				k := policy.Keys[id]
				k.Roles = []string{RoleExporter, RoleProducer}
				policy.Keys[id] = k
			case "wrong_key", "invalid_key":
				k := policy.Keys[id]
				k.PublicKey = exporter.Public().(ed25519.PublicKey)
				want, crypto, trusted = SignatureInvalid, IntegrityFailed, false
				if mode == "invalid_key" {
					k.PublicKey, crypto = nil, IntegrityNotChecked
				}
				policy.Keys[id] = k
			case "known_id_does_not_fallback":
				env.Signatures[0].KeyID = attest.KeyID(exporter.Public().(ed25519.PublicKey))
				want, crypto, trusted = SignatureInvalid, IntegrityFailed, false
			}
			writeSourceEnvelope(t, files, m, env)
			resealSourceView(t, files, m, exporter)
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if err != nil || got.FileIntegrity != IntegrityPassed {
				t.Fatalf("err=%v result=%+v", err, got)
			}
			source := requireSource(t, got, want, crypto, trusted)
			if mode == "legacy" && source.KeyID != id {
				t.Fatalf("legacy key was not resolved: %+v", source)
			}
		})
	}
}

func TestOriginalBundleAndSignatureTampering(t *testing.T) {
	for _, target := range []string{"bundle", "signature", "missing_bundle", "missing_signature"} {
		t.Run(target, func(t *testing.T) {
			files, m, _, _, policy := sourceFixture(t)
			crypto := IntegrityNotChecked
			switch target {
			case "bundle":
				files[m.Sources[0].Digest.Path].Data[0] ^= 1
				crypto = IntegrityPassed
			case "signature":
				env, _ := sourceEnvelope(t, files, m)
				env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				writeSourceEnvelope(t, files, m, env)
				crypto = IntegrityFailed
			case "missing_bundle":
				delete(files, m.Sources[0].Digest.Path)
			case "missing_signature":
				delete(files, m.Sources[0].Signature.Path)
			}
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if err != nil || got.FileIntegrity != IntegrityFailed || got.DerivedSignature.Status != SignatureValid {
				t.Fatalf("err=%v result=%+v", err, got)
			}
			requireSource(t, got, SignatureInvalid, crypto, false)
		})
	}
}

func TestOriginalStatementAndEnvelopeValidation(t *testing.T) {
	for _, mutation := range []string{"payload_type", "statement_type", "predicate_type", "no_subject", "later_subject_matches", "first_subject_matches", "no_sha256", "sha256_alias", "subject_name", "run_mismatch", "kind", "no_predicate", "extra_predicate", "signed_duplicate_predicate", "empty_signatures", "too_many_signatures", "duplicate_envelope", "case_envelope", "duplicate_payload", "case_payload", "subject_alias", "predicate_alias", "bad_base64", "bad_sig_base64"} {
		t.Run(mutation, func(t *testing.T) {
			files, m, exporter, producer, policy := sourceFixture(t)
			env, stmt := sourceEnvelope(t, files, m)
			valid := false
			switch mutation {
			case "statement_type":
				stmt.Type = "https://in-toto.io/Statement/v0.1"
			case "predicate_type":
				stmt.PredicateType = SchemaVersion
			case "no_subject":
				stmt.Subject = nil
			case "later_subject_matches":
				stmt.Subject = append([]attest.Subject{{Name: "forensics/run-1", Digest: map[string]string{"sha256": strings.Repeat("0", 64)}}}, stmt.Subject...)
			case "first_subject_matches":
				stmt.Subject = append(stmt.Subject, attest.Subject{Name: "another", Digest: map[string]string{"sha256": strings.Repeat("0", 64)}})
				valid = true
			case "no_sha256":
				delete(stmt.Subject[0].Digest, "sha256")
			case "sha256_alias":
				stmt.Subject[0].Digest["SHA256"] = stmt.Subject[0].Digest["sha256"]
			case "subject_name":
				stmt.Subject[0].Name = "arbitrary/run-1"
			case "run_mismatch":
				stmt.Predicate.(map[string]any)["run_id"] = "different-run"
			case "kind":
				stmt.Predicate.(map[string]any)["kind"] = "reader"
			case "no_predicate":
				stmt.Predicate = nil
			case "extra_predicate":
				stmt.Predicate.(map[string]any)["future_metadata"] = map[string]any{"counter": 1}
				valid = true
			case "signed_duplicate_predicate":
				stmt.Predicate = json.RawMessage(`{"run_id":"different","run_id":"run-1","kind":"forensics_bundle"}`)
			}
			var err error
			env, err = attest.Sign(stmt, producer, env.Signatures[0].KeyID)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "payload_type":
				env.PayloadType = "application/json"
			case "empty_signatures":
				env.Signatures = []attest.Signature{}
			case "too_many_signatures":
				for len(env.Signatures) <= maxSourceSignatures {
					env.Signatures = append(env.Signatures, env.Signatures[0])
				}
			case "bad_base64":
				env.Payload = "!"
			case "bad_sig_base64":
				env.Signatures[0].Sig = "!"
			case "duplicate_payload", "case_payload", "subject_alias", "predicate_alias":
				payload, _ := base64.StdEncoding.DecodeString(env.Payload)
				switch mutation {
				case "duplicate_payload":
					payload = append([]byte(`{"_type":"wrong",`), payload[1:]...)
				case "case_payload":
					payload = bytes.Replace(payload, []byte(`"predicateType"`), []byte(`"PredicateType"`), 1)
				case "subject_alias":
					payload = bytes.Replace(payload, []byte(`"name"`), []byte(`"Name"`), 1)
				case "predicate_alias":
					payload = bytes.Replace(payload, []byte(`"run_id"`), []byte(`"RUN_ID"`), 1)
				}
				env.Payload = base64.StdEncoding.EncodeToString(payload)
			}
			writeSourceEnvelope(t, files, m, env)
			if mutation == "duplicate_envelope" {
				raw := files[m.Sources[0].Signature.Path].Data
				files[m.Sources[0].Signature.Path].Data = append([]byte(`{"payload":"wrong",`), raw[1:]...)
			}
			if mutation == "case_envelope" {
				files[m.Sources[0].Signature.Path].Data = bytes.Replace(files[m.Sources[0].Signature.Path].Data, []byte(`"payloadType"`), []byte(`"PayloadType"`), 1)
			}
			resealSourceView(t, files, m, exporter)
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if err != nil || got.FileIntegrity != IntegrityPassed || got.DerivedSignature.Status != SignatureValid {
				t.Fatalf("err=%v result=%+v", err, got)
			}
			if valid {
				requireSource(t, got, SignatureValid, IntegrityPassed, true)
			} else if got.SourceSignatures[0].Status != SignatureInvalid || got.SourceSignatures[0].Trusted {
				t.Fatalf("invalid original accepted: %+v", got.SourceSignatures[0])
			}
		})
	}
}

func TestOriginalUnsignedCommitmentsAndUnsupportedKind(t *testing.T) {
	for _, mode := range []string{"unsigned", "bundle_commitment", "signature_commitment", "both_commitments", "private_db_commitment", "other_kind"} {
		t.Run(mode, func(t *testing.T) {
			files, m, exporter, _, policy := sourceFixture(t)
			want := SignatureNotChecked
			switch mode {
			case "unsigned":
				m.Sources[0].Signature = nil
				want = SignatureUnsigned
			case "bundle_commitment", "both_commitments":
				delete(files, m.Sources[0].Digest.Path)
				m.Sources[0].Digest.Path = ""
			case "other_kind":
				m.Sources[0].Kind = "opaque_source"
			case "private_db_commitment":
				delete(files, m.Sources[0].Digest.Path)
				delete(files, m.Sources[0].Signature.Path)
				m.Sources[0].Kind = "sqlite_snapshot_commitment"
				m.Sources[0].Digest.Path = ""
				m.Sources[0].Signature = nil
			}
			if mode == "signature_commitment" || mode == "both_commitments" {
				delete(files, m.Sources[0].Signature.Path)
				m.Sources[0].Signature.Path = ""
			}
			resealSourceView(t, files, m, exporter)
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if err != nil || got.FileIntegrity != IntegrityPassed || got.SourceSignatures[0].Status != want || got.SourceSignatures[0].Cryptographic != IntegrityNotChecked || got.SourceSignatures[0].Trusted {
				t.Fatalf("err=%v result=%+v", err, got)
			}
		})
	}
}

type countingSourceFS struct {
	fs.FS
	opens map[string]int
}

func (f countingSourceFS) Open(name string) (fs.File, error) {
	f.opens[name]++
	return f.FS.Open(name)
}

func TestOriginalSharedFilesReadOnceAndLimits(t *testing.T) {
	files, m, exporter, _, policy := sourceFixture(t)
	second := m.Sources[0]
	second.ID = "same-original-another-reference"
	m.Sources = append(m.Sources, second)
	resealSourceView(t, files, m, exporter)
	counted := countingSourceFS{FS: files, opens: map[string]int{}}
	got, err := VerifyFS(context.Background(), counted, policy, Limits{})
	if err != nil || got.FileIntegrity != IntegrityPassed || len(got.SourceSignatures) != 2 {
		t.Fatalf("err=%v result=%+v", err, got)
	}
	for _, source := range got.SourceSignatures {
		if source.Status != SignatureValid || !source.Trusted {
			t.Fatalf("invalid shared source: %+v", source)
		}
	}
	for _, name := range []string{m.Sources[0].Digest.Path, m.Sources[0].Signature.Path} {
		if counted.opens[name] != 1 {
			t.Fatalf("read %s %d times", name, counted.opens[name])
		}
	}
	sigPath := m.Sources[0].Signature.Path
	files[sigPath].Data = append(files[sigPath].Data, bytes.Repeat([]byte(" "), int(DefaultLimits().MaxSignatureBytes))...)
	resealSourceView(t, files, m, exporter)
	counted.opens = map[string]int{}
	got, err = VerifyFS(context.Background(), counted, policy, Limits{})
	if !errors.Is(err, ErrLimit) || got.FileIntegrity != IntegrityFailed || counted.opens[sigPath] != 0 {
		t.Fatalf("unbounded signature read: opens=%d err=%v result=%+v", counted.opens[sigPath], err, got)
	}
	if got.SourceSignatures[0].Status != SignatureInvalid || got.SourceSignatures[0].Trusted {
		t.Fatalf("oversized source signature accepted: %+v", got)
	}
}

func TestOriginalCancellation(t *testing.T) {
	files, m, _, _, policy := sourceFixture(t)
	for _, name := range []string{m.Sources[0].Digest.Path, m.Sources[0].Signature.Path} {
		ctx, cancel := context.WithCancel(context.Background())
		got, err := VerifyFS(ctx, cancelFS{FS: files, cancel: cancel, name: name}, policy, Limits{})
		cancel()
		if !errors.Is(err, context.Canceled) || got.FileIntegrity == IntegrityPassed || got.SourceSignatures[0].Trusted {
			t.Fatalf("path=%s err=%v result=%+v", name, err, got)
		}
	}
}

type failingSourceFS struct {
	fs.FS
	path string
}

func (f failingSourceFS) Open(name string) (fs.File, error) {
	if name == f.path {
		return nil, fs.ErrPermission
	}
	return f.FS.Open(name)
}

func TestOriginalReadFailurePreservesOtherSourceResults(t *testing.T) {
	files, m, exporter, _, policy := sourceFixture(t)
	other := m.Sources[0]
	other.ID = "good-original"
	badPath := "originals/unreadable.json"
	files[badPath] = &fstest.MapFile{Data: bytes.Clone(files[other.Digest.Path].Data)}
	m.Sources[0].ID = "unreadable-original"
	m.Sources[0].Digest.Path = badPath
	m.Sources = append(m.Sources, other)
	resealSourceView(t, files, m, exporter)
	got, err := VerifyFS(context.Background(), failingSourceFS{FS: files, path: badPath}, policy, Limits{})
	if !errors.Is(err, fs.ErrPermission) || got.FileIntegrity != IntegrityFailed || len(got.SourceSignatures) != 2 {
		t.Fatalf("err=%v result=%+v", err, got)
	}
	if got.SourceSignatures[0].Status != SignatureInvalid || got.SourceSignatures[0].Trusted || got.SourceSignatures[1].Status != SignatureValid || !got.SourceSignatures[1].Trusted {
		t.Fatalf("sources did not retain independent results: %+v", got.SourceSignatures)
	}
}

func TestOriginalMultipleSignaturesAreKeyScoped(t *testing.T) {
	for _, mode := range []string{"valid_producer", "untrusted_role", "unknown_and_invalid", "mislabelled_producer"} {
		t.Run(mode, func(t *testing.T) {
			files, m, exporter, producer, policy := sourceFixture(t)
			env, stmt := sourceEnvelope(t, files, m)
			exporterID := attest.KeyID(exporter.Public().(ed25519.PublicKey))
			producerID := attest.KeyID(producer.Public().(ed25519.PublicKey))
			exporterEnv, err := attest.Sign(stmt, exporter, exporterID)
			if err != nil {
				t.Fatal(err)
			}
			want, crypto, trusted := SignatureValid, IntegrityPassed, true
			switch mode {
			case "valid_producer":
				env.Signatures = append(exporterEnv.Signatures, env.Signatures...)
			case "untrusted_role":
				env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				env.Signatures = append(env.Signatures, exporterEnv.Signatures...)
				want, trusted = SignatureUntrustedRole, false
			case "unknown_and_invalid":
				env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				exporterEnv.Signatures[0].KeyID = "unknown"
				env.Signatures = append(env.Signatures, exporterEnv.Signatures...)
				want, crypto, trusted = SignatureUnknownKey, IntegrityNotChecked, false
			case "mislabelled_producer":
				// A signature that claims producerID must not authorize another
				// signature in the envelope whose keyid only allows exporter.
				env.Signatures[0].Sig = exporterEnv.Signatures[0].Sig
				env.Signatures[0].KeyID = producerID
				env.Signatures = append(env.Signatures, exporterEnv.Signatures...)
				want, trusted = SignatureUntrustedRole, false
			}
			writeSourceEnvelope(t, files, m, env)
			resealSourceView(t, files, m, exporter)
			got, err := VerifyFS(context.Background(), files, policy, Limits{})
			if err != nil || got.FileIntegrity != IntegrityPassed {
				t.Fatalf("err=%v result=%+v", err, got)
			}
			requireSource(t, got, want, crypto, trusted)
		})
	}
}

func FuzzOriginalDSSE(f *testing.F) {
	files, m, _, _, policy := sourceFixture(f)
	f.Add(files[m.Sources[0].Signature.Path].Data)
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","signatures":[]}`))
	f.Add([]byte(`{"payload":"a","payload":"b"}`))
	keyIDs := make([]string, 0, len(policy.Keys))
	for id := range policy.Keys {
		keyIDs = append(keyIDs, id)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if int64(len(raw)) > DefaultLimits().MaxSignatureBytes {
			t.Skip()
		}
		result, err := verifySourceEnvelope(context.Background(), raw, policy, keyIDs)
		if err != nil {
			t.Fatal(err)
		}
		if result.signature.Trusted && (result.signature.Status != SignatureValid || result.signature.Cryptographic != IntegrityPassed || !validDigest(result.subjectDigest)) {
			t.Fatal("trusted source lacks validated crypto/subject")
		}
	})
}
