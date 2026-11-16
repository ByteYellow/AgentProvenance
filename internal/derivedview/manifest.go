package derivedview

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/attest"
)

// CanonicalManifest returns the v1 wire encoding: encoding/json's compact struct
// encoding, UTF-8, no trailing newline, Files sorted by exact path. It fills the
// schema and file-list digest if omitted; a supplied digest must agree. This is a
// version-specific encoding, not a claim to implement RFC 8785 for arbitrary JSON.
// Other arrays retain caller order. No input slices are reordered in place.
func CanonicalManifest(m Manifest) ([]byte, error) {
	if m.SchemaVersion == "" {
		m.SchemaVersion = SchemaVersion
	}
	m.Files = append([]File{}, m.Files...)
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	files, err := json.Marshal(m.Files)
	if err != nil {
		return nil, err
	}
	digest := attest.DigestSHA256(files)
	if m.FilesSHA256 != "" && m.FilesSHA256 != digest {
		return nil, fmt.Errorf("%w: file-list digest mismatch", ErrInvalid)
	}
	m.FilesSHA256 = digest
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// Sign seals an existing inventory; it does not read or write any payload. It
// returns exactly the bytes to write at ManifestPath and SignaturePath. The DSSE
// in-toto subject is the canonical manifest digest; the manifest commits to every
// other file. Neither reserved metadata path may appear in Files, so there is no
// self-digest cycle. Sign fills a missing key ID, role and public key.
func Sign(m Manifest, key ed25519.PrivateKey) (manifest, signature []byte, err error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
		return nil, nil, fmt.Errorf("%w: invalid Ed25519 private key", ErrInvalid)
	}
	pub := key.Public().(ed25519.PublicKey)
	encodedKey := base64.StdEncoding.EncodeToString(pub)
	if m.Exporter.PublicKey != "" && m.Exporter.PublicKey != encodedKey {
		return nil, nil, fmt.Errorf("%w: exporter key does not match signer", ErrInvalid)
	}
	m.Exporter.PublicKey = encodedKey
	if m.Exporter.KeyID == "" {
		m.Exporter.KeyID = attest.KeyID(pub)
	}
	if m.Exporter.Role == "" {
		m.Exporter.Role = RoleExporter
	}
	manifest, err = CanonicalManifest(m)
	if err != nil {
		return nil, nil, err
	}
	env, err := attest.Sign(statement(m.Exporter, manifest), key, m.Exporter.KeyID)
	if err != nil {
		return nil, nil, err
	}
	signature, err = json.Marshal(env)
	return manifest, signature, err
}

func statement(exporter Exporter, manifest []byte) attest.Statement {
	stmt := attest.NewStatement(ManifestPath, attest.DigestSHA256(manifest), struct {
		Exporter Exporter `json:"exporter"`
	}{exporter})
	stmt.PredicateType = SchemaVersion
	return stmt
}

func parseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if err := decodeStrict(raw, &m); err != nil {
		return m, err
	}
	canonical, err := CanonicalManifest(m)
	if err != nil {
		return m, err
	}
	if !bytes.Equal(raw, canonical) {
		return m, fmt.Errorf("%w: manifest is not in canonical v1 encoding", ErrInvalid)
	}
	return m, nil
}

func validateManifest(m Manifest) error {
	fail := func(message string) error { return fmt.Errorf("%w: %s", ErrInvalid, message) }
	if !validStrings(reflect.ValueOf(m)) {
		return fail("metadata strings must be UTF-8")
	}
	if m.SchemaVersion != SchemaVersion {
		return fail("unsupported schema version")
	}
	if _, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err != nil {
		return fail("created_at must be RFC3339")
	}
	if m.Exporter.ID == "" || m.Exporter.KeyID == "" || m.Exporter.Role != RoleExporter {
		return fail("exporter ID, key ID and exporter role are required")
	}
	if m.Exporter.PublicKey != "" {
		pub, err := base64.StdEncoding.Strict().DecodeString(m.Exporter.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(pub) != m.Exporter.PublicKey {
			return fail("invalid exporter public key")
		}
	}
	if m.Projection.Version == "" || !validDigest(m.Projection.SHA256) || !validDigest(m.Projection.ImplementationSHA256) {
		return fail("projection version and SHA256 digests are required")
	}
	files := make(map[string]File, len(m.Files))
	paths := pathSet{limits: DefaultLimits()}
	for _, file := range m.Files {
		if file.Path == ManifestPath || file.Path == SignaturePath {
			return fail("reserved metadata cannot be in the file inventory")
		}
		if err := paths.add(file.Path, false); err != nil {
			return err
		}
		if file.Bytes < 0 || !validDigest(file.SHA256) {
			return fail("invalid file length or SHA256")
		}
		files[file.Path] = file
	}
	checkRef := func(ref Reference) error {
		if !validDigest(ref.SHA256) {
			return fail("invalid reference SHA256")
		}
		if ref.Path != "" {
			file, found := files[ref.Path]
			if !found || file.SHA256 != ref.SHA256 {
				return fail("delivered reference must match a file inventory member")
			}
		}
		return nil
	}
	if err := checkRef(m.Selection); err != nil {
		return err
	}
	for _, ref := range []*Reference{m.IncludedRecords, m.IncludedAttachments} {
		if ref != nil {
			if err := checkRef(*ref); err != nil {
				return err
			}
		}
	}
	if len(m.Sources) == 0 {
		return fail("at least one source commitment is required")
	}
	ids := map[string]bool{}
	for _, source := range m.Sources {
		if source.ID == "" || source.Kind == "" || ids[source.ID] {
			return fail("source IDs must be nonempty and unique; source kind is required")
		}
		ids[source.ID] = true
		if err := checkRef(source.Digest); err != nil {
			return err
		}
		if source.Signature != nil {
			if err := checkRef(*source.Signature); err != nil {
				return err
			}
		}
	}
	switch m.Coverage.State {
	case CoverageComplete:
		if m.Coverage.Scope == "" || len(m.Coverage.Gaps) != 0 {
			return fail("complete coverage requires a scope and no gaps")
		}
	case CoverageGaps:
		if len(m.Coverage.Gaps) == 0 {
			return fail("gapped coverage requires at least one gap")
		}
	case CoverageUnknown:
		if len(m.Coverage.Gaps) != 0 {
			return fail("known gaps must use the gaps coverage state")
		}
	default:
		return fail("invalid coverage state")
	}
	for _, gaps := range [][]Gap{m.Coverage.Gaps, m.Exclusions} {
		for _, gap := range gaps {
			if gap.Category == "" || gap.Reason == "" || gap.Count < 0 {
				return fail("invalid gap or exclusion summary")
			}
		}
	}
	capabilities := map[string]bool{}
	for _, capability := range m.Coverage.Capabilities {
		if capability.Name == "" || capability.Status == "" || capabilities[capability.Name] {
			return fail("invalid or duplicate capability")
		}
		capabilities[capability.Name] = true
	}
	return nil
}

func validDigest(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validStrings(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return utf8.ValidString(v.String())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !validStrings(v.Field(i)) {
				return false
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if !validStrings(v.Index(i)) {
				return false
			}
		}
	case reflect.Pointer:
		return v.IsNil() || validStrings(v.Elem())
	}
	return true
}
