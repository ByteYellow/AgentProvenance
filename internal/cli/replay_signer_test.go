package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/derivedview"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/viewverify"
)

func TestDashboardExportSignerAndRecipientCLI(t *testing.T) {
	t.Setenv("AGENTPROV_DAEMON_URL", "")
	root := t.TempDir()
	dataDir := filepath.Join(root, "store")
	db, cleanup, err := openLocalDB(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	body := "saved message"
	_, err = (agentcontext.Service{DB: db, Paths: store.ResolvePaths(dataDir)}).Save(context.Background(), "run",
		agentcontext.Source{Harness: "fixture", SessionID: "s", ParserVersion: "fixture/v1", Binding: "explicit"},
		[]agentcontext.Record{{Key: "message", Kind: "message", Body: &body}}, agentcontext.Coverage{Status: agentcontext.OK})
	if err != nil {
		t.Fatal(err)
	}
	pub, key, keyID, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath, policyPath := filepath.Join(root, "private.hex"), filepath.Join(root, "trust.json")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key.Seed())), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := json.Marshal(viewverify.PolicyFile{SchemaVersion: viewverify.PolicySchema, ID: "recipient",
		Keys: []viewverify.PolicyKey{{KeyID: keyID, PublicKeyHex: hex.EncodeToString(pub), Roles: []string{"exporter"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, policy, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := NewRootCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(append([]string{"--data-dir", dataDir}, args...))
		err := cmd.Execute()
		return out.String(), err
	}
	zipPath := filepath.Join(root, "reader.zip")
	for _, args := range [][]string{{"--sign-key", keyPath}, {"--exporter-id", "operator"}} {
		if _, err := run(append([]string{"dashboard", "export", "--run", "run", "--output", zipPath}, args...)...); err == nil {
			t.Fatal("incomplete signing configuration succeeded")
		}
		if _, err := os.Stat(zipPath); !os.IsNotExist(err) {
			t.Fatal("invalid configuration published output")
		}
	}
	out, err := run("dashboard", "export", "--run", "run", "--output", zipPath, "--sign-key", keyPath, "--exporter-id", "operator")
	if err != nil || !strings.Contains(out, "signed=true") {
		t.Fatalf("export: %s %v", out, err)
	}
	for _, trusted := range []bool{false, true} {
		args := []string{"evidence", "verify-view", zipPath}
		if trusted {
			args = append(args, "--trust-policy", policyPath)
		}
		out, err := run(args...)
		if (err == nil) != trusted {
			t.Fatalf("trust=%t: %s %v", trusted, out, err)
		}
		var result derivedview.Result
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if result.FileIntegrity != derivedview.IntegrityPassed || result.DerivedSignature.Trusted != trusted {
			t.Fatalf("verification result: %+v", result)
		}
	}
}
