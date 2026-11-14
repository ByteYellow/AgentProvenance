package handoff

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestExecutionConfig(t *testing.T) {
	valid := `{"target":{"producer_id":"vm","instance_id":"one","generation":"first"},"caller":{"principal_id":"router","producer_id":"mac","namespace":"user"}}`
	c, err := ReadConfig(strings.NewReader(valid))
	if err != nil || c.Concurrency != 2 || c.Principal().ID != "router" || c.Principal().AllowedTargets[0] != c.Target {
		t.Fatalf("valid configuration: %+v %v", c, err)
	}
	for _, input := range []string{"null", `{}`, valid + `{}`, valid + strings.Repeat(" ", 64<<10),
		strings.TrimSuffix(valid, "}") + `,"auth_token":"not-configurable"}`,
		strings.TrimSuffix(valid, "}") + `,"concurrency":33}`} {
		if _, err := ReadConfig(strings.NewReader(input)); err == nil {
			t.Fatal("accepted invalid execution configuration")
		}
	}
}

func TestExecutionCaptureConfig(t *testing.T) {
	base := `{"target":{"producer_id":"vm","instance_id":"one","generation":"first"},"caller":{"principal_id":"router","producer_id":"mac","namespace":"user"},"capture":`
	if _, err := ReadConfig(strings.NewReader(base + `{"mode":"native"}}`)); err != nil {
		t.Fatalf("native capture configuration: %v", err)
	}
	for _, capture := range []string{`{}`, `{"mode":"unknown"}`, `{"mode":"native","ring_buffer_mib":3}`,
		`{"mode":"native","close_timeout_seconds":-1}`, `{"mode":"native","startup_timeout_seconds":121}`,
		`{"mode":"native","tls_targets":["relative/libssl.so"]}`} {
		if _, err := ReadConfig(strings.NewReader(base + capture + `}`)); err == nil {
			t.Fatalf("accepted invalid capture configuration: %s", capture)
		}
	}
}

func TestExecutionDeliveryConfigLoadsRelativePinnedKeys(t *testing.T) {
	root := t.TempDir()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"sender.key": key.Seed(), "receiver.pub": pub} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(hex.EncodeToString(raw)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw := `{"target":{"producer_id":"vm","instance_id":"one","generation":"first"},"caller":{"principal_id":"router","producer_id":"mac","namespace":"user"},"delivery":{"receiver_id":"receiver","sign_key_file":"sender.key","receiver_public_key_file":"receiver.pub"}}`
	c, err := ReadConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	paths, err := store.Init(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := c.DeliveryService(root, Ledger{DB: db, Target: c.Target}, paths)
	if err != nil || s.ReceiverID != "receiver" || !s.ReceiverKey.Equal(pub) {
		t.Fatalf("key configuration: %+v %v", s, err)
	}
	if err := os.Remove(filepath.Join(root, "receiver.pub")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeliveryService(root, Ledger{DB: db, Target: c.Target}, paths); err == nil {
		t.Fatal("missing key silently disabled delivery")
	}
	for _, invalid := range []string{strings.Replace(raw, `"receiver"`, `""`, 1), strings.Replace(raw, `"sender.key"`, `""`, 1), strings.Replace(raw, `"receiver.pub"`, `""`, 1)} {
		if _, err := ReadConfig(strings.NewReader(invalid)); err == nil {
			t.Fatal("accepted incomplete delivery configuration")
		}
	}
}
