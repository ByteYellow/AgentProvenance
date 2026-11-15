package launch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/record"
)

func TestRemotePreflightStopsLaunchBeforeAgentOrStore(t *testing.T) {
	x := newRemoteFixture(t)
	var config RemoteExecutionConfig
	if err := readRouteJSON(x.config, &config, 64<<10); err != nil {
		t.Fatal(err)
	}
	config.ReceiverID = "wrong-receiver"
	if err := saveRouteJSON(x.config, config, true); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	marker, command := filepath.Join(root, "agent-started"), filepath.Join(root, "claude")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nprintf started > "+shQuote(marker)+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	data := filepath.Join(root, "caller-store")
	_, err := Run(Options{DataDir: data, Workdir: root, Command: []string{command}, Sensor: "off",
		RemoteExecution: x.config, SelfExe: os.Args[0], Stdout: &output, Stderr: &output})
	if err == nil || !strings.Contains(err.Error(), "receiver_id") {
		t.Fatalf("preflight did not reject receiver mismatch: %v", err)
	}
	for _, path := range []string{marker, data} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("launch caused side effects before matching its remote configuration: %s %v", path, err)
		}
	}
}

func TestRemotePreflightIdentityKeysAndNoExecution(t *testing.T) {
	for _, issue := range []string{"none", "target", "caller", "receiver", "executor_key", "receiver_key", "token", "wait", "stopped"} {
		t.Run(issue, func(t *testing.T) {
			x := newRemoteFixture(t)
			var config RemoteExecutionConfig
			if err := readRouteJSON(x.config, &config, 64<<10); err != nil {
				t.Fatal(err)
			}
			config.URL += "/"
			root := filepath.Dir(x.config)
			var execution handoff.Config
			if err := readRouteJSON(filepath.Join(root, config.ExecutionConfig), &execution, 64<<10); err != nil {
				t.Fatal(err)
			}
			switch issue {
			case "target":
				execution.Target.Generation = "other"
			case "caller":
				execution.Caller.ProducerID = "other"
			case "receiver":
				config.ReceiverID = "other"
			case "executor_key", "receiver_key":
				pub, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				data, path := []byte(hex.EncodeToString(pub)), config.PublicKeyFile
				if issue == "receiver_key" {
					data, path = []byte(hex.EncodeToString(key)), config.SignKeyFile
				}
				if err := os.WriteFile(filepath.Join(root, path), data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "token":
				if err := os.WriteFile(filepath.Join(root, config.TokenFile), []byte("wrong-token"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "wait":
				yes := true
				config.WaitCapture = &yes
			case "stopped":
				if err := x.stop(); err != nil {
					t.Fatal(err)
				}
			}
			if err := saveRouteJSON(filepath.Join(root, config.ExecutionConfig), execution, true); err != nil {
				t.Fatal(err)
			}
			if err := saveRouteJSON(x.config, config, true); err != nil {
				t.Fatal(err)
			}
			report := PreflightReport{Checks: checkRemoteExecution(x.config)}
			if report.HasFailures() != (issue != "none") {
				t.Fatalf("unexpected checks: %+v", report.Checks)
			}
			var count int
			if err := x.server.DB.QueryRow("SELECT count(*) FROM execution_attempts").Scan(&count); err != nil || count != 0 {
				t.Fatalf("preflight dispatched work: %d %v", count, err)
			}
			encoded, _ := json.Marshal(report)
			for _, path := range []string{config.TokenFile, config.SignKeyFile} {
				secret, err := os.ReadFile(filepath.Join(root, path))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), string(secret)) {
					t.Fatal("preflight exposed a credential")
				}
			}
		})
	}
}

func TestRemotePreflightCaptureMismatchAndReadiness(t *testing.T) {
	for _, test := range []struct {
		name  string
		ready bool
		want  CheckStatus
	}{
		{"early_delivery", true, CheckWarn}, {"probes_not_ready", false, CheckFail},
	} {
		t.Run(test.name, func(t *testing.T) {
			x := remoteFixtureWithTransport(t, record.Options{AllowShell: true}, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.URL.Path != "/v1/execution-readiness" {
					next.ServeHTTP(w, r)
					return
				}
				original := httptest.NewRecorder()
				next.ServeHTTP(original, r)
				var body daemon.ExecutionReadiness
				if err := json.Unmarshal(original.Body.Bytes(), &body); err != nil {
					t.Error(err)
					return
				}
				body.NativeCapture, body.CaptureReady = true, test.ready
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(body)
			})
			report := PreflightReport{Checks: checkRemoteExecution(x.config)}
			check := findCheck(t, report, "remote capture")
			if check.Status != test.want || check.Fix == "" {
				t.Fatalf("capture check: %+v", check)
			}
		})
	}
}

func TestRemotePreflightDoesNotFollowRedirectOrReflectServerText(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "redirect"}[redirect], func(t *testing.T) {
			var forwarded atomic.Bool
			destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Store(true) }))
			defer destination.Close()
			x := remoteFixtureWithTransport(t, record.Options{AllowShell: true}, func(w http.ResponseWriter, r *http.Request, _ http.Handler) {
				if redirect {
					http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
				} else {
					w.WriteHeader(500)
					_, _ = w.Write([]byte(`{"error":"private-upstream-detail"}`))
				}
			})
			checks := checkRemoteExecution(x.config)
			raw, _ := json.Marshal(checks)
			if forwarded.Load() || strings.Contains(string(raw), "private-upstream-detail") || len(checks) != 1 || checks[0].Status != CheckFail {
				t.Fatalf("unsafe diagnostic: %s", raw)
			}
		})
	}
}
