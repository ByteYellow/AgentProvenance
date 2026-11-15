package launch

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
)

func checkRemoteExecution(path string) []Check {
	fail := func(name string, detail, fix message) []Check {
		return []Check{makeCheck(name, CheckFail, detail, fix)}
	}
	config, err := readRemoteConfig(path)
	if err != nil {
		return fail("remote route", messagef("route configuration is invalid"), messagef("Check URL, workdir and credential/configuration file paths in %s", path))
	}
	f, err := os.Open(config.ExecutionConfig)
	if err != nil {
		return fail("remote identity", messagef("execution configuration is unavailable"), messagef("Check execution_config: %s", config.ExecutionConfig))
	}
	execution, readErr := handoff.ReadConfig(f)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return fail("remote identity", messagef("caller or target configuration is invalid"), messagef("Check caller, target and capture fields in %s", config.ExecutionConfig))
	}
	token, err := routeToken(config.TokenFile)
	if err != nil {
		return fail("remote credentials", messagef("bearer token file is missing or invalid"), messagef("Check token_file: %s", config.TokenFile))
	}
	key, err := attest.LoadPrivateKeyHex(config.SignKeyFile)
	if err != nil {
		return fail("remote credentials", messagef("receiver signing key is missing or invalid"), messagef("Check sign_key_file: %s", config.SignKeyFile))
	}
	pub, err := attest.LoadPublicKeyHex(config.PublicKeyFile)
	if err != nil {
		return fail("remote credentials", messagef("executor public key is missing or invalid"), messagef("Check public_key_file: %s", config.PublicKeyFile))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := daemon.Client{BaseURL: strings.TrimRight(config.URL, "/"), Token: token, HTTP: &http.Client{Timeout: 5 * time.Second}}
	remote, err := client.ExecutionReadiness(ctx)
	if err != nil {
		// A server error body can contain arbitrary text; never reflect it into
		// diagnostics that operators may export alongside their evidence.
		return fail("remote endpoint", messagef("authenticated readiness query failed"), messagef("Check the endpoint/tunnel, bearer token and executor version; GET /v1/execution-readiness must be available"))
	}
	checks := []Check{makeCheck("remote endpoint", CheckPass, messagef("authenticated read-only readiness query succeeded"))}
	compare := func(name string, ok bool, detail, mismatch, fix message) {
		if ok {
			checks = append(checks, makeCheck(name, CheckPass, detail))
		} else {
			checks = append(checks, makeCheck(name, CheckFail, mismatch, fix))
		}
	}
	compare("remote identity", remote.Target == execution.Target && remote.PrincipalID == execution.Caller.PrincipalID &&
		remote.SourceProducerID == execution.Caller.ProducerID && remote.SourceNamespace == execution.Caller.Namespace,
		messagef("caller and target instance/generation match"), messagef("caller or target identity differs from the executor"), messagef("Match caller and target fields with the executor configuration"))
	compare("remote delivery keys", remote.ReceiverID == config.ReceiverID && remote.TargetKeySHA256 == attest.DigestSHA256(pub) &&
		remote.ReceiverKeySHA256 == attest.DigestSHA256(key.Public().(ed25519.PublicKey)),
		messagef("receiver identity and both public-key fingerprints match"), messagef("receiver identity or delivery keys differ from the executor"), messagef("Match receiver_id, executor public_key_file and the receiver signing key with the executor delivery configuration"))
	compare("remote worker", remote.WorkerRunning, messagef("executor worker is running"), messagef("executor worker is stopped"), messagef("Start the configured executor before launching the agent"))
	waitCapture := execution.Capture != nil
	if config.WaitCapture != nil {
		waitCapture = *config.WaitCapture
	}
	if waitCapture && !remote.NativeCapture {
		checks = append(checks, makeCheck("remote capture", CheckFail, messagef("capture wait is enabled but the executor has no native collector"), messagef("Enable native capture on the executor or set wait_capture=false for separately managed capture")))
	} else if remote.NativeCapture && !remote.CaptureReady {
		checks = append(checks, makeCheck("remote capture", CheckFail, messagef("executor native capture is not ready"), messagef("Inspect executor probe capabilities and permissions before launching the agent")))
	} else if remote.NativeCapture && !waitCapture {
		checks = append(checks, makeCheck("remote capture", CheckWarn, messagef("native capture is enabled; this route may deliver before capture finishes"), messagef("Set wait_capture=true to collect after native capture reaches sealed or incomplete")))
	} else {
		checks = append(checks, makeCheck("remote capture", CheckPass, messagef("wait_capture=%t; executor native_capture=%t", waitCapture, remote.NativeCapture)))
	}
	return checks
}
