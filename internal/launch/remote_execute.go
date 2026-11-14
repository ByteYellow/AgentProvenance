package launch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// ExecuteRemoteCall runs only after the harness has approved the rewritten
// tool. Reinvocation reuses the saved request; it never invents a retry attempt.
func ExecuteRemoteCall(ctx context.Context, routePath, requestPath, nativeCommand string, stdout, stderr io.Writer) (exitCode int, resultErr error) {
	route, err := ReadRemoteRoute(routePath)
	if err != nil {
		return 1, err
	}
	if filepath.Dir(requestPath) != filepath.Dir(routePath) {
		return 1, fmt.Errorf("prepared remote command must belong to this route")
	}
	var prepared PreparedRemoteCall
	if err := readRouteJSON(requestPath, &prepared, 2<<20); err != nil {
		return 1, err
	}
	request, _, digest, err := prepared.Request.Canonical()
	if err != nil || prepared.SchemaVersion != remoteRouteSchema || digest != prepared.RequestHash ||
		request.Source.RunID != route.RunID || request.Source.Harness != "claude" ||
		route.Principal.Authorize(request.Source, request.Target) != nil || request.Target != route.Target ||
		len(request.Command.Argv) != 3 || request.Command.Argv[0] != route.Config.Shell || request.Command.Argv[1] != "-lc" ||
		request.Command.Argv[2] != nativeCommand || request.Command.Workdir != route.Config.Workdir ||
		request.Command.DisableSnapshot != !route.Config.FileDiff || request.Command.CapturePreset != route.Policy.Preset ||
		request.Command.ToolResults == nil || *request.Command.ToolResults != route.Policy.ToolResults ||
		prepared.TimeoutMS < 1 || prepared.TimeoutMS > int64(route.Config.TimeoutSeconds)*1000 {
		return 1, fmt.Errorf("prepared native command identity or digest mismatch")
	}
	token, err := routeToken(route.Config.TokenFile)
	if err != nil {
		return 1, err
	}
	key, err := attest.LoadPrivateKeyHex(route.Config.SignKeyFile)
	if err != nil {
		return 1, err
	}
	pub, err := attest.LoadPublicKeyHex(route.Config.PublicKeyFile)
	if err != nil {
		return 1, err
	}
	paths, err := store.Init(route.DataDir)
	if err != nil {
		return 1, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return 1, err
	}
	defer db.Close()
	receiver := &handoff.DeliveryReceiver{DB: db, Paths: paths, ID: route.Config.ReceiverID, SignKey: key,
		Target: route.Target, TargetKey: pub, Caller: route.Principal}
	client := daemon.Client{BaseURL: strings.TrimRight(route.Config.URL, "/"), Token: token,
		HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(prepared.TimeoutMS)*time.Millisecond)
	defer cancel()
	admission, err := client.SubmitExecution(ctx, request)
	if err != nil {
		return 1, fmt.Errorf("remote admission unavailable; reuse the prepared request to recover: %w", err)
	}
	_, _, admittedHash, canonicalErr := admission.Attempt.Request.Canonical()
	if canonicalErr != nil || admission.SchemaVersion != handoff.SchemaVersion || admission.Attempt.SchemaVersion != handoff.SchemaVersion ||
		admission.Attempt.ID == "" || admission.Attempt.LocalRunID == "" || admittedHash != digest ||
		admission.Attempt.RequestHash != digest || admission.Attempt.DigestVersion != handoff.DigestVersion {
		return 1, fmt.Errorf("remote admission does not match prepared command")
	}
	// Cancellation can arrive while saving admission or collecting evidence,
	// not only during status polling. Stop only the authenticated attempt.
	defer func() {
		if ctx.Err() == nil {
			return
		}
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		stop, stopErr := client.StopExecution(stopCtx, admission.Attempt.ID, "wrapper-stop-"+request.OperationID)
		if stopErr == nil {
			fmt.Fprintf(stderr, "agentprov: stop request %s; query the prepared request for its observed result\n", stop.State)
		}
		exitCode = 1
		resultErr = errors.Join(resultErr, ctx.Err(), stopErr)
	}()
	if receiver.SourceAdmissionRef, err = receiver.RecordAdmission(ctx, request, admission.Attempt); err != nil {
		return 1, fmt.Errorf("remote execution accepted but source evidence could not be saved; reuse the prepared request to recover: %w", err)
	}
	admissionPath := strings.TrimSuffix(requestPath, ".json") + "-admission.json"
	if err := saveRouteJSON(admissionPath, admission, true); err != nil {
		return 1, fmt.Errorf("remote execution accepted but local admission could not be saved: %w", err)
	}
	fmt.Fprintf(stderr, "agentprov: remote attempt %s; source %s/%s; instance %s\n", admission.Attempt.ID, request.Source.SessionID, request.Source.ToolCallID, request.Target.InstanceID)
	report, err := waitRemoteCall(ctx, client, admission, route.WaitCapture)
	if err != nil {
		return 1, err
	}
	collection, err := client.CollectExecution(ctx, handoff.IdentityOf(admission.Attempt), "native-result-"+request.OperationID, receiver)
	collectionPath := strings.TrimSuffix(requestPath, ".json") + "-collection.json"
	if len(collection.Receipt) != 0 {
		err = errors.Join(err, saveRouteJSON(collectionPath, collection, true))
	}
	if err != nil {
		return 1, fmt.Errorf("remote execution ended; evidence delivery %s (reuse this request, not a new execution): %w", collection.Status, err)
	}
	// Read output from the locally verified signed projection, not from an
	// unsigned body in the status response or a remote working-directory path.
	var checkpoint handoff.Checkpoint
	if report.CheckpointRef == "" {
		return 1, fmt.Errorf("remote execution ended without a checkpoint reference")
	}
	if err := provenance.ReadObjectPayload(db, admission.Attempt.LocalRunID, report.CheckpointRef, &checkpoint); err != nil {
		return 1, err
	}
	if checkpoint.AttemptID != admission.Attempt.ID || checkpoint.RequestHash != digest || checkpoint.Result == nil {
		return 1, fmt.Errorf("signed checkpoint has no matching execution result")
	}
	if checkpoint.Error != "" && (checkpoint.Stdout == nil || checkpoint.Stderr == nil) {
		return 1, fmt.Errorf("remote execution %s: %s", checkpoint.State.Execution, checkpoint.Error)
	}
	for _, output := range []struct {
		name string
		data *handoff.Output
		to   io.Writer
	}{{"stdout", checkpoint.Stdout, stdout}, {"stderr", checkpoint.Stderr, stderr}} {
		if output.data == nil || output.data.Ref == "" {
			return 1, fmt.Errorf("remote %s is unavailable in the signed result", output.name)
		}
		for offset := int64(0); ; {
			page, err := provenance.ReadTextContentPage(db, admission.Attempt.LocalRunID, output.data.Ref, offset, provenance.MaxContentPageBytes)
			if err != nil {
				return 1, err
			}
			if _, err := io.WriteString(output.to, page.Content); err != nil {
				return 1, err
			}
			if !page.HasMore {
				break
			}
			offset = page.NextOffset
		}
		if output.data.State == "truncated" {
			fmt.Fprintf(stderr, "\nagentprov: %s truncated by execution output retention limit\n", output.name)
		}
	}
	fmt.Fprintf(stderr, "\nagentprov: execution=%s capture=%s delivery=%s; saved admission %s\n",
		checkpoint.State.Execution, checkpoint.State.Capture, collection.Status, admissionPath)
	return checkpoint.Result.ExitCode, nil
}

func waitRemoteCall(ctx context.Context, client daemon.Client, admission daemon.ExecutionAdmission, waitCapture bool) (handoff.Report, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		report, err := client.Execution(ctx, admission.Attempt.ID)
		if err != nil {
			return report, err
		}
		if report.Attempt.ID != admission.Attempt.ID || report.Attempt.RequestHash != admission.Attempt.RequestHash ||
			report.Attempt.Request.Source != admission.Attempt.Request.Source || report.Attempt.Request.Target != admission.Attempt.Request.Target {
			return report, fmt.Errorf("remote status identity changed")
		}
		switch report.Attempt.State.Execution {
		case handoff.Unknown:
			return report, fmt.Errorf("remote execution result is unknown; inspect the saved attempt before retrying")
		case handoff.Succeeded, handoff.Failed, handoff.Cancelled:
			if !waitCapture || report.Attempt.State.Capture == handoff.Sealed || report.Attempt.State.Capture == handoff.Incomplete {
				return report, nil
			}
		}
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		case <-ticker.C:
		}
	}
}

func remoteHookError(err error) map[string]any {
	return map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse",
		"permissionDecision": "deny", "permissionDecisionReason": "Remote execution preparation failed: " + err.Error()}}
}

// RemoteHookOutput makes preparation failures explicit to Claude instead of
// falling back to executing the original command on the caller's machine.
func RemoteHookOutput(route string, raw []byte) ([]byte, error) {
	output, err := PrepareClaudeRemoteCall(route, raw)
	if err != nil {
		output = remoteHookError(err)
	}
	return json.Marshal(output)
}
