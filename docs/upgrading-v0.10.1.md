# Upgrading to v0.10.1

English | [中文](zh-CN/upgrading-v0.10.1.md)

This guide describes the upcoming v0.10.1 changes. It applies to source builds
on the integration branch; v0.10.0 remains the latest published release.

Stop writers and back up the complete data directory before upgrading. Keep the
older binary with that backup if you need to return to the earlier version.
Keep original signed bundles and their public keys unchanged.

## Choose the execution path

Local `launch` and `record` keep terminal input, Ctrl-C, long-running commands,
the caller's environment and arbitrary working directories. Use these commands
for interactive Agents, API keys, proxy variables and virtual environments:

```sh
agentprov --data-dir "$HOME/.agentprov" launch --workdir "$PWD" -- claude
agentprov --data-dir "$HOME/.agentprov" record --workdir "$PWD" -- python3 task.py
```

The authenticated HTTP `POST /v1/record` endpoint has a separate execution policy:

| Setting | HTTP default | Migration |
| --- | --- | --- |
| Execution timeout | 60 seconds | Set `daemon serve --record-timeout 10m` for longer jobs; a negative duration explicitly disables the limit |
| Shell as the first executable | Refused | Name the program directly, or enable `--record-allow-shell` on the daemon |
| Working directory | Inside `<data-dir>/workspaces` | Place the workload there; omitting `workdir` creates a directory for the Run |
| Child environment | `PATH`, `HOME`, `TMPDIR`, `TERM` | Use local recording for tasks that need the caller's full environment |

For example, start a daemon for authenticated shell jobs with a ten-minute limit:

```sh
agentprov --data-dir "$HOME/.agentprov" daemon serve \
  --listen 127.0.0.1:8574 --record-timeout 10m --record-allow-shell
```

The timeout terminates the recorded process group. Client timeouts are separate:
set the SDK's `timeout` long enough for the chosen server limit.
The daemon executes authorized programs with its operating-system privileges;
the shell setting controls command form, not isolation. Give its token only to
trusted callers.

## Connect to the daemon

The daemon now requires a bearer token. Its default token is generated once and
reused from `<data-dir>/auth-token`, with mode `0600`. Startup prints a newly
generated token; protect service logs accordingly. `--auth-token` or
`AGENTPROV_DAEMON_TOKEN` overrides this file and is not saved back to it.

CLI clients automatically read the token from their selected data directory:

```sh
agentprov --data-dir "$HOME/.agentprov" --daemon-url http://127.0.0.1:8574 \
  telemetry list --run RUN_ID --json
```

Direct HTTP and Python SDK clients must supply the token. For a local shell:

```sh
export AGENTPROV_DAEMON_TOKEN="$(cat "$HOME/.agentprov/auth-token")"
curl --fail-with-body 'http://127.0.0.1:8574/v1/telemetry/events?run=RUN_ID' \
  -H "Authorization: Bearer $AGENTPROV_DAEMON_TOKEN"
```

If you configured your own token, pass that value instead. The SDK reads
`AGENTPROV_DAEMON_TOKEN` from its `env` argument or the process environment;
`data_dir` alone does not configure authentication for direct HTTP requests.
See the [Python example](python-sdk.md#client-configuration).

- GET `/v1/health`, `/v1/ready` and `/v1/live` remain anonymous health checks.
- Body-bearing writes require `Content-Type: application/json`.
- Browser requests require a matching Origin; writes also validate Fetch
  Metadata. A token does not waive these checks.
- `--insecure-open` is an explicit local-development option. Keep normal
  deployments authenticated. Browser guards and path restrictions remain active.

To materialize a manifest, switch to POST:

```sh
curl --fail-with-body http://127.0.0.1:8574/v1/evidence/manifest \
  -H "Authorization: Bearer $AGENTPROV_DAEMON_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"run_id":"RUN_ID"}'
```

Ordinary GET stays read-only. The legacy `GET ...?materialize=1` form requires
authentication even in open mode. The CLI handles POST automatically through
`evidence manifest --run RUN_ID --materialize`.

Server-side file ingestion is restricted to `<data-dir>/ingest`, or the directory
chosen with `--ingest-allow-dir`. This affects task YAML paths supplied to
`/v1/leases` and files supplied to `/v1/telemetry/ingest-falco`. Put the files in
that server directory; symlinks escaping the directory are rejected.

## Import a historical bundle

Imports verify a DSSE signature before writing to the store. Obtain the public
key from the publisher or another trusted channel, and keep the companion
attestation beside the bundle:

```text
capture.forensics.json.gz
capture.forensics.dsse.json
publisher.pub
```

```sh
agentprov --data-dir ./replay forensics import capture.forensics.json.gz \
  --pub-key publisher.pub --json
```

Successful output contains `attestation_verified: true` and
`attestation_status: "verified"`. Existing signed demos use their bundled public
keys; `agentprov demo` handles this automatically.

For a trusted historical capture that has no signature, explicitly select the
unverified path:

```sh
agentprov --data-dir ./replay forensics import unsigned.json \
  --allow-unverified --json
```

This emits a warning and marks the result `unverified`. If both flags are
present, `--pub-key` takes precedence: a wrong key, missing attestation or altered
bundle still fails. There is no fallback after failed verification.

JSON fields and generated import diagnostics stay English. `--lang zh-CN`
localizes terminal help and text-mode diagnostics. Original evidence keeps its
recorded language.

## Docker-backed compatibility commands

Docker `lease`, `session` and `api` commands drop all Linux capabilities and set
`no-new-privileges`. On Unix, their default container account is the invoking
CLI or daemon's effective UID:GID, so the bind-mounted workspace remains writable.
Non-root default accounts use `HOME=/tmp`; install dependencies in a project
directory or virtual environment.

Set `user: "1000:1000"` in the task YAML when an image needs a specific account,
and give that account access to the workspace. Explicit users keep the image's
home environment. Rootless Docker may need a different mapped account. See
[Docker session compatibility](deployment-modes.md#docker-session-compatibility)
for mappings and the Docker 29.0–29.2 API override. Local `launch`, `record` and
replay do not use this Docker client.

## Reading evidence after the upgrade

- Tool-level intent coverage is separate from other calls by the same Agent.
- Delegation details retain candidate messages when execution ownership is
  ambiguous. Endpoint details separate body matches, source-read candidates and
  execution attribution.
- TLS readers show complete messages, incomplete fragments and historical
  unknown status. Gaps do not become model commands or reconstructed full bodies.

These details use the existing Dashboard layout and follow selected evidence
into offline replay. Original signed bundles keep their original analysis;
newly computed relationships carry their own rule version.

[Release notes draft](releases/v0.10.1.md) · [Deployment modes](deployment-modes.md)
