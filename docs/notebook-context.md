# Jupyter request and output context

English | [中文](zh-CN/notebook-context.md)

Record a selected Jupyter client's messages, then import them into an existing
AgentProvenance Run. The adapter records native requests and outputs without
changing the kernel's code execution or retry behavior.

## Integration

Use `agentprov.notebook.Recorder` from the repository's optional Python package.
It has no Jupyter dependency itself. The live fixture uses
`jupyter-client==8.6.3` and `ipykernel==6.29.5`.

After your client connects and completes its readiness handshake:

```python
from agentprov.notebook import Recorder

info = client.kernel_info(reply=True, timeout=15)
scope = {
    "producer_id": "notebook-router", "namespace": "team-a",
    "instance_id": "vm-a", "generation": "lifecycle-1",
    "notebook_id": "analysis", "kernel_id": "kernel-resource-id",
    "kernel_session_id": info["header"]["session"],
}

with Recorder("capture.jsonl", scope, client_version="8.6.3") as capture:
    request = client.session.msg("execute_request", content={
        "code": "print(7 + 11)", "silent": False, "store_history": True,
        "user_expressions": {}, "allow_stdin": False, "stop_on_error": True,
    })
    client.shell_channel.send(request)
    capture.record("shell", "send", request)
    # In the tool's existing receive loop, record every decoded message:
    # capture.record("iopub", "receive", client.get_iopub_msg(timeout=...))
    # capture.record("shell", "receive", client.get_shell_msg(timeout=...))
```

Keep using your existing receive loop and cancellation policy. The recorder does
not consume channels, resend requests, or infer that a failed recording means a
command was never sent. Record each channel at one collection point to avoid
duplicating broadcast observations. Connection files, authentication keys, and
ZeroMQ routing frames are outside the transcript.

The output is a new `0600` file. It contains source inputs and outputs; keep it
private. Import applies AgentProvenance's existing redaction and retention:

```bash
agentprov context import --run RUN_ID --harness jupyter --file capture.jsonl --capture detailed
agentprov context project --run RUN_ID
agentprov context list --run RUN_ID
agentprov context coverage --run RUN_ID
```

Use `--capture basic` on a new Run to omit result bodies and source projections,
or `--capture-tool-results=false` to exclude results from detailed capture.
Request and parent identities remain available in both presets. The private
source file is separate from the retained evidence store; remove or retain it
under your own source-log policy.

## Association and lifecycle

- The launcher supplies producer, namespace, instance and generation. The kernel
  session comes from a native `kernel_info_reply`. A local import treats these as
  source assertions and does not establish an authenticated remote identity.
- Source identity includes notebook, kernel resource and kernel session. Open a
  new capture file after kernel restart. Reconnecting to the same live kernel
  preserves its identity. A restored or cloned execution instance needs a fresh
  externally assigned generation.
- Request identity combines that scope with native frontend session and message
  ID. Responses use `parent_header`, including outputs arriving after another
  client's request. Execution counters and timestamps are display information.
- Missing parents leave output at kernel scope with an explicit gap. Conflicting
  native message content or an unexpected kernel session produces an ambiguous
  import instead of joining unrelated executions.
- Only a shell `execute_reply` supplies a terminal request outcome. Stream output,
  display updates, and `idle` retain their own evidence without closing a request.
  Shared-kernel operating-system events keep their existing process/scope-level
  attribution.

`context project` explicitly rebuilds existing graph relationships from saved
context. It can be repeated after importing another capture; it does not execute
tool inputs or change original entries. `context import` remains an import-only
operation. Existing context queries consume the same entries.
`source.notebook` and `entry.notebook` are documented in the
[context API](agent-context-api.yaml). No new remote write endpoint is required.

## Content and limits

The recorder defaults to 128 MiB and 24,998 messages, with a 32 MiB message limit.
These limits can be lowered. Exceeding a budget appends `notebook_gap` and stops
recording with an error; import reports the gap. Files and processing also use
the existing context import budgets.

The text projection retains plain text, HTML/Markdown as inert text, and JSON.
PNG and JPEG outputs use separate content-addressed attachments. Their base64
bytes never enter conversation text or retained source projections. Unsupported
MIME values, including SVG, retain an omission reason and source-value digest.
`raw_content.reason=notebook_protocol_projection` identifies this reduced source
representation. Transport buffers are rejected by this recorder.

### Raster attachments

Detailed capture retains raster output by default; basic capture omits it.
`--capture-attachments=true|false` overrides that choice independently. Without
an override, attachments follow `--capture-tool-results`. Settings are fixed for
the Run, and intentional omission retains the native output relationship.

Each PNG/JPEG is decoded, checked and reencoded as a static PNG. The reference
records both the source and retained byte digests, dimensions and
`transformation: raster_reencode/v1`. Reencoding removes source metadata and
trailing bytes. Pixel content is retained without OCR redaction and is marked
`privacy: visual_content_unredacted`; inspect images before sharing.

| Budget | Limit |
| --- | --- |
| Source or retained image | 8 MiB each |
| Dimensions | 8,192 per side; 16,777,216 total pixels |
| Attachments per record | 32 |
| Distinct attachments per Run | 256; 64 MiB of retained image bytes |
| Read page | 256 KiB of decoded bytes |

Invalid or over-budget images retain an omission reason and source digest. The
Run budget persists across imports; reimporting an identical output reuses its
attachment. Source-file limits still apply before import.

Read `entries[].attachments` from `context list`, then request bounded JSON pages:

```bash
agentprov context attachment --run RUN_ID --ref sha256:ATTACHMENT_HASH --limit 65536
```

`data` contains base64 for that page, `offset` and `next_offset` count decoded
bytes, and `sha256` identifies the entire retained image. The HTTP equivalent is
`GET /v1/context/attachment?run=RUN_ID&ref=sha256:ATTACHMENT_HASH`.

Signed Bundles include image manifests and chunks. To share text without a chosen
image, use its attachment reference:

```bash
agentprov dashboard export --run RUN_ID \
  --exclude-attachment sha256:ATTACHMENT_HASH --output text-replay.zip
```

The flag is repeatable. The local export API and selection files accept
`exclude_attachments`. An explicit reference excludes that image from every
included entry using it; excluding a whole record preserves images independently
used by other selected records. The read-only ZIP records exclusions while
leaving original evidence and signed Bundles unchanged.

## Reproduce the native protocol fixture

In a dedicated Python environment, from the repository root:

```bash
python -m pip install jupyter-client==8.6.3 ipykernel==6.29.5
PYTHONPATH=python python scripts/accept_notebook.py --output /tmp/notebook-acceptance
```

The output directory must be new. The fixture starts its own kernel, records two
frontend sessions and background output, restarts the kernel, and computes a CSV
total into `result.json`. It stops its kernel and removes connection resources
on exit. `first.jsonl` and `restarted.jsonl` can be imported into the same Run;
the two kernel lifetimes stay separate. `result-manifest.json` records the actual
native IDs and versions. This is a Jupyter integration fixture, not a model task.

Add `--agentprov /path/to/agentprov` to verify both retention presets through the
public CLI: repeated import, graph projection, native output links, signed export
and import, and reading after the original store has been moved. It creates a
fixture-only signing key under the private output directory. Results are saved
in `cli-results.json`.

Add `--attachments` to generate a real PNG chart and inert HTML output. With
`--agentprov`, the fixture also verifies image paging and signed round trips,
checks detailed capture with images disabled, and produces full and image-excluded
replay ZIPs. The chart is generated inside the restarted kernel from the CSV values.

Protocol reference: [Jupyter messaging](https://jupyter-client.readthedocs.io/en/stable/messaging.html).
