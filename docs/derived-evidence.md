# Evidence Delivery and Verification

[简体中文](zh-CN/derived-evidence.md)

Use a signed reading copy when someone needs to inspect selected evidence
without connecting to your AgentProvenance store. The exporter signs a
`DerivedView/v1` manifest that binds the reader assets, selected records,
attachments, selection rules, and implementation digest.

The default `dashboard export` remains an unsigned reading copy. Existing
exports continue to open offline. Signing is opt-in and uses the same frozen
snapshot and selection path.

## Choose a Delivery Mode

| Mode | Contents | Choose it for |
| --- | --- | --- |
| `reading` | Reader and selected evidence, unsigned. | Quick offline investigation. |
| `derived` | Selected evidence and the exporter's signed manifest. | Sharing a reviewed selection without excluded originals. |
| `originals` | Reader, explicitly selected signed bundles and their attestations, exporter manifest. | Delivering complete evidence revisions for independent verification. |

Without `--delivery`, an exporter key selects `derived`; otherwise the default is
`reading`. Use `--delivery reading` to request an unsigned copy explicitly.
`derived` uses the existing retention and exclusion rules; review the selected
content before sharing. It does not automatically remove every sensitive string.

### Deliver Complete Originals

First create a signed bundle and note the returned `id`:

```sh
agentprov forensics export RUN_ID --sign-key producer.private.hex --json
agentprov dashboard export --run RUN_ID --output complete.zip \
  --delivery originals --original-bundle BUNDLE_ID --confirm-original-scope \
  --sign-key exporter.private.hex --exporter-id review-team
```

Select exactly one registered bundle per run. The reader is generated from those
bundle revisions, so newer live records do not enter the package. Original bytes
and their attestations are copied unchanged under `originals/`. An original may
contain material that the reader does not display; the explicit confirmation
acknowledges this full-content scope. Session filters and exclusions are rejected
in this mode. Use `derived` for selective disclosure.

Each original must be a signed JSON bundle within the 256 MiB strict-import
limit. The combined original budget is 900 MiB; the complete delivery budget is
1280 MiB. Exceeding a budget fails the export without truncating evidence.

## Export

Create an exporter key once, outside the evidence directory. Keep the private
key on the exporting machine; distribute the public key through a trusted channel.
Choose new filenames because `forensics keygen` writes the named key files.

```sh
agentprov forensics keygen --priv exporter.private.hex --pub exporter.public.hex
agentprov dashboard export --run RUN_ID --output selected.zip \
  --harness claude --session SESSION_ID \
  --sign-key exporter.private.hex --exporter-id review-team
```

Existing `--selection-file`, `--exclude-record`, `--exclude-category`, and
`--exclude-attachment` options still apply. Excluded bodies and original databases
are not added to make a signature verifiable. The manifest retains a digest
commitment to the private frozen source, without including that source.

For local HTTP export, configure the operator-owned key when starting the server:

```sh
agentprov dashboard serve --addr 127.0.0.1:7396 \
  --replay-sign-key exporter.private.hex --replay-exporter-id review-team
```

The [export API](replay-export-api.yaml) reports `signed` and the exporter/key ID.
HTTP callers cannot supply or replace the key. The downloadable ZIP includes
`manifest.json` and `manifest.signature`; both are inspectable in the frozen preview.
Its optional `delivery` object selects the same modes and accepts registered
bundle IDs, not filesystem paths. Preview inventory lists each included original.

## Verify Independently

Build the standalone verifier from the source revision you trust:

```sh
go build -o agentprov-verify ./cmd/agentprov-verify
./agentprov-verify selected.zip
```

It reads a ZIP or an extracted directory without starting a daemon, importing
evidence, executing page scripts, or making network requests. Without a trust
policy it checks available hashes and signatures and reports an unknown signer.

Configure trusted public keys and their roles in a separate, recipient-owned file:

```json
{
  "schema_version": "agentprovenance.reader_trust/v1",
  "id": "review-team-keys",
  "keys": [{
    "key_id": "FIRST_16_HEX_OF_PUBLIC_KEY_SHA256",
    "public_key_hex": "ED25519_PUBLIC_KEY_HEX",
    "roles": ["exporter"]
  }]
}
```

`forensics keygen` prints the key ID. Use the public key received through your
trusted channel, not an automatically accepted key from the ZIP. The trust file
must be outside an extracted evidence directory.

```sh
./agentprov-verify --trust-policy recipient-trust.json selected.zip
agentprov evidence verify-view selected.zip --trust-policy recipient-trust.json
```

The standalone command returns JSON and these exit codes:

| Code | Meaning |
| --- | --- |
| 0 | All listed files match; the exporter and any delivered original signatures are valid and trusted in their roles. |
| 1 | Verification failed, including changed, missing, extra, or unsafe files. |
| 2 | Unsigned copy, or an exporter/producer not authorized by the recipient policy. |
| 3 | Invalid input path, policy, arguments, or output failure. |

The integrated CLI emits the same JSON; any nonzero verification outcome is a
command error. Preserve the JSON when automating a decision.

## Read the Results

The report keeps file integrity, exporter signature, source signatures,
derivation, and declared collection coverage in separate fields. An exporter
signature authenticates the exporter's declaration. `derivation: not_checked`
means the recipient has not recomputed the view from its original sources.
Collection gaps remain visible even with a valid, trusted signature.

Package keys and policy files do not grant trust. The verifier uses only the
recipient's explicit policy and authorized roles. A producer key without the
`exporter` role cannot authorize a reading copy.

For `originals`, authorize the producer public key with the `producer` role in
the recipient policy. The standalone verifier checks delivered bundle bytes
against their original DSSE attestations and reports them separately from the
exporter signature. It still reports valid originals when a reader asset has
been changed. `forensics verify` remains available for separately delivered
originals.

Declared coverage is taken from retained capture observations. Gap counts in the
manifest count those observations, not estimated lost events. Original counters
keep their recorded run or collector scope in the reader. A successful command
or signature does not change a recorded coverage gap.

## Reproduce the Local Check

```sh
python3 scripts/accept_derived_view.py \
  --agentprov ./agentprov --verifier ./agentprov-verify --out /tmp/reader-check
```

The check records a real local command, exports signed and unsigned readers,
and checks trusted, unknown-key, wrong-role, tampered, and extra-file cases.
It also delivers an original, verifies its producer separately and changes a
reader asset to check that the valid original result remains available.
It creates its own temporary signing key and preserves reports and public
verification material, not the private key.
