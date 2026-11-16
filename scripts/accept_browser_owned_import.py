#!/usr/bin/env python3
"""Verify saved Chrome receipts through the synchronous receiver-pinned CLI.

This read-only source check uses explicit fixture operator pins. It does not
retroactively authenticate the launcher that produced the original artifacts.
No browser, model key, or system Sensor is needed.
"""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write_private(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(0o600)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def accept(args, out):
    binary = args.agentprov.resolve(strict=True)
    artifacts = args.artifacts.resolve(strict=True)
    source_report = artifacts / "results.json"
    report_bytes = source_report.read_bytes()
    source = json.loads(report_bytes)
    check(source.get("passed") is True, "source Chrome acceptance did not pass")
    receipts = [item["result"]["browser_receipt"] for item in source["observations"]
                if item.get("result", {}).get("browser_receipt")]
    check(receipts, "source report has no durable Browser receipts")
    groups = {}
    for receipt in receipts:
        name = receipt["source_refs"]["accept"]["log"]
        check(Path(name).name == name and name.endswith(".jsonl"), "unsafe source log name")
        groups.setdefault(name, []).append(receipt)

    receiver = out / "receiver"
    receiver.mkdir(mode=0o700)
    data, received = out / "data", out / "received"
    run = "browser-owned-acceptance"
    environment = dict(os.environ, AGENTPROV_DAEMON_URL="", AGENTPROV_LANG="en")
    invocations = 0

    def cli(home, label, *argv, failure=False, structured=True):
        nonlocal invocations
        invocations += 1
        result = subprocess.run([str(binary), "--data-dir", str(home), "--lang", "en", *map(str, argv)],
                                env=environment, capture_output=True, text=True, timeout=120)
        # The keygen output is deliberately not retained or printed.
        if label != "keygen":
            write_private(out / f"{invocations:02d}-{label}.stdout", result.stdout.encode())
            write_private(out / f"{invocations:02d}-{label}.stderr", result.stderr.encode())
        if failure:
            check(result.returncode != 0, f"{label}: untrusted import succeeded")
            check(not result.stdout.strip(), f"{label}: failed import returned a binding")
            return
        check(result.returncode == 0, f"{label}: CLI failed; see private output logs")
        return json.loads(result.stdout) if structured else result.stdout

    def import_args(config_path, receipt_path):
        return ("context", "import", "--run", run, "--harness", "browser", "--capture", "basic",
                "--browser-owned-config", config_path, "--browser-receipts", receipt_path)

    fixtures, original_hashes, binding_records = [], {}, {}
    verified_count = 0
    original_actions = 0
    for index, (name, items) in enumerate(groups.items()):
        original = artifacts / "capture" / name
        raw = original.read_bytes()
        check(raw.endswith(b"\n"), "source capture ends in a partial line")
        original_hashes[str(original)] = digest(raw)
        rows = [json.loads(line) for line in raw.splitlines()]
        original_actions += sum(row.get("kind") == "action_start" for row in rows)
        scope = items[0]["scope"]
        check(all(item["scope"] == scope for item in items), "log contains multiple receipt scopes")
        placement = {key: scope[key] for key in ("producer_id", "namespace", "instance_id", "generation")}
        snapshot = out / f"capture-{index}"
        snapshot.mkdir(mode=0o700)
        write_private(snapshot / name, raw)
        bridge_id = "acceptance-fixture-bridge"
        bridge_config = digest(encode({"fixture_operator_pin": True, "placement": placement}))
        manifest = {"schema_version": "agentprovenance.browser_owned_capture/v1", "run_id": run,
                    "placement": placement, "bridge_id": bridge_id, "bridge_config_digest": bridge_config,
                    "logs": [{"name": name, "scope": scope, "prefix_bytes": len(raw), "sha256": digest(raw)}]}
        manifest_raw = encode(manifest)
        write_private(snapshot / "browser-owned.json", manifest_raw)
        config = {"directory": str(snapshot), "manifest_name": "browser-owned.json",
                  "manifest_sha256": digest(manifest_raw), "run_id": run, "placement": placement,
                  "bridge_id": bridge_id, "bridge_config_digest": bridge_config}
        config_path, receipt_path = receiver / f"config-{index}.json", snapshot / "receipts.json"
        write_private(config_path, encode(config))
        write_private(receipt_path, encode(items))
        imported = cli(data, f"import-{index}", *import_args(config_path, receipt_path))
        repeated = cli(data, f"repeat-{index}", *import_args(config_path, receipt_path))
        check(imported["verified_receipts"] == len(items), "missing verified receipt")
        check(imported["binding_refs"] == repeated["binding_refs"], "repeated import changed binding refs")
        check(all(item["stored"] == 0 for item in repeated["imports"]), "repeated import duplicated context")
        for item, record, ref in zip(items, imported["bindings"], imported["binding_refs"], strict=True):
            check(record["receipt"] == item, "import changed original receipt claims")
            check(record["receipt"]["bridge_identity"]["authentication"] == "unverified",
                  "import promoted a source claim")
            binding = record["binding"]
            check(binding["authentication"] == "verified" and binding["scope"] == scope
                  and binding["verified_source_refs"] == item["source_refs"]
                  and binding["manifest_sha256"] == config["manifest_sha256"], "independent binding mismatch")
            binding_records[ref] = record
        verified_count += len(items)
        fixtures.append((config, config_path, receipt_path, items))

    config, config_path, receipt_path, items = fixtures[0]
    negatives = []
    wrong_pin = dict(config, manifest_sha256=digest(b"different receiver pin"))
    wrong_pin_path = receiver / "wrong-pin.json"
    write_private(wrong_pin_path, encode(wrong_pin))
    self_config = Path(config["directory"]) / "artifact-self-config.json"
    write_private(self_config, encode(config))
    forged = deepcopy(items[0])
    forged["bridge_identity"]["authentication"] = "verified"
    forged.pop("digest")
    forged["digest"] = digest(encode(forged))
    forged_path = Path(config["directory"]) / "forged-receipts.json"
    write_private(forged_path, encode([forged]))
    cases = [("wrong-external-pin", wrong_pin_path, receipt_path),
             ("artifact-self-config", self_config, receipt_path),
             ("self-verified-receipt", config_path, forged_path)]
    if len(fixtures) > 1:
        cases.append(("cross-generation", fixtures[1][1], receipt_path))
    for name, cfg, receipt_file in cases:
        cli(data, name, *import_args(cfg, receipt_file), failure=True)
        negatives.append(name)

    private, public = receiver / "fixture.key", receiver / "fixture.pub"
    cli(data, "keygen", "forensics", "keygen", "--priv", private, "--pub", public, structured=False)
    bundle = cli(data, "export", "forensics", "export", run, "--sign-key", private, "--json")
    imported_bundle = cli(received, "receive", "forensics", "import", bundle["path"], "--pub-key", public, "--json")
    check(bundle["signed"] and imported_bundle["attestation_verified"], "signed bundle did not verify")
    objects, cursor = [], ""
    while True:
        page = cli(received, "objects", "graph", "objects", "--run", run, "--limit", "100", "--cursor", cursor, "--json")
        objects.extend(page["objects"])
        if not page["has_more"]:
            break
        check(page["next_cursor"] != cursor, "object paging stalled")
        cursor = page["next_cursor"]
    bindings = {obj["hash"]: obj for obj in objects if obj["type"] == "browser_receipt_binding"}
    check(set(bindings) == set(binding_records), "signed bundle lost or added binding records")
    for ref, obj in bindings.items():
        path = Path(obj["path"])
        if not path.is_absolute():
            path = received / path
        check(json.loads(path.read_bytes())["payload"] == binding_records[ref], "signed bundle altered binding payload")
    graph = cli(received, "verify", "graph", "verify", "--run", run, "--json")
    check(graph["error_count"] == 0, "signed graph verification failed")
    check(source_report.read_bytes() == report_bytes, "source report changed")
    check(all(digest(Path(path).read_bytes()) == value for path, value in original_hashes.items()), "source capture changed")
    result = {"passed": True, "fixture_operator_pin": True, "production_launch_authentication": "not_evaluated",
              "verified_receipts": verified_count, "unique_bindings": len(binding_records),
              "generations": sorted({item["scope"]["generation"] for item in receipts}),
              "original_source_sha256": original_hashes, "source_actions_before": original_actions,
              "source_actions_after": original_actions, "source_unchanged": True,
              "negative_cases_rejected": negatives, "repeat_import_idempotent": True,
              "signed_roundtrip": True, "graph_errors": graph["error_count"],
              "graph_warnings": graph["warning_count"], "binary_sha256": digest(binary.read_bytes()),
              "source_result_sha256": digest(report_bytes), "sensor": "off", "run_id": run}
    write_private(out / "results.json", json.dumps(result, indent=2).encode() + b"\n")
    print(json.dumps({key: result[key] for key in ("passed", "fixture_operator_pin", "verified_receipts",
          "unique_bindings", "generations", "negative_cases_rejected", "signed_roundtrip", "graph_errors")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentprov", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path, help="Chrome live results.json and capture/ directory")
    parser.add_argument("--output", required=True, type=Path, help="new private fixture directory")
    parser.add_argument("--approve-fixture-pin", action="store_true", help="explicitly approve test-only pins for copied source bytes")
    args = parser.parse_args()
    if not args.approve_fixture_pin:
        parser.error("--approve-fixture-pin is required; artifact-provided pins are not authority")
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    accept(args, args.output.resolve(strict=True))


if __name__ == "__main__":
    main()
