#!/usr/bin/env python3
"""Deliver an owned Linux Browser/Sensor acceptance after its processes stop.

Run as the Browser operator account. The launcher configuration remains external
to every signed package and is independently checked by the recipient CLI.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile


RULE = "agentprov.browser_runtime_custody/v1"


def save(path, value):
    with path.open("x") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def relations(value):
    return {e["id"]: e for e in value.get("derived_edges", []) if e.get("derivation_rule") == RULE}


def reader_relations(path):
    result = {}
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.startswith("data/") or not name.endswith(".js"):
                continue
            raw = archive.read(name).decode()
            if not raw.startswith("window.AgentProvOffline.accept("):
                continue
            args = json.loads("[" + raw.removeprefix("window.AgentProvOffline.accept(").removesuffix(");") + "]")
            value = json.loads(gzip.decompress(base64.b64decode(args[1])))
            if isinstance(value, dict):
                for edge in value.get("focus_edges") or []:
                    if edge.get("derivation_rule") == RULE:
                        result[edge["id"]] = edge
    return result


def accept(args):
    root, output = args.capture.resolve(strict=True), args.output.resolve()
    output.mkdir(mode=0o700)
    data, received = root / "data", output / "received"
    run = json.loads((root / "browser-result.json").read_text())["run_id"]
    env = dict(os.environ, AGENTPROV_DAEMON_URL="", AGENTPROV_LANG="en")
    report = {"schema_version": "agentprovenance.browser_native_delivery/v1", "status": "failed", "run_id": run,
              "binary_sha256": digest(args.agentprov), "verifier_sha256": digest(args.verifier), "scopes": []}

    def invoke(binary, *argv, expected=0, structured=True):
        p = subprocess.run([str(binary), *map(str, argv)], env=env, capture_output=True, timeout=180)
        if p.returncode != expected:
            raise RuntimeError(f"{Path(binary).name} exit {p.returncode}: " + p.stderr[-2000:].decode(errors="replace"))
        return json.loads(p.stdout) if structured else p.stdout.decode()

    def cli(store, *argv, **kwargs):
        return invoke(args.agentprov, "--data-dir", store, *argv, **kwargs)

    try:
        configs = sorted((root / "operator").glob("*/browser-runtime.json"))
        assert len(configs) == 3, "fixture requires both concurrent browsers and the restarted generation"
        imports = []
        for config in configs:
            cfg = json.loads(config.read_text())
            argv = ["context", "import", "--run", run, "--harness", "browser", "--capture", "detailed",
                    "--browser-owned-config", cfg["capture_config"], "--browser-receipts", cfg["receipts"]]
            first, repeated = cli(data, *argv), cli(data, *argv)
            assert first["binding_refs"] == repeated["binding_refs"] and all(x["stored"] == 0 for x in repeated["imports"])
            imports.append(first)
        assert not relations(cli(data, "graph", "lens", "--run", run, "--detail", "raw", "--limit", "100000", "--json")), "stored objects granted runtime authority"

        private, public = output / "producer.key", output / "producer.pub"
        cli(data, "forensics", "keygen", "--priv", private, "--pub", public, structured=False)
        bundle = cli(data, "forensics", "export", run, "--sign-key", private, "--json")
        assert bundle["signed"]
        shutil.copyfile(bundle["path"], output / "bundle.json")
        shutil.copyfile(bundle["attestation_path"], output / "bundle.dsse.json")
        imported = cli(received, "forensics", "import", output / "bundle.json", "--pub-key", public, "--json")
        assert imported["attestation_verified"]
        assert cli(received, "graph", "verify", "--run", run, "--json")["error_count"] == 0
        exporter, exporter_pub = output / "exporter.key", output / "exporter.pub"
        cli(received, "forensics", "keygen", "--priv", exporter, "--pub", exporter_pub, structured=False)
        key = bytes.fromhex(exporter_pub.read_text().strip())
        policy = {"schema_version": "agentprovenance.reader_trust/v1", "id": "browser-native-recipient",
                  "keys": [{"key_id": hashlib.sha256(key).hexdigest()[:16], "public_key_hex": key.hex(), "roles": ["exporter"]}]}
        save(output / "recipient-trust.json", policy)

        entries, cursor = [], ""
        while True:
            page = cli(received, "context", "list", "--run", run, "--limit", "200", "--cursor", cursor)
            entries += page["entries"]
            if not page["has_more"]:
                break
            assert page["next_cursor"] != cursor and len(entries) < 25000
            cursor = page["next_cursor"]

        for index, (config, imported) in enumerate(zip(configs, imports, strict=True)):
            cfg = json.loads(config.read_text())
            scope = cfg["mappings"][0]["scope"]
            opts = ["graph", "lens", "--run", run, "--detail", "raw", "--limit", "100000", "--browser-custody-config", config, "--json"]
            source = relations(cli(data, *opts))
            destination = relations(cli(received, *opts))
            assert source == destination and any(e["edge_type"] == "browser_scope_process" for e in source.values())
            support_id = imported["bindings"][0]["binding"]["verified_source_refs"]["accept"]["event_id"]
            support = [e for e in entries if (e.get("browser") or {}).get("event_id") == support_id]
            assert len(support) == 1
            full, selected = output / f"scope-{index}.zip", output / f"scope-{index}-selected.zip"
            for archive, extra in [(full, []), (selected, ["--exclude-record", "entry/" + support[0]["id"]])]:
                cli(received, "dashboard", "export", "--run", run, "--browser-custody-config", config,
                    "--output", archive, "--delivery", "derived", "--sign-key", exporter,
                    "--exporter-id", "browser-native-acceptance", *extra, structured=False)
                verified = invoke(args.verifier, "--trust-policy", output / "recipient-trust.json", archive)
                assert verified["file_integrity"] == "passed" and verified["derived_signature"]["trusted"] is True
                unknown = invoke(args.verifier, archive, expected=2)
                assert unknown["derived_signature"]["status"] == "unknown_key"
            full_edges, selected_edges = reader_relations(full), reader_relations(selected)
            assert full_edges and not selected_edges, "selected reader retained unsupported native custody"
            # A new generation and a different process birth must not borrow the
            # valid pinned source claim, even when the numerical PID is reused.
            wrong = json.loads(config.read_text())
            wrong["mappings"][0]["scope"]["generation"] += "-wrong"
            wrong_path = output / f"scope-{index}-wrong.json"
            save(wrong_path, wrong)
            rejected = subprocess.run([str(args.agentprov), "--data-dir", str(received), "graph", "lens", "--run", run,
                "--browser-custody-config", str(wrong_path), "--json"], env=env, capture_output=True, timeout=30)
            assert rejected.returncode != 0
            report["scopes"].append({"scope": scope, "native_relations": len(source),
                "matched_native_process_observations": sum(e["edge_type"] == "browser_scope_process" for e in source.values()),
                "reader_native_relations": len(full_edges), "selected_native_relations": len(selected_edges),
                "wrong_generation_rejected": True, "reader_sha256": digest(full), "selected_sha256": digest(selected)})
        report.update(status="passed", duplicate_import="passed", signed_bundle="passed",
                      retained_binding_refs=sum(len(x["binding_refs"]) for x in imports), bundle_sha256=digest(output / "bundle.json"))
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        save(output / "report.json", report)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("agentprov", "verifier", "capture", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    os.umask(0o077)
    accept(args)


if __name__ == "__main__":
    main()
