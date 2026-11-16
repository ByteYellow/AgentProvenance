#!/usr/bin/env python3
"""Verify a real signed derived reader of an already imported fixture run."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import sys
import zipfile

from common import clean_env, command, digest, redact, save


def verify_reader(binary, verifier, data, run_id, output, source=None):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema_version": "agentprovenance.kata_reader_acceptance/v1", "status": "FAIL",
              "run_id": run_id, "binary_sha256": digest(binary), "verifier_sha256": digest(verifier), "checks": {}}
    env = clean_env()
    def execute(*argv, expected=0):
        return command(argv, timeout=120, env=env, allowed=(expected,))
    try:
        if source is None:
            repo = Path(__file__).resolve().parents[3]
            source = {"head": execute("git", "-C", repo, "rev-parse", "HEAD").strip(),
                      "dirty": bool(execute("git", "-C", repo, "status", "--porcelain", "--untracked-files=normal").strip())}
        report["source"] = source
        report["fixture_sha256"] = {p.name: digest(p) for p in (Path(__file__), Path(__file__).with_name("common.py"))}
        report["builds"] = {"agentprov": execute(binary, "--version").strip(), "verifier": execute(verifier, "--version").strip()}
        private, public = output / "exporter.key", output / "exporter.pub"
        execute(binary, "forensics", "keygen", "--priv", private, "--pub", public)
        key = bytes.fromhex(public.read_text().strip())
        policy = {"schema_version": "agentprovenance.reader_trust/v1", "id": "kata-fixture-recipient",
                  "keys": [{"key_id": hashlib.sha256(key).hexdigest()[:16], "public_key_hex": key.hex(), "roles": ["exporter"]}]}
        policy_file, archive = output / "recipient-trust.json", output / "derived.zip"
        save(policy_file, policy)
        execute(binary, "--data-dir", data, "dashboard", "export", "--run", run_id, "--output", archive,
                "--delivery", "derived", "--sign-key", private, "--exporter-id", "kata-acceptance-exporter")
        checks = report["checks"]
        checks["trusted"] = json.loads(execute(verifier, "--trust-policy", policy_file, archive))
        if checks["trusted"].get("file_integrity") != "passed" or checks["trusted"].get("derived_signature", {}).get("trusted") is not True:
            raise RuntimeError("derived reader integrity or recipient trust failed")
        checks["unknown_key"] = json.loads(execute(verifier, archive, expected=2))
        if checks["unknown_key"]["derived_signature"]["status"] != "unknown_key":
            raise RuntimeError("package exporter key granted itself trust")
        wrong = json.loads(json.dumps(policy))
        wrong["keys"][0]["roles"] = ["producer"]
        save(output / "wrong-role.json", wrong)
        checks["wrong_role"] = json.loads(execute(verifier, "--trust-policy", output / "wrong-role.json", archive, expected=2))
        if checks["wrong_role"]["derived_signature"]["status"] != "untrusted_role":
            raise RuntimeError("producer role authorized a derived exporter")
        damaged = output / "tampered.zip"
        with zipfile.ZipFile(archive) as source, zipfile.ZipFile(damaged, "x") as destination:
            changed = False
            for info in source.infolist():
                body = source.read(info)
                if not changed and info.filename.endswith(".html"):
                    body += b"\nfixture-tamper\n"
                    changed = True
                destination.writestr(info, body)
            if not changed:
                raise RuntimeError("export lacks a reader HTML payload")
        checks["tampered"] = json.loads(execute(verifier, "--trust-policy", policy_file, damaged, expected=1))
        if checks["tampered"].get("file_integrity") != "failed":
            raise RuntimeError("tampered reader accepted")
        report.update(status="PASS", archive_sha256=digest(archive), policy_sha256=digest(policy_file))
        return report
    except Exception as error:
        report["error"] = redact(str(error))
        raise
    finally:
        save(output / "report.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("binary", "verifier", "data-dir", "output"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    result = verify_reader(args.binary.resolve(), args.verifier.resolve(), args.data_dir.resolve(), args.run, args.output.resolve())
    print(json.dumps({"status": result["status"], "report": str(args.output / "report.json")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
