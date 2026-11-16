#!/usr/bin/env python3
"""Exercise the exported reader and standalone verifier with owned local data."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(128 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentprov", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    agent, verifier, out = args.agentprov.resolve(), args.verifier.resolve(), args.out.resolve()
    for binary in (agent, verifier):
        if not binary.is_file():
            parser.error(f"binary missing: {binary}")
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema_version": "agentprovenance.derived_acceptance/v1", "passed": False,
              "binaries": {"agentprov": digest(agent), "agentprov_verify": digest(verifier)}, "checks": []}

    def run(name, command, code=0, json_output=False):
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=120)
        (out / (name + ".stdout")).write_text(result.stdout)
        (out / (name + ".stderr")).write_text(result.stderr)
        report["checks"].append({"name": name, "exit_code": result.returncode, "expected_exit_code": code})
        if result.returncode != code:
            raise RuntimeError(f"{name}: exit {result.returncode}, expected {code}; see stderr")
        return json.loads(result.stdout) if json_output else result.stdout

    try:
        with tempfile.TemporaryDirectory(prefix="agentprov-reader-key-") as key_dir:
            private, public = Path(key_dir) / "private.hex", Path(key_dir) / "public.hex"
            run("keygen", [agent, "forensics", "keygen", "--priv", private, "--pub", public])
            public_bytes = bytes.fromhex(public.read_text().strip())
            key = {"key_id": hashlib.sha256(public_bytes).hexdigest()[:16],
                   "public_key_hex": public_bytes.hex(), "roles": ["exporter"]}
            policy = out / "recipient-trust.json"
            policy.write_text(json.dumps({"schema_version": "agentprovenance.reader_trust/v1", "id": "owned-fixture", "keys": [key]}))
            work = out / "workspace"
            work.mkdir()
            (work / "input.txt").write_text("owned offline reader fixture\n")
            command = [agent, "--data-dir", out / "store"]
            run("record", [*command, "record", "--run", "reader-acceptance", "--workdir", work, "--json", "--",
                           "sh", "-c", "cp input.txt output.txt; printf 'recorded reader fixture\\n'"])
            signed, unsigned = out / "signed.zip", out / "unsigned.zip"
            run("export-signed", [*command, "dashboard", "export", "--run", "reader-acceptance", "--output", signed,
                                  "--sign-key", private, "--exporter-id", "acceptance-exporter"])
            run("export-unsigned", [*command, "dashboard", "export", "--run", "reader-acceptance", "--output", unsigned])
            result = run("trusted", [verifier, "--trust-policy", policy, signed], json_output=True)
            assert result["file_integrity"] == "passed" and result["derived_signature"]["trusted"]
            assert result["derivation"] == "not_checked"
            result = run("unknown-key", [verifier, signed], 2, True)
            assert result["derived_signature"]["status"] == "unknown_key"
            assert result["derived_signature"]["cryptographic"] == "passed"
            result = run("unsigned", [verifier, unsigned], 2, True)
            assert result["derived_signature"]["status"] == "unsigned"
            role_policy = out / "producer-only.json"
            role_policy.write_text(json.dumps({"schema_version": "agentprovenance.reader_trust/v1", "id": "wrong-role",
                                              "keys": [{**key, "roles": ["producer"]}]}))
            result = run("wrong-role", [verifier, "--trust-policy", role_policy, signed], 2, True)
            assert result["derived_signature"]["status"] == "untrusted_role"
            reader = out / "reader"
            # Only the ZIP just produced from this owned fixture is extracted.
            with zipfile.ZipFile(signed) as z:
                assert all(not name.startswith("/") and ".." not in Path(name).parts for name in z.namelist())
                assert "snapshot.db" not in z.namelist()
                z.extractall(reader)
            run("directory", [verifier, "--trust-policy", policy, reader], json_output=True)
            payload = reader / "en/index.html"
            original = payload.read_bytes()
            payload.write_bytes(original + b"changed")
            result = run("tampered", [verifier, "--trust-policy", policy, reader], 1, True)
            assert result["file_integrity"] == "failed"
            payload.write_bytes(original)
            shutil.copyfile(policy, reader / "policy.json")
            result = run("extra-policy", [verifier, "--trust-policy", policy, reader], 1, True)
            assert any(i["code"] == "extra_file" for i in result["issues"])
            (reader / "policy.json").unlink()
            run("restored", [verifier, "--trust-policy", policy, reader], json_output=True)
            report["artifacts"] = {p.name: digest(p) for p in (signed, unsigned, policy)}
            report["reader"] = "reader/en/index.html"
            report["passed"] = True
    finally:
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
