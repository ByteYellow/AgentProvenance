#!/usr/bin/env python3
"""Verify frozen signed demos, their query surfaces, and in-place DB upgrades.

Requires the read-only freeze manifest and native baseline/candidate binaries.
Creates a new output directory; never updates or re-signs the source bundles.
"""
import argparse
import base64
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile


MAX_JSON_BYTES = 128 << 20
LENSES = (
    "default", "security", "process", "file-artifact", "network-egress",
    "data-flow-taint", "agent-intent", "orchestration", "intent", "substrate",
    "trust-origin", "sandbox-boundary",
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path, compressed=False):
    with (gzip.open(path, "rb") if compressed else path.open("rb")) as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("acceptance input exceeds the JSON budget")
    return json.loads(raw)


def under(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError("manifest path leaves the evidence root")
    return path


def invoke(binary, store, *args, json_output=True):
    env = dict(os.environ)
    env.pop("AGENTPROV_DAEMON_URL", None)
    command = [str(binary), "--data-dir", str(store), "--lang", "en", *args]
    # Keep large graph responses out of subprocess pipe buffers and console logs.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(command, env=env, stdout=output, stderr=errors, timeout=180)
        if result.returncode:
            errors.seek(0)
            raise RuntimeError(f"{args[0]} exited {result.returncode}: " + errors.read(2048).decode(errors="replace"))
        if output.tell() > MAX_JSON_BYTES:
            raise ValueError("acceptance response exceeds the JSON budget")
        output.seek(0)
        raw = output.read().decode("utf-8")
    return json.loads(raw) if json_output else raw.strip()


def check_files(root, demos):
    count = 0
    for demo in demos:
        for item in demo["files"]:
            path = under(root, item["frozen"])
            assert path.stat().st_size == item["bytes"], f"{demo['run']}: changed file size"
            assert sha256(path) == item["sha256"], f"{demo['run']}: changed frozen hash"
            count += 1
    return count


def check_rows(store, bundle, tables):
    """Compare every exported field, excluding only relocated content paths."""
    checked = 0
    uri = (store / "agentprov.db").resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.row_factory = sqlite3.Row
        for table, count in tables.items():
            assert re.fullmatch(r"[a-z_]+", table), "invalid table name"
            original = bundle[table]
            assert len(original) == count, f"{table}: baseline count mismatch"
            columns = sorted({key for row in original for key in row})
            assert all(re.fullmatch(r"[a-z_][a-z0-9_]*", col) for col in columns), "invalid column"
            if table in ("provenance_objects", "snapshots"):
                columns.remove("path")
            quoted = ",".join('"' + col + '"' for col in columns)
            actual = Counter(tuple(row) for row in db.execute(f'SELECT {quoted} FROM "{table}"'))
            expected = Counter(tuple(row.get(col) for col in columns) for row in original)
            assert actual == expected, f"{table}: historical fields or row multiplicity changed"
            checked += count
        for blob in bundle.get("object_blobs") or []:
            row = db.execute("SELECT path FROM provenance_objects WHERE hash = ?", (blob["hash"],)).fetchone()
            assert row is not None, "missing imported object"
            assert sha256(Path(row["path"])) == blob["hash"].removeprefix("sha256:"), "changed object bytes"
        for snapshot in bundle.get("snapshot_files") or []:
            row = db.execute("SELECT path FROM snapshots WHERE id = ?", (snapshot["snapshot_id"],)).fetchone()
            assert row is not None, "missing imported snapshot"
            path = under(Path(row["path"]).resolve(), snapshot["name"])
            content = base64.b64decode(snapshot["content_b64"], validate=True)
            assert sha256(path) == hashlib.sha256(content).hexdigest(), "changed snapshot bytes"
    return checked


def check_graph(binary, store, run):
    graph = invoke(binary, store, "graph", "verify", "--run", run, "--json")
    assert graph["run_id"] == run and graph["status"] == "ok", f"{run}: graph not verified"
    assert graph["error_count"] == graph["warning_count"] == 0, f"{run}: graph issues"
    return graph


def lens_shape(lens):
    assert not lens["query"]["truncated"], "increase the acceptance budget to compare the complete graph"
    nodes = lens.get("nodes") or []
    edges = (lens.get("edges") or []) + (lens.get("derived_edges") or [])
    node_ids = {node["id"] for node in nodes}
    assert len(node_ids) == len(nodes), "duplicate lens nodes"
    assert all(edge["from_id"] in node_ids and edge["to_id"] in node_ids for edge in edges), "dangling lens edge"
    assert len(nodes) == lens["query"]["node_count"], "incorrect node count"
    assert len(edges) == lens["query"]["edge_count"], "incorrect edge count"
    # The baseline chose runtime-process labels in map iteration order. Compare
    # their identities instead; all underlying event fields are checked above.
    # Layout and local content paths are also not immutable source evidence.
    def signatures(items, fields):
        return sorted(json.dumps({key: item.get(key) for key in fields
                                  if key != "label" or item.get("kind") != "runtime_process"}, sort_keys=True) for item in items)
    return {
        "nodes": signatures(nodes, ("id", "kind", "subtype", "label", "trust_origin", "risk")),
        "edges": signatures(edges, ("from_id", "to_id", "edge_type", "source_event_id", "derived",
                                     "derivation_rule", "confidence", "evidence_refs")),
        "raw_event_count": lens["query"]["raw_event_count"],
    }


def check_legacy_coverage(binary, store, run):
    overview = invoke(binary, store, "context", "coverage", "--run", run)
    assert overview["run_id"] == run and not overview["has_more_sources"]
    assert all(overview[key] is None for key in ("messages", "tool_calls", "tool_results", "snapshots"))
    assert len(overview["coverage"]) == 1
    coverage = overview["coverage"][0]
    assert coverage["status"] == "legacy_not_recorded", "historical coverage was invented"
    assert all(count is None for count in coverage["counts"].values()), "unknown counts became zero"
    entries = invoke(binary, store, "context", "list", "--run", run)
    assert not entries["entries"] and not entries["has_more"], "historical context was fabricated"
    return coverage["status"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--baseline-binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new, nonexistent report/store directory")
    args = parser.parse_args()
    binary, baseline = args.binary.resolve(), args.baseline_binary.resolve()
    root, output = args.evidence_root.resolve(), args.output.resolve()
    manifest = read_json(args.manifest)
    demos = manifest["demos"]
    assert len(demos) == 6 and len({d["run"] for d in demos}) == 6, "six distinct historical demos required"
    baseline_hash = sha256(baseline)
    allowed_hashes = {manifest["binary_sha256"]}
    allowed_hashes.update(item["binary_sha256"] for item in manifest.get("baseline_binaries", []))
    assert baseline_hash in allowed_hashes, "baseline binary differs from the frozen release verifiers"
    frozen_files = check_files(root, demos)
    assert frozen_files == 18, "expected bundle, attestation and public key for each demo"
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": "agentprovenance.legacy_context_acceptance/v1",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "candidate_sha256": sha256(binary), "baseline_sha256": sha256(baseline),
        "manifest_sha256": sha256(args.manifest), "frozen_files": frozen_files,
        "scope": "offline signed imports, semantic query parity, and legacy DB migration; not rendered UI or new live capture",
        "display_exclusions": ["runtime_process label (baseline map-order nondeterminism)", "layout", "relocated local content paths"],
        "demos": [],
    }
    for demo in demos:
        run = demo["run"]
        assert re.fullmatch(r"[a-z0-9-]+", run), "invalid run path"
        bundle_path, signature, key = [under(root, item["frozen"]) for item in demo["files"]]
        new_store, old_store = output / run / "new", output / run / "upgrade"
        # Both binaries must verify the ORIGINAL DSSE before importing it.
        for cli, store in ((baseline, old_store), (binary, new_store)):
            invoke(cli, store, "forensics", "verify-attestation", str(bundle_path), str(signature),
                   "--pub-key", str(key), json_output=False)
            imported = invoke(cli, store, "forensics", "import", str(bundle_path), "--pub-key", str(key), "--json")
            assert imported["run_id"] == run
            for field in ("tables", "total_rows", "object_blobs", "snapshot_files", "omitted_content"):
                assert imported[field] == demo["imported"][field], f"{run}: changed import {field}"
            check_graph(cli, store, run)
        bundle = read_json(bundle_path, compressed=True)
        rows = check_rows(new_store, bundle, demo["imported"]["tables"])
        views = []
        for name in LENSES:
            for detail in ("summary", "raw"):
                # Compare complete semantics, not two differently truncated
                # selections among equally prioritized edges.
                opts = ("graph", "lens", "--run", run, "--lens", name, "--detail", detail, "--limit", "100000", "--json")
                previous = lens_shape(invoke(baseline, old_store, *opts))
                current = lens_shape(invoke(binary, new_store, *opts))
                assert current == previous, f"{run}: {name}/{detail} semantic query regression"
                views.append({"lens": name, "detail": detail, "nodes": len(current["nodes"]), "edges": len(current["edges"])})
        with closing(sqlite3.connect(old_store / "agentprov.db")) as db:
            old_version = db.execute("SELECT MAX(version) FROM schema_versions").fetchone()[0]
        coverage = check_legacy_coverage(binary, new_store, run)
        # Opening the old binary's database exercises real migration, not a
        # synthetic schema fixture. The separate old store is disposable.
        check_legacy_coverage(binary, old_store, run)
        check_graph(binary, old_store, run)
        check_rows(old_store, bundle, demo["imported"]["tables"])
        with closing(sqlite3.connect(old_store / "agentprov.db")) as db:
            new_version = db.execute("SELECT MAX(version) FROM schema_versions").fetchone()[0]
        assert new_version > old_version, "legacy database did not migrate"
        # Duplicate import must preserve multiplicities and not create context.
        invoke(binary, new_store, "forensics", "import", str(bundle_path), "--pub-key", str(key), "--json")
        check_rows(new_store, bundle, demo["imported"]["tables"])
        check_graph(binary, new_store, run)
        check_legacy_coverage(binary, new_store, run)
        report["demos"].append({
            "run": run, "signature_verified": True, "preserved_rows": rows,
            "object_blobs": demo["imported"]["object_blobs"], "snapshot_files": demo["imported"]["snapshot_files"],
            "graph_errors": 0, "graph_warnings": 0, "context_coverage": coverage,
            "database_upgrade": {"from": old_version, "to": new_version, "preserved": True},
            "duplicate_import": "passed", "views": views,
        })
        print(f"{run}: original signature, fields/content, {len(views)} views, DB upgrade and unknown coverage passed", flush=True)
    assert check_files(root, demos) == frozen_files, "frozen input changed during validation"
    report["status"] = "passed"
    path = output / "report.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Passed all six historical demos; report: {path}")


if __name__ == "__main__":
    main()
