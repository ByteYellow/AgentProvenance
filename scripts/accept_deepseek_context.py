#!/usr/bin/env python3
"""Verify the real DeepSeek capture in a fresh, offline evidence store.

No model calls or captured commands are executed. Source bundles are read-only.
"""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from accept_legacy_context import check_graph, check_rows, invoke, read_json, sha256, under


@contextmanager
def dashboard(binary, store):
    env = dict(os.environ)
    env.pop("AGENTPROV_DAEMON_URL", None)
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            [str(binary), "--data-dir", str(store), "--lang", "en", "dashboard", "serve",
             "--addr", "127.0.0.1:0"], env=env, stdout=subprocess.PIPE,
            stderr=errors, text=True,
        )
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=20):
                    raise RuntimeError("Dashboard did not announce its local listener")
                line = process.stdout.readline()
            match = re.search(r"http://127\.0\.0\.1:[0-9]+/", line)
            if not match:
                raise RuntimeError("Dashboard failed to start; no replay check was performed")
            yield match.group(0)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            process.stdout.close()


class ContextClient:
    def __init__(self, base, run):
        self.base, self.run = base, run
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def get(self, route, **query):
        params = urllib.parse.urlencode({"run": self.run, **query})
        with self.opener.open(self.base + "api/context/" + route + "?" + params,
                              timeout=20) as response:
            assert response.headers.get("Cache-Control") == "no-store"
            raw = response.read((2 << 20) + 1)
            assert len(raw) <= 2 << 20, "unbounded API response"
            return json.loads(raw)

    def entries(self):
        result, cursor = [], ""
        for _ in range(100):
            page = self.get("entries", limit=7, cursor=cursor)
            result.extend(page["entries"])
            if not page["has_more"]:
                assert len(result) == len({entry["id"] for entry in result})
                return result
            assert page["next_cursor"] and page["next_cursor"] != cursor
            cursor = page["next_cursor"]
        raise AssertionError("entry pagination did not end within the fixture budget")

    def content(self, ref, expected):
        chunks, offset = [], 0
        for _ in range(4096):
            page = self.get("content", ref=ref, offset=offset, limit=1021)
            assert page["ref"] == ref and page["offset"] == offset
            raw = page["content"].encode("utf-8")
            assert len(raw) <= 1021 and page["next_offset"] == offset + len(raw)
            assert page["sha256"] == expected["sha256"]
            assert page["total_bytes"] == expected["bytes"]
            assert page["redacted"] == expected["redacted"]
            chunks.append(raw)
            if not page["has_more"]:
                body = b"".join(chunks)
                assert len(body) == expected["bytes"]
                assert hashlib.sha256(body).hexdigest() == expected["sha256"]
                return body.decode("utf-8")
            assert page["next_offset"] > offset
            offset = page["next_offset"]
        raise AssertionError("content pagination did not end within the fixture budget")


def check_http(client, bundle, expected):
    objects = {blob["hash"]: json.loads(base64.b64decode(blob["content_b64"], validate=True))
               for blob in bundle["object_blobs"]}
    overview = client.get("overview")
    for field in ("messages", "tool_calls", "tool_results", "snapshots"):
        assert overview[field] == expected[field], field
    transcript = [c for c in overview["coverage"] if c["source"].get("channel") == "transcript"]
    assert len(transcript) == 1 and transcript[0]["status"] == "ok"
    assert transcript[0]["source"]["harness"] == "deepseek"
    assert transcript[0]["source"]["format_version"] == "4"
    assert transcript[0]["counts"]["stored"] == expected["physical_records"]
    assert "approval" in transcript[0]["missing_fields"]
    runtime = overview["runtime_coverage"]
    assert runtime["capture"]["status"] == "partial"
    assert runtime["capture"]["run_dropped_events"] is None
    assert runtime["capture"]["run_impact"] == "unknown"
    assert runtime["correlation"]["summary"]["runtime_events"] == expected["runtime_events"]
    assert runtime["correlation"]["by_source"]["agentprov_ebpf"] == expected["native_runtime_events"]

    entries = client.entries()
    assert len(entries) == expected["physical_records"]
    original_ids = {entry["id"] for entry in bundle["agent_context_entries"]}
    assert {entry["id"] for entry in entries} == original_ids
    assert not any(entry["kind"] == "approval" for entry in entries), "invented an approval"
    refs = {entry[key]["ref"] for entry in entries for key in ("content", "raw_content")
            if entry[key]["state"] == "stored"}
    bodies = {}
    for ref in sorted(refs):
        manifest = objects[ref]["payload"]["text_manifest"]
        bodies[ref] = client.content(ref, manifest)
    results = [bodies[entry["content"]["ref"]] for entry in entries if entry["kind"] == "tool_result"]
    assert any("Ran 7 tests" in body and "OK" in body for body in results)
    assert any(all(text in body for text in ("Total: 42.00", "2026-09-25: 30.00",
                                            "2026-09-26: 7.25", "2026-09-27: 4.75"))
               for body in results), "missing captured task output"
    tool_entries = [entry for entry in entries if entry["kind"] in ("tool_call", "tool_result")]
    for entry in tool_entries:
        links = client.get("links", entry=entry["id"])
        assert links["links"] and not links["has_more"]
    config = [entry for entry in entries if entry["kind"] == "configuration"]
    assert client.get("compare", left=config[0]["id"], right=config[0]["id"])["status"] == "same"

    reports = [obj["payload"] for obj in objects.values() if obj["type"] == "runtime_correlation"]
    assert len(reports) == 1 and reports[0]["matched_execs"] == expected["matched_execs"]
    assert reports[0]["status"] == "partial" and reports[0]["confidence"] == 0.8
    files = [obj["payload"] for obj in objects.values() if obj["type"] == "artifact_capture"]
    assert len(files) == 1
    files = files[0]["files"]
    stored = [f for f in files if f["content_state"] == "stored"]
    assert sorted(f["path"] for f in stored) == expected["stored_files"]
    assert sum(f["content_state"] == "binary_omitted" for f in files) == expected["omitted_binary_files"]
    for file in stored:
        body = client.content(file["content_ref"], objects[file["content_ref"]]["payload"]["text_manifest"])
        assert len(body.encode("utf-8")) == file["content_bytes"]
        assert hashlib.sha256(body.encode("utf-8")).hexdigest() == file["sha256"]
        assert "daily" in body

    cases = [("entries", {"limit": 201}, 400), ("content", {"ref": "../../etc/passwd"}, 400),
             ("entries", {"cursor": "invalid"}, 400), ("overview", {"run": "missing-run"}, 404)]
    for route, query, code in cases:
        try:
            client.get(route, **query)
        except urllib.error.HTTPError as error:
            assert error.code == code and json.load(error)["error"]["code"]
        else:
            raise AssertionError("invalid request was accepted")
    return {"entries": len(entries), "context_content_refs": len(refs),
            "context_content_bytes": sum(len(body.encode("utf-8")) for body in bodies.values()),
            "saved_files": len(stored), "tool_link_queries": len(tool_entries),
            "matched_execs": reports[0]["matched_execs"], "negative_api_cases": len(cases),
            "capture_status": runtime["capture"]["status"], "run_dropped_events": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new, nonexistent directory")
    parser.add_argument("--demo", type=Path, default=Path(__file__).resolve().parents[1] / "demo/deepseek-context")
    args = parser.parse_args()
    binary, root, output = args.binary.resolve(), args.demo.resolve(), args.output.resolve()
    manifest = read_json(root / "capture-manifest.json")
    for item in manifest["files"]:
        path = under(root, item["path"])
        assert path.stat().st_size == item["bytes"] and sha256(path) == item["sha256"], "changed demo file"
    bundle_path = under(root, manifest["bundle"])
    with gzip.open(bundle_path, "rb") as stream:
        raw = stream.read((32 << 20) + 1)
    assert len(raw) <= 32 << 20
    assert hashlib.sha256(raw).hexdigest() == manifest["bundle_json_sha256"]
    bundle = json.loads(raw)
    assert bundle["run_id"] == manifest["run_id"] and not bundle["omitted_content"]
    assert bundle["exported_at"] == manifest["exported_at"]
    assert len(bundle.get("telemetry_batch_records", [])) == manifest["expected"]["telemetry_batches"]
    assert not output.exists(), "use a fresh output directory"
    output.mkdir(parents=True)
    store = output / "replay"
    attestation, key = under(root, manifest["attestation"]), under(root, manifest["public_key"])
    invoke(binary, store, "forensics", "verify-attestation", str(bundle_path), str(attestation),
           "--pub-key", str(key), json_output=False)
    assert not (store / "agentprov.db").exists(), "verification must precede import"
    invoke(binary, store, "forensics", "import", str(bundle_path), "--pub-key", str(key), json_output=False)
    assert bundle.get("telemetry_batch_records"), "capture export must preserve full batch records"
    row_bundle = {**bundle, "telemetry_batches": bundle["telemetry_batch_records"]}
    tables = {name: len(rows) for name, rows in row_bundle.items() if isinstance(rows, list) and rows
              and name not in ("object_blobs", "snapshot_files", "omitted_content", "telemetry_batch_records")}
    rows = check_rows(store, row_bundle, tables)
    graph = check_graph(binary, store, manifest["run_id"])
    with dashboard(binary, store) as base:
        checks = check_http(ContextClient(base, manifest["run_id"]), bundle, manifest["expected"])
    invoke(binary, store, "forensics", "import", str(bundle_path), "--pub-key", str(key), json_output=False)
    assert check_rows(store, row_bundle, tables) == rows, "duplicate import changed evidence"
    check_graph(binary, store, manifest["run_id"])
    report = {"schema_version": "agentprovenance.deepseek_acceptance/v1",
              "checked_at": datetime.now(timezone.utc).isoformat(), "binary_sha256": sha256(binary),
              "run_id": manifest["run_id"], "bundle_sha256": sha256(bundle_path),
              "signature_verified_before_import": True, "rows_preserved": rows,
              "object_blobs": len(bundle["object_blobs"]), "snapshot_files": len(bundle["snapshot_files"]),
              "telemetry_batches": len(bundle["telemetry_batch_records"]),
              "graph_errors": graph["error_count"], "graph_warnings": graph["warning_count"],
              "duplicate_import_preserved": True, "http_checks": checks}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
