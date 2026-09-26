#!/usr/bin/env python3
"""Standalone Jev reference integration: capture, inspect, compare, review and export.

Calls the existing public CLI for verification; it is not part of the main
dashboard or daemon. It does not modify core storage, execute evidence, install
policies or run a general optimization workflow.
"""

from datetime import datetime, timezone
import difflib
import fcntl
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import statistics
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit

import judge
import rules


# Shared display helpers ship beside both optional evaluators in the archive.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from localization import CATALOG, Parser, cli_language, diagnostic, page, request_language, tr


HERE = Path(__file__).resolve().parent
VERSIONS = ("v1", "v2")
MAX_BODY = 32_768
MAX_AUDIT = 10_000


def now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    return json.loads(path.read_bytes())


def canonical_hash(value):
    return judge.digest(judge.encode(value))


def atomic_event(path, value):
    """Publish a complete, durable event without replacing an earlier event."""
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(judge.encode(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def run_cli(binary, root, *args):
    result = subprocess.run([str(binary), "--data-dir", str(root / "store"), *args, "--json"],
                            capture_output=True, timeout=180, check=False)
    if result.returncode:
        raise ValueError("AgentProvenance CLI failed; no completed study was published")
    return json.loads(result.stdout)


def capture(args):
    if not args.send_raw:
        raise ValueError("Capture requires --send-raw: selected evidence is sent without redaction")
    root = args.data_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    key = judge.load_key(args.key_file, args.provider)
    # Import verifies the signed bundle against the explicitly supplied trust key.
    print(tr(getattr(args, "lang", "en"), "Verifying the signed source bundle and graph before provider calls..."), flush=True)
    run_cli(args.agentprov, root, "forensics", "import", str(args.bundle), "--pub-key", str(args.pub_key))
    manifest = judge.make_cases(args.bundle)
    verification = run_cli(args.agentprov, root, "graph", "verify", "--run", manifest["run_id"])
    if verification.get("status") != "ok" or verification.get("error_count") != 0:
        raise ValueError("Graph verification failed; no provider requests were made")
    judge.save(root / "verification.json", verification)
    judge.save(root / "cases.json", manifest)
    profile_set = rules.profiles()
    reports = {}
    for version, profile in profile_set.items():
        judge.save(root / "rules" / (version + ".json"), profile)
        results = []
        for case in manifest["cases"]:
            result = judge.evaluate(args.provider, key, case["state"], profile["questions"],
                                    root / "evaluations" / version / case["id"])
            results.append({**result, "case_id": case["id"]})
            print(json.dumps({"version": version, "case": case["id"],
                              "choices": {k: v["choice"] for k, v in result["answers"].items()},
                              "latency_ms": result["latency_ms"]}), flush=True)
        reports[version] = {"profile_sha256": canonical_hash(profile),
                            "dataset_sha256": canonical_hash(manifest), "results": results}
        judge.save(root / "evaluations" / version / "report.json", reports[version])
    study = {
        "schema_version": "agentprovenance.jev_review/v1", "created_at": now(),
        "run_id": manifest["run_id"], "bundle_sha256": manifest["bundle_sha256"],
        "dataset_sha256": canonical_hash(manifest), "guard_version": rules.GUARD_VERSION,
        "verification_sha256": canonical_hash(verification),
        "trust_key_sha256": judge.digest(args.pub_key.read_bytes()),
        "profiles": {v: canonical_hash(p) for v, p in profile_set.items()},
        "reports": {v: canonical_hash(r) for v, r in reports.items()},
        "provider": args.provider, "evaluation_kind": "live_provider",
        "disclosure": "Selected raw demo evidence; no redaction. Local hashes are not a signed judge attestation.",
    }
    judge.save(root / "study.json", study)
    print(json.dumps({"study": str(root), "calls": len(manifest["cases"]) * 2, "review": "pending"}), flush=True)


class Conflict(ValueError):
    pass


class Study:
    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.Lock()
        self.audit_dir = self.root / "reviews"
        self.audit_dir.mkdir(mode=0o700, exist_ok=True)
        self.load()

    def load(self):
        """Verify immutable inputs and exact wire bodies before trusting an assessment."""
        study = read_json(self.root / "study.json")
        manifest = read_json(self.root / "cases.json")
        verification = read_json(self.root / "verification.json")
        if study["guard_version"] != rules.GUARD_VERSION:
            raise ValueError("Coverage guard changed; capture a new study")
        if canonical_hash(manifest) != study["dataset_sha256"] or canonical_hash(verification) != study["verification_sha256"]:
            raise ValueError("Study input integrity check failed")
        ids = [case["id"] for case in manifest["cases"]]
        if not 1 <= len(ids) <= 20 or len(ids) != len(set(ids)) or any(not judge.re.fullmatch(r"[a-z0-9_]+", cid) for cid in ids):
            raise ValueError("Invalid case inventory")
        profile_set, reports = {}, {}
        for version in VERSIONS:
            profile = read_json(self.root / "rules" / (version + ".json"))
            report = read_json(self.root / "evaluations" / version / "report.json")
            if (canonical_hash(profile) != study["profiles"][version]
                    or canonical_hash(report) != study["reports"][version]
                    or report["profile_sha256"] != study["profiles"][version]
                    or report["dataset_sha256"] != study["dataset_sha256"]):
                raise ValueError("Rule or report integrity check failed")
            if set(profile["questions"]) != set(judge.QUESTIONS):
                raise ValueError("Invalid question inventory")
            if [r["case_id"] for r in report["results"]] != ids:
                raise ValueError("Reports must cover exactly the same cases")
            for case, result in zip(manifest["cases"], report["results"]):
                directory = self.root / "evaluations" / version / case["id"]
                request_bytes = (directory / "request.json").read_bytes()
                response_bytes = (directory / "response.json").read_bytes()
                request = json.loads(request_bytes)
                response = json.loads(response_bytes)
                if (judge.digest(request_bytes) != result["request_sha256"]
                        or judge.digest(response_bytes) != result["response_sha256"]
                        or request["state"] != case["state"] or request["questions"] != profile["questions"]
                        or request["model"] != result["requested_model"]
                        or result["questions_sha256"] != canonical_hash(profile["questions"])
                        or judge.validate_answers(response, profile["questions"]) != result["answers"]
                        or response.get("model") != result["returned_model"]):
                    raise ValueError("Provider artifact integrity check failed")
            profile_set[version], reports[version] = profile, report
        return study, manifest, profile_set, reports, verification

    def journal(self, study_hash):
        files = sorted(self.audit_dir.glob("*.json"))
        if len(files) > MAX_AUDIT:
            raise ValueError("Review journal exceeds demo limit")
        events, previous = [], None
        for number, path in enumerate(files, 1):
            event = read_json(path)
            if (path.name != "%06d.json" % number or event["revision"] != number
                    or event["previous_sha256"] != previous or event["study_sha256"] != study_hash
                    or event.get("content_sha256") != canonical_hash({k: v for k, v in event.items() if k != "content_sha256"})
                    or event["kind"] not in {"review", "decision"}):
                raise ValueError("Review journal integrity check failed")
            events.append(event)
            previous = canonical_hash(event)
        return events

    def snapshot(self):
        study, manifest, profile_set, reports, verification = self.load()
        study_hash = canonical_hash(study)
        events = self.journal(study_hash)
        reviews = {event["case_id"]: event for event in events if event["kind"] == "review"}
        review_hash = canonical_hash(reviews)
        decisions = [event for event in events if event["kind"] == "decision"]
        decision = decisions[-1] if decisions else None
        decision_current = bool(decision and decision["reviews_sha256"] == review_hash)
        cases = []
        for index, case in enumerate(manifest["cases"]):
            evaluations = {v: {**reports[v]["results"][index],
                               "effective": rules.effective_answers(case, reports[v]["results"][index]["answers"])}
                           for v in VERSIONS}
            cases.append({**case, "evaluations": evaluations, "review": reviews.get(case["id"])})
        metrics = {}
        for version in VERSIONS:
            results = [case["evaluations"][version] for case in cases]
            reviewed = [case for case in cases if case["review"]]
            metrics[version] = {
                "mean_latency_ms": round(statistics.mean(r["latency_ms"] for r in results), 2),
                "models": sorted({r["returned_model"] or "not_reported" for r in results}),
                "raw_disagreements": sum(r["evaluations"][version]["answers"][q]["choice"] != r["review"]["labels"][q]
                                         for r in reviewed for q in judge.QUESTIONS),
                "effective_disagreements": sum(r["evaluations"][version]["effective"]["choices"][q] != r["review"]["labels"][q]
                                               for r in reviewed for q in judge.QUESTIONS),
                "reviewed_decisions": len(reviewed) * len(judge.QUESTIONS),
                "guard_overrides": sum(len(r["effective"]["overrides"]) for r in results),
                "input_tokens": sum((r.get("usage") or {}).get("input_tokens", 0) for r in results),
            }
        raw_regressions, effective_regressions = [], []
        for case in cases:
            if not case["review"]:
                continue
            for question, expected in case["review"]["labels"].items():
                v1, v2 = (case["evaluations"][v] for v in VERSIONS)
                if v1["answers"][question]["choice"] == expected and v2["answers"][question]["choice"] != expected:
                    raw_regressions.append(case["id"] + ":" + question)
                if v1["effective"]["choices"][question] == expected and v2["effective"]["choices"][question] != expected:
                    effective_regressions.append(case["id"] + ":" + question)
        reasons = []
        if len(reviews) != len(cases):
            reasons.append("Review every case before approving the candidate")
        if raw_regressions or effective_regressions:
            reasons.append("Candidate regresses on reviewed decisions; reject or revise it in a new study")
        if any(not case["evaluations"]["v1"]["returned_model"]
               or case["evaluations"]["v1"]["returned_model"] != case["evaluations"]["v2"]["returned_model"] for case in cases):
            reasons.append("Returned model identity is missing or differs for a case; this is not a same-model rule comparison")
        lines = [json.dumps(profile_set[v]["questions"], ensure_ascii=False, indent=2).splitlines(keepends=True) for v in VERSIONS]
        rule_diff = "".join(difflib.unified_diff(*lines, fromfile="v1/questions.json", tofile="v2/questions.json"))
        return {"study": study, "study_sha256": study_hash, "verification": verification,
                "profiles": profile_set, "cases": cases, "metrics": metrics, "rule_diff": rule_diff,
                "revision": len(events), "reviews_sha256": review_hash, "reviewed_cases": len(reviews),
                "decision": decision, "decision_current": decision_current, "audit": events,
                "approval_blockers": reasons, "raw_regressions": raw_regressions,
                "effective_regressions": effective_regressions}

    def append(self, kind, body):
        with self.lock:
            lockfd = os.open(self.audit_dir / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            with os.fdopen(lockfd, "w") as lockfile:
                fcntl.flock(lockfile, fcntl.LOCK_EX)
                state = self.snapshot()
                if type(body.get("revision")) is not int or body["revision"] != state["revision"]:
                    raise Conflict("Review changed in another tab; reload before saving")
                if state["revision"] >= MAX_AUDIT:
                    raise ValueError("Review journal exceeds demo limit")
                reviewer, reason = body.get("reviewer"), body.get("reason")
                if not isinstance(reviewer, str) or not 1 <= len(reviewer.strip()) <= 80:
                    raise ValueError("Reviewer name is required (maximum 80 characters)")
                if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 3000:
                    raise ValueError("A review reason of 5-3000 characters is required")
                payload = {"reviewer": reviewer.strip(), "reason": reason.strip()}
                if kind == "review":
                    cases = {case["id"]: case for case in state["cases"]}
                    if body.get("case_id") not in cases:
                        raise ValueError("Unknown case")
                    labels = body.get("labels")
                    if not isinstance(labels, dict) or set(labels) != set(judge.QUESTIONS):
                        raise ValueError("Review all three questions explicitly")
                    for question, label in labels.items():
                        if not isinstance(label, str) or label not in judge.QUESTIONS[question]["criteria"]:
                            raise ValueError("Unknown review label")
                    if not cases[body["case_id"]]["state"].get("runtime_events") and any(labels[q] != "unknown" for q in ("runtime_conformance", "secret_transfer")):
                        raise ValueError("No runtime coverage: runtime review labels must remain unknown")
                    payload.update(case_id=body["case_id"], labels=labels)
                elif kind == "decision":
                    if body.get("status") not in ("approved", "rejected"):
                        raise ValueError("Choose approved or rejected")
                    if body["status"] == "approved" and state["approval_blockers"]:
                        raise ValueError("; ".join(state["approval_blockers"]))
                    payload.update(status=body["status"], candidate="v2", reviews_sha256=state["reviews_sha256"])
                else:
                    raise ValueError("Unknown journal action")
                event = {"revision": state["revision"] + 1, "kind": kind, "at": now(),
                         "study_sha256": state["study_sha256"],
                         "previous_sha256": canonical_hash(state["audit"][-1]) if state["audit"] else None,
                         **payload}
                event["content_sha256"] = canonical_hash(event)
                atomic_event(self.audit_dir / ("%06d.json" % event["revision"]), event)
                return self.snapshot()

    def signals(self):
        state = self.snapshot()
        if (not state["decision_current"] or state["decision"]["status"] != "approved"
                or state["approval_blockers"]):
            raise ValueError("A current candidate approval is required before export")
        case = next(c for c in state["cases"] if c["id"] == "runtime_evidence" and c["origin"] == "captured_subset")
        result = case["evaluations"]["v2"]
        signals = []
        for question, answer in result["answers"].items():
            signals.append({
                "id": "jev-" + result["request_sha256"][:16] + "-" + question,
                "name": "jev." + question, "kind": "quality_signal", "run_id": state["study"]["run_id"],
                "score": answer["probabilities"][answer["choice"]], "label": answer["choice"],
                "reason": "Model inference on selected run-level evidence; human review stored separately. Not enforcement or proof of exfiltration.",
                "evidence": {"source": "external_evaluator", "model": result["returned_model"],
                             "request_sha256": result["request_sha256"], "response_sha256": result["response_sha256"],
                             "study_sha256": state["study_sha256"], "rules_sha256": state["study"]["profiles"]["v2"],
                             "evidence_ids": case["evidence_ids"], "coverage": case["state"]["coverage"],
                             "raw_answer": answer, "effective_label": result["effective"]["choices"][question],
                             "human_review": case["review"], "approval": state["decision"],
                             "review_identity": "self_reported_local_reviewer_not_authenticated"},
            })
        return {"signals": signals}


def make_server(study, port):
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def send(self, status, value, mime="application/json; charset=utf-8", language=None, remember=False):
            body = value if isinstance(value, bytes) else judge.encode(value)
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if language:
                self.send_header("Content-Language", language)
            if remember:
                self.send_header("Set-Cookie", "agentprov_language=%s; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax" % language)
            self.end_headers()
            self.wfile.write(body)

        def allowed(self):
            host = "127.0.0.1:%d" % self.server.server_port
            origin = self.headers.get("Origin")
            return self.headers.get("Host") == host and (origin is None or origin == "http://" + host)

        def do_GET(self):
            if not self.allowed():
                return self.send(403, {"error": "Loopback same-origin access only"})
            path = urlsplit(self.path).path
            try:
                if path == "/api/state":
                    return self.send(200, {**study.snapshot(), "csrf_token": token})
                if path == "/api/signals":
                    return self.send(200, study.signals())
                parts = path.split("/")
                if len(parts) == 6 and parts[1:3] == ["api", "artifact"]:
                    version, case_id, name = parts[3:]
                    current = study.snapshot()
                    if version in VERSIONS and case_id in {c["id"] for c in current["cases"]} and name in {"request.json", "response.json"}:
                        return self.send(200, (study.root / "evaluations" / version / case_id / name).read_bytes())
                    return self.send(404, {"error": "Unknown study artifact"})
                if path == "/i18n.json":
                    return self.send(200, CATALOG)
                assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
                if path in assets:
                    name, mime = assets[path]
                    if path == "/":
                        language, remember = request_language(self.path, self.headers)
                        body = page((HERE / "web" / name).read_text(encoding="utf-8"), language).encode("utf-8")
                        return self.send(200, body, mime + "; charset=utf-8", language, remember)
                    return self.send(200, (HERE / "web" / name).read_bytes(), mime + "; charset=utf-8")
                return self.send(404, {"error": "Not found"})
            except (ValueError, OSError, KeyError, TypeError):
                return self.send(409, {"error": "Study integrity or approval check failed; inspect the local study"})

        def do_POST(self):
            if not self.allowed() or not hmac.compare_digest(self.headers.get("X-Review-Token", "").encode(), token.encode()):
                return self.send(403, {"error": "Invalid local review token or origin"})
            if self.headers.get("Content-Type") != "application/json" or self.headers.get("Transfer-Encoding"):
                return self.send(415, {"error": "Expected bounded JSON body"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                size = 0
            if not 0 < size <= MAX_BODY:
                return self.send(413, {"error": "Review body size is invalid"})
            kind = {"/api/review": "review", "/api/decision": "decision"}.get(self.path)
            if not kind:
                return self.send(404, {"error": "Not found"})
            try:
                self.connection.settimeout(5)
                body = json.loads(self.rfile.read(size))
                if not isinstance(body, dict):
                    raise ValueError("Expected a JSON object")
                return self.send(200, {**study.append(kind, body), "csrf_token": token})
            except Conflict as error:
                return self.send(409, {"error": str(error)})
            except (ValueError, OSError, KeyError, TypeError) as error:
                message = str(error) if type(error) is ValueError else "Invalid review request or unavailable local storage"
                return self.send(400, {"error": message})

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = Parser(description='Jev workbench: capture, inspect, compare, review and export. Local review makes no provider calls.', language=cli_language())
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("capture", help=tr(cli_language(), "Verify a demo bundle and call Jev 12 times (6 cases x 2 rubrics)"))
    prepare.add_argument("--data-dir", type=Path, required=True, help="New private output directory, outside Git")
    prepare.add_argument("--bundle", type=Path, default=HERE.parent / "multiagent-provenance/run-double-attempt.forensics.json.gz", help='Signed source bundle')
    prepare.add_argument("--pub-key", type=Path, default=HERE.parent / "multiagent-provenance/attestation.pub", help='Trusted public key')
    prepare.add_argument("--agentprov", type=Path, required=True, help='AgentProvenance executable')
    prepare.add_argument("--key-file", type=Path, required=True, help='Private key file')
    prepare.add_argument("--provider", choices=judge.ENDPOINTS, required=True, help='Evaluation provider')
    prepare.add_argument("--send-raw", action="store_true", help='Authorize sending selected case contents without redaction')
    serve = sub.add_parser("serve", help=tr(cli_language(), "Open an existing study; no key or provider calls"))
    serve.add_argument("--data-dir", type=Path, required=True, help='Evidence store directory')
    serve.add_argument("--port", type=int, default=8641, help='Local server port')
    export = sub.add_parser("export", help=tr(cli_language(), "Export reviewed candidate signals; never installs a policy"))
    export.add_argument("--data-dir", type=Path, required=True, help='Evidence store directory')
    export.add_argument("--output", type=Path, required=True, help='Export destination')
    args = parser.parse_args()
    if args.command == "capture":
        capture(args)
    elif args.command == "export":
        judge.save(args.output, Study(args.data_dir).signals())
        print(tr(cli_language(), "Exported candidate signals; use a fresh store for signal import"))
    else:
        server = make_server(Study(args.data_dir), args.port)
        print(tr(cli_language(), "Jev review: http://127.0.0.1:%s%s (local only; no provider calls)", server.server_port, "/?lang=" + args.lang if hasattr(args, "lang") else ""), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        detail = str(error) if type(error) in (ValueError, RuntimeError) else type(error).__name__
        print(tr(cli_language(), "Jev workbench stopped: %s. Existing evidence was not overwritten.", diagnostic(cli_language(), detail)), file=sys.stderr)
        sys.exit(1)
