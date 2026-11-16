"""Durable receipts projected from the bridge's existing capture journal.

action_accept is admission, action_start is dispatch, and action_end is the
durable result (including unknown outcomes). Missing/conflicting records never
authorize replay. This is a local journal, not an authenticated transcript.
"""

import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat

from .browser import PLACEMENT, SCHEMA, _id, safe_url


RECEIPT_SCHEMA = "agentprovenance.browser_operation_receipt/v1"
MAX_OUTPUT_BYTES = 32 << 10
MAX_LINE_BYTES = 12 << 20
MAX_HISTORY_BYTES = 256 << 20
MAX_LOGS = 64
MAX_RECEIPTS = 65536
ACTIONS = ("navigate", "click", "read_text", "screenshot")
SCOPE_KEYS = PLACEMENT + ("browser_id", "context_id")


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def private_directory(path, *, create=False):
    path = Path(path)
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
        if hasattr(os, "O_DIRECTORY"):
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
        raise ValueError("browser receipt directory must be private and owned")


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate journal field")
        value[key] = item
    return value


def _invalid_constant(_):
    raise ValueError("nonfinite journal value")


def project_output(payload):
    """Keep the existing result allowlist; transport URLs stay privacy-projected."""
    output = {k: payload[k] for k in ("url", "status", "text", "bytes", "sha256", "reason") if k in payload}
    for key in ("url", "text", "sha256", "reason"):
        if key in output and not isinstance(output[key], str):
            raise ValueError("invalid result text")
    for key, maximum in (("status", 999), ("bytes", 8 << 20)):
        if key in output and (type(output[key]) is not int or not 0 <= output[key] <= maximum):
            raise ValueError("invalid result number")
    if "sha256" in output and (len(output["sha256"]) != 64 or any(ch not in "0123456789abcdef" for ch in output["sha256"])):
        raise ValueError("invalid result digest")
    if "reason" in output and output["reason"] not in ("capture_policy", "operation_incomplete"):
        raise ValueError("invalid result reason")
    if "url" in output:
        output["url"] = safe_url(output["url"])
    truncated = False
    if "text" in output:
        raw = output["text"].encode("utf-8")
        output["text"] = raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="ignore")
        truncated = len(raw) > MAX_OUTPUT_BYTES
    return output, truncated


class ReceiptStore:
    """Bounded, incremental, read-only recovery; the Capture remains sole writer.

    The configured producer/namespace/instance bounds lookup. Earlier generations
    within that lineage remain historical records, never the current scope.
    """

    def __init__(self, directory, placement):
        self.directory, self.placement = Path(directory), dict(placement)
        self.logs, self.gap = {}, ""

    def accept(self, capture, target, action, value, operation_id):
        self.refresh()
        if self.gap or sum(len(item["operations"]) for item in self.logs.values()) >= MAX_RECEIPTS:
            raise RuntimeError("browser receipt history budget exceeded")
        live = [log for log in self.logs.values() if log["scope"] == capture.scope]
        if (any(capture.scope[k] != self.placement[k] for k in PLACEMENT) or len(live) != 1
                or live[0]["corrupt"] or live[0]["partial"] or live[0]["gap"]):
            raise RuntimeError("browser receipt journal unavailable")
        if any(operation_id in log["operations"] for log in self.logs.values()):
            raise ValueError("browser operation identity already used")
        # Do not persist selectors, URL credentials, queries, or fragments, even
        # as guessable hashes. The digest explicitly commits to this projection.
        normalized = {"action": action}
        redactions = []
        if action == "navigate":
            normalized["url"] = safe_url(value)
            redactions = ["url.userinfo", "url.query", "url.fragment"]
        elif action == "click":
            normalized["selector"] = "__redacted__"
            redactions = ["selector"]
        try:
            capture.event("action_accept", target_id=target, operation_id=operation_id, operation=action,
                          payload={"schema_version": RECEIPT_SCHEMA, "normalized_input_digest": digest(normalized),
                                   "input_digest_basis": "privacy_projected_input/v1", "input_redactions": redactions,
                                   "capture_epoch": capture.scope["browser_id"], "sequence": capture.count + 1,
                                   "run_id": None, "caller_session_id": None, "caller_tool_call_id": None})
            if self.result(operation_id, pending=True)["capture_status"] != "ok":
                raise RuntimeError("admission is not recoverable within the history budget")
        except (OSError, ValueError, RuntimeError):
            capture.stopped = True
            raise RuntimeError("browser receipt admission failed") from None

    def refresh(self):
        if not self.directory.exists():
            if self.logs:
                self.gap = "receipt_log_missing"
            return
        private_directory(self.directory)
        paths = sorted(path for path in self.directory.iterdir()
                       if path.name == "browser.jsonl" or (path.name.startswith("browser-") and path.suffix == ".jsonl"))
        if len(paths) > MAX_LOGS:
            self.gap = "receipt_history_budget_exceeded"
            return
        if any(not (self.directory / name).exists() for name in self.logs):
            self.gap = "receipt_log_missing"
        total = 0
        for path in paths:
            log = self.logs.setdefault(path.name, dict(offset=0, scope=None, operations={}, corrupt=False,
                                                       partial=False, gap=False, identity=None, sequence=0, modified=None,
                                                       event_ids=set()))
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    total += info.st_size
                    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1
                            or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
                        raise ValueError("unsafe journal")
                    identity = (info.st_dev, info.st_ino)
                    if log["identity"] is not None and (log["identity"] != identity or info.st_size < log["offset"]):
                        raise ValueError("replaced journal")
                    modified = (info.st_mtime_ns, info.st_ctime_ns)
                    if (log["modified"] is not None and log["modified"] != modified
                            and info.st_size == log["offset"]):
                        raise ValueError("rewritten journal")
                    log["identity"] = identity
                    log["modified"] = modified
                    if total > MAX_HISTORY_BYTES:
                        self.gap = "receipt_history_budget_exceeded"
                        return
                    if log["corrupt"]:
                        continue
                    stream.seek(log["offset"])
                    log["partial"] = False
                    while True:
                        raw = stream.readline(MAX_LINE_BYTES + 1)
                        if not raw:
                            break
                        if len(raw) > MAX_LINE_BYTES:
                            raise ValueError("journal line budget exceeded")
                        if not raw.endswith(b"\n"):
                            log["partial"] = True
                            break
                        row = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
                        self._record(log, row, path.name, raw)
                        log["offset"] += len(raw)
                        log["sequence"] += 1
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                log["corrupt"] = True

    def _record(self, log, row, name, raw):
        if not isinstance(row, dict) or row.get("schema_version") != SCHEMA or not _id(row.get("timestamp")):
            raise ValueError("invalid journal envelope")
        if datetime.datetime.fromisoformat(row["timestamp"]).utcoffset() is None:
            raise ValueError("journal clock lacks timezone")
        if log["scope"] is None:
            if row.get("type") != "browser_session":
                raise ValueError("journal session missing")
            scope = {k: row[k] for k in SCOPE_KEYS}
            if not all(map(_id, scope.values())):
                raise ValueError("invalid journal scope")
            log["scope"] = scope
            return
        if row.get("type") != "browser_event" or row.get("context_id") != log["scope"]["context_id"]:
            raise ValueError("journal scope changed")
        if not _id(row.get("event_id")) or row["event_id"] in log["event_ids"]:
            raise ValueError("invalid or duplicate event identity")
        log["event_ids"].add(row["event_id"])
        if any(log["scope"][k] != self.placement[k] for k in PLACEMENT[:-1]):
            return
        kind = row.get("kind")
        if kind == "gap":
            log["gap"] = True
        if kind not in ("action_accept", "action_start", "action_end"):
            return
        operation_id = row.get("operation_id")
        if (not all(_id(row.get(k)) for k in ("operation_id", "target_id", "event_id"))
                or row.get("operation") not in ACTIONS or not isinstance(row.get("payload"), dict)):
            raise ValueError("invalid action record")
        state = log["operations"].get(operation_id)
        if state is None and sum(len(item["operations"]) for item in self.logs.values()) >= MAX_RECEIPTS:
            self.gap = "receipt_history_budget_exceeded"
            raise ValueError("receipt count exceeded")
        if kind == "action_accept":
            if state is not None:
                state["conflict"] = True
                return
            payload = row["payload"]
            input_digest = payload.get("normalized_input_digest", "")
            if (payload.get("schema_version") != RECEIPT_SCHEMA
                    or payload.get("input_digest_basis") != "privacy_projected_input/v1"
                    or not isinstance(input_digest, str) or len(input_digest) != 71 or not input_digest.startswith("sha256:")
                    or any(ch not in "0123456789abcdef" for ch in input_digest[7:])
                    or payload.get("capture_epoch") != log["scope"]["browser_id"]
                    or payload.get("sequence") != log["sequence"]
                    or payload.get("input_redactions") not in ([], ["selector"], ["url.userinfo", "url.query", "url.fragment"])
                    or any(payload.get(k) is not None for k in ("run_id", "caller_session_id", "caller_tool_call_id"))):
                raise ValueError("invalid accept receipt")
            state = dict(accept=None, start=None, end=None, conflict=False)
            log["operations"][operation_id] = state
        if state is None:
            # Legacy action logs have no durable admission. Do not upgrade them
            # to receipts or treat their operation IDs as new executions.
            log["operations"][operation_id] = dict(accept=None, start=None, end=None, conflict=True)
            return
        slot = {"action_accept": "accept", "action_start": "start", "action_end": "end"}[kind]
        accept = state["accept"]
        if kind != "action_accept" and (accept is None
                or any(row[k] != accept["row"][k] for k in ("operation", "target_id"))
                or state[slot] is not None or (kind == "action_end" and state["start"] is None)):
            state["conflict"] = True
            return
        state[slot] = {"row": row, "source_ref": {"log": name, "event_id": row["event_id"],
                                                  "sha256": hashlib.sha256(raw).hexdigest()}}

    def result(self, operation_id, *, pending=False):
        if not _id(operation_id):
            raise ValueError("invalid browser operation identity")
        self.refresh()
        matches = [(log, log["operations"][operation_id]) for log in self.logs.values()
                   if operation_id in log["operations"]]
        if not matches:
            raise ValueError("unknown browser operation")
        if len(matches) != 1:
            raise ValueError("ambiguous browser operation")
        if matches[0][1]["accept"] is None:
            raise ValueError("unknown browser operation")
        log, state = matches[0]
        accept = state["accept"]["row"]
        start = state["start"]["row"] if state["start"] else None
        end = state["end"]["row"] if state["end"] else None
        reason = (self.gap or ("receipt_log_corrupt" if log["corrupt"] else "")
                  or ("receipt_identity_conflict" if state["conflict"] else ""))
        status, output, truncated = "unknown", {}, False
        if not reason and end:
            if end.get("status", "ok") == "ok":
                try:
                    output, truncated = project_output(end["payload"])
                    status = "ok"
                except (AttributeError, TypeError, ValueError):
                    reason = "receipt_log_corrupt"
            else:
                reason = "operation_incomplete"
        if not reason and not end and not pending:
            reason = "result_not_recorded"
        gaps = [reason] if reason else []
        if log["partial"]:
            gaps.append("receipt_log_partial_tail")
        if log["gap"]:
            gaps.append("browser_capture_gap")
        payload = accept["payload"]
        receipt = {"schema_version": RECEIPT_SCHEMA, "scope": dict(log["scope"]),
                   "target_id": accept["target_id"], "operation_id": operation_id, "action": accept["operation"],
                   "normalized_input_digest": payload["normalized_input_digest"],
                   "input_digest_basis": payload["input_digest_basis"], "input_redactions": payload["input_redactions"],
                   "accepted_at": accept["timestamp"], "started_at": start["timestamp"] if start else None,
                   "ended_at": end["timestamp"] if end else None, "sequence": payload["sequence"],
                   "run_id": None, "caller_session_id": None, "caller_tool_call_id": None,
                   "capture_epoch": payload["capture_epoch"], "outcome": status, "gap_refs": gaps,
                   "source_refs": {k: state[k]["source_ref"] for k in ("accept", "start", "end") if state[k]},
                   "result_digest": digest({"output": output, "output_truncated": truncated}) if status == "ok" else None,
                   "bridge_identity": {"source": "local_bridge_configuration", "authentication": "unverified",
                                       "transcript_identity": "source_asserted_only",
                                       "identity": {k: log["scope"][k] for k in PLACEMENT}}}
        receipt["digest"] = digest(receipt)
        return copy.deepcopy({"browser_operation": {"scope": dict(log["scope"]), "target_id": accept["target_id"],
                                                     "operation_id": operation_id, "operation": accept["operation"]},
                              "browser_receipt": receipt, "execution_status": status, "execution_reason": reason,
                              "capture_status": "partial" if gaps else "ok", "capture_reason": gaps[0] if gaps else "",
                              "output": output, "output_truncated": truncated})
