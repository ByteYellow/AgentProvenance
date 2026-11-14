"""Bounded, local Jupyter message recording. Does not execute or retry requests."""

import datetime
import json
import os
import threading


SCHEMA = "agentprovenance.jupyter_capture/v1"
SCOPE_FIELDS = (
    "producer_id", "namespace", "instance_id", "generation", "notebook_id",
    "kernel_id", "kernel_session_id",
)


def _time():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _json(value):
    def convert(item):
        if isinstance(item, datetime.datetime):
            return item.isoformat()
        raise TypeError("notebook message contains an unsupported value")
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                       default=convert, allow_nan=False) + "\n").encode("utf-8")


class Recorder:
    """Record messages from one observed kernel session into a new private file.

    The caller supplies trusted local placement metadata and the kernel session
    observed in kernel_info_reply. Record outgoing messages after send(), and
    incoming messages returned by the client's authenticated channel decoder.
    A restart requires a new file/Recorder; connection keys are never accepted.
    """

    def __init__(self, path, scope, *, client_version, max_bytes=128 << 20,
                 max_messages=24998):
        if set(scope) != set(SCOPE_FIELDS):
            raise ValueError("notebook scope requires exactly the documented identity fields")
        for value in scope.values():
            if (not isinstance(value, str) or not value or value.strip() != value
                    or len(value.encode("utf-8")) > 512
                    or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value)):
                raise ValueError("invalid notebook identity")
        if not 8192 <= max_bytes <= 128 << 20 or not 1 <= max_messages <= 24998:
            raise ValueError("invalid notebook capture budget")
        self.scope = dict(scope)
        self.max_bytes, self.max_messages = max_bytes, max_messages
        self.count, self.size, self.stopped = 0, 0, False
        self.lock = threading.Lock()
        self.file = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        try:
            self._write({"type": "notebook_session", "schema_version": SCHEMA, **scope,
                         "jupyter_client_version": client_version, "timestamp": _time()})
        except BaseException:
            self.file.close()
            raise

    def _write(self, value):
        raw = _json(value)
        self.file.write(raw)
        self.file.flush()
        os.fsync(self.file.fileno())
        self.size += len(raw)

    def record(self, channel, direction, message):
        if channel not in ("shell", "control", "iopub") or direction not in ("send", "receive"):
            raise ValueError("invalid notebook channel or direction")
        header = message.get("header", {})
        if direction == "receive" and header.get("session") != self.scope["kernel_session_id"]:
            raise ValueError("kernel identity changed; start a new notebook capture")
        # ZeroMQ identities, signatures, connection settings and binary buffers
        # are not transcript fields. The importer inventories non-text MIME data.
        if message.get("buffers"):
            raise ValueError("binary buffers require typed attachment capture")
        projected = {key: message.get(key, {}) for key in ("header", "parent_header", "content", "metadata")}
        value = {"type": "notebook_message", "schema_version": SCHEMA, "channel": channel,
                 "direction": direction, "observed_at": _time(), "message": projected}
        raw = _json(value)
        with self.lock:
            if self.stopped or self.file.closed:
                raise ValueError("notebook capture is closed")
            if self.count >= self.max_messages or len(raw) > 32 << 20 or self.size + len(raw) + 4096 > self.max_bytes:
                self._write({"type": "notebook_gap", "schema_version": SCHEMA,
                             "timestamp": _time(), "reason": "capture_budget_exceeded"})
                self.stopped = True
                raise ValueError("notebook capture budget exceeded")
            self._write(value)
            self.count += 1

    def close(self):
        with self.lock:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
