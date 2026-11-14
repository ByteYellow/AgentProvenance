"""Bounded HAR projection from already-filtered native CDP observations."""

import datetime
import json
import math


class HARCapture:
    def __init__(self, scope, *, max_entries=4096, max_bytes=8 << 20):
        if not 1 <= max_entries <= 4096 or not 16384 <= max_bytes <= 8 << 20:
            raise ValueError("invalid HAR budget")
        self.scope, self.max_entries, self.max_bytes = dict(scope), max_entries, max_bytes
        self.entries, self.starts, self.response_times = {}, {}, {}
        self.omitted, self.size = 0, 8192
        self.incomplete = False

    @staticmethod
    def key(native):
        return native["cdp_session_id"], native["request_id"], native["redirect_index"]

    @staticmethod
    def number(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)

    def _replace(self, key, value):
        old = self.entries.get(key)
        size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()) + 1
        previous = len(json.dumps(old, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()) + 1 if old else 0
        if (old is None and len(self.entries) >= self.max_entries) or self.size + size - previous > self.max_bytes:
            if old is None:
                self.omitted += 1
            self.incomplete = True
            return False
        self.size += size - previous
        self.entries[key] = value
        return True

    def request(self, native, payload, monotonic, wall):
        key = self.key(native)
        if key in self.entries:
            raise ValueError("duplicate HAR request identity")
        if not self.number(wall) or not self.number(monotonic) or not payload["url"]:
            self.omitted += 1
            return
        started = datetime.datetime.fromtimestamp(wall, datetime.timezone.utc).isoformat()
        value = {"startedDateTime": started, "time": 0,
                 "request": {"method": payload["method"], "url": payload["url"], "httpVersion": "",
                             "headers": [], "cookies": [], "queryString": [], "headersSize": -1, "bodySize": -1},
                 "response": {"status": 0, "statusText": "", "httpVersion": "", "cookies": [], "headers": [],
                              "content": {"size": -1, "mimeType": ""}, "redirectURL": "", "headersSize": -1, "bodySize": -1},
                 "cache": {}, "timings": {k: -1 for k in ("blocked", "dns", "connect", "ssl", "send", "wait", "receive")},
                 "_agentprovenance": {k: native[k] for k in ("target_id", "target_type", "cdp_session_id", "request_id", "redirect_index", "frame_id", "loader_id")}}
        value["_agentprovenance"].update(outcome="pending", observed_duration_ms=None, encoded_bytes=None)
        if self._replace(key, value):
            self.starts[key] = monotonic

    def response(self, native, payload, protocol, timing):
        key = self.key(native)
        if key not in self.entries:
            return
        value = json.loads(json.dumps(self.entries[key]))
        response = value["response"]
        response.update(status=payload["status"], httpVersion=protocol if protocol in ("http/1.0", "http/1.1", "h2", "h3") else "")
        response["httpVersion"] = {"http/1.0": "HTTP/1.0", "http/1.1": "HTTP/1.1", "h2": "HTTP/2", "h3": "HTTP/3"}.get(response["httpVersion"], "")
        value["request"]["httpVersion"] = response["httpVersion"]
        response["content"]["mimeType"] = payload["mime_type"]
        timing = timing or {}
        phases = value["timings"]
        for name, start, end in (("dns", "dnsStart", "dnsEnd"), ("connect", "connectStart", "connectEnd"),
                                 ("ssl", "sslStart", "sslEnd"), ("send", "sendStart", "sendEnd"), ("wait", "sendEnd", "receiveHeadersEnd")):
            a, b = timing.get(start), timing.get(end)
            if self.number(a) and self.number(b) and 0 <= a <= b:
                phases[name] = b - a
        start_values = [timing[k] for k in ("dnsStart", "connectStart", "sendStart") if self.number(timing.get(k)) and timing[k] >= 0]
        if start_values:
            phases["blocked"] = min(start_values)
        request, headers = timing.get("requestTime"), timing.get("receiveHeadersEnd")
        if self.number(request) and self.number(headers) and headers >= 0:
            self.response_times[key] = request + headers / 1000
        self._total(value)
        self._replace(key, value)

    @staticmethod
    def _total(value):
        value["time"] = sum(v for k, v in value["timings"].items() if k != "ssl" and v >= 0)

    def finish(self, native, monotonic, outcome, *, encoded=None, redirect=""):
        key = self.key(native)
        if key not in self.entries:
            return
        value = json.loads(json.dumps(self.entries[key]))
        meta = value["_agentprovenance"]
        meta["outcome"] = outcome
        if self.number(monotonic) and monotonic >= self.starts[key]:
            meta["observed_duration_ms"] = (monotonic - self.starts[key]) * 1000
            received = self.response_times.get(key)
            if received is not None and monotonic >= received:
                value["timings"]["receive"] = (monotonic - received) * 1000
        if isinstance(encoded, int) and not isinstance(encoded, bool) and encoded >= 0:
            meta["encoded_bytes"] = encoded
        value["response"]["redirectURL"] = redirect
        self._total(value)
        self._replace(key, value)

    def document(self, *, incomplete=False):
        return {"log": {"version": "1.2", "creator": {"name": "AgentProvenance", "version": "har_projection/v1"},
                        "_agentprovenance": {"scope": self.scope, "capture_state": "incomplete" if incomplete or self.incomplete or self.omitted else "closed",
                                             "omitted_entries": self.omitted}, "entries": list(self.entries.values())}}
