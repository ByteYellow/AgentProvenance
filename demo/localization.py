"""Presentation-only language support for the optional Python evaluators.

Never call these helpers while constructing evidence, requests, or audit records.
"""
import argparse
from functools import partial
from http.cookies import CookieError, SimpleCookie
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qs, urlsplit

CATALOG = json.loads(Path(__file__).with_name("zh-CN.json").read_text(encoding="utf-8"))


def normalize(value):
    value = value.strip().lower()
    if value in ("zh", "zh-cn", "zh-hans"):
        return "zh-CN"
    if value in ("en", "en-us", "en-gb"):
        return "en"
    return None


def cli_language(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    language = "en"
    for index, arg in enumerate(argv):
        if arg == "--":
            break
        value = arg.partition("=")[2] if arg.startswith("--lang=") else (
            argv[index + 1] if arg == "--lang" and index + 1 < len(argv) else "")
        language = normalize(value) or language
    return language


def request_language(path, headers):
    explicit = normalize(parse_qs(urlsplit(path).query).get("lang", [""])[0])
    if explicit:
        return explicit, True
    cookie = SimpleCookie()
    try:
        cookie.load(headers.get("Cookie", ""))
        saved = cookie.get("agentprov_language")
        if saved and normalize(saved.value):
            return normalize(saved.value), False
    except (ValueError, TypeError, CookieError):
        pass
    preferences = []
    for index, item in enumerate(headers.get("Accept-Language", "").split(",")):
        parts = item.strip().split(";")
        try:
            weight = float(parts[1].strip().removeprefix("q=")) if len(parts) == 2 else 1.0
        except ValueError:
            continue
        if 0 < weight <= 1:
            preferences.append((-weight, index, parts[0].lower().split("-")[0]))
    for _, _, base in sorted(preferences):
        if base in ("en", "zh"):
            return ("zh-CN" if base == "zh" else "en"), False
    return "en", False


def tr(language, source, *values):
    template = CATALOG.get(source, source) if language == "zh-CN" else source
    return template % values if values else template


def diagnostic(language, message):
    """Translate only app-owned diagnostics; opaque tails keep their original bytes."""
    if language != "zh-CN":
        return message
    if message in CATALOG:
        return CATALOG[message]
    if "; " in message:
        parts = message.split("; ")
        if all(p in CATALOG for p in parts):
            return "；".join(CATALOG[p] for p in parts)
    for prefix in (
        "Missing or invalid typed answer: ", "Unknown choice: ",
        "Incomplete probability distribution: ", "Invalid probability: ",
        "Probabilities do not sum to one: ", "Invalid confidence: ",
        "the following arguments are required: ", "unrecognized arguments: ",
        "argument ",
    ):
        if message.startswith(prefix):
            tail = message[len(prefix):]
            if prefix == "argument ":
                name, sep, reason = tail.partition(": ")
                return tr(language, prefix) + name + ("：" + diagnostic(language, reason) if sep else "")
            return tr(language, prefix) + tail
    for source, pattern in (
        ("Provider returned HTTP %s; stopped, not classified as safe", r"Provider returned HTTP (\d+); stopped, not classified as safe"),
        ("invalid choice: %s (choose from %s)", r"invalid choice: (.*?) \(choose from (.*)\)"),
        ("invalid choice: %s", r"invalid choice: (.*)"),
        ("invalid int value: %s", r"invalid int value: (.*)"),
        ("agentprov %s timed out after %ss", r"agentprov (.*?) timed out after (\S+)s"),
        ("agentprov %s failed rc=%s: %s", r"agentprov (.*?) failed rc=(\d+): ([\s\S]*)"),
        ("LLM HTTP %s: %s", r"LLM HTTP (\d+): ([\s\S]*)"),
    ):
        match = re.fullmatch(pattern, message)
        if match:
            return tr(language, source, *match.groups())
    return message


class Parser(argparse.ArgumentParser):
    """Per-invocation help and errors; no process-wide gettext changes."""
    def __init__(self, *args, language="en", **kwargs):
        self.language = language
        kwargs["add_help"] = False
        if kwargs.get("description"):
            kwargs["description"] = tr(language, kwargs["description"])
        super().__init__(*args, **kwargs)
        self._positionals.title = tr(language, "positional arguments")
        self._optionals.title = tr(language, "options")
        self.add_argument("-h", "--help", action="help", help="show this help message and exit")
        self.add_argument("--lang", choices=("en", "zh-CN"), default=argparse.SUPPRESS,
                          help="Display language (default: English)")

    def add_argument(self, *args, **kwargs):
        if kwargs.get("help") and kwargs["help"] != argparse.SUPPRESS:
            kwargs["help"] = tr(self.language, kwargs["help"])
        return super().add_argument(*args, **kwargs)

    def add_subparsers(self, **kwargs):
        kwargs["parser_class"] = partial(Parser, language=self.language)
        return super().add_subparsers(**kwargs)

    def format_help(self):
        return self._localize_usage(super().format_help())

    def format_usage(self):
        return self._localize_usage(super().format_usage())

    def _localize_usage(self, text):
        return text.replace("usage: ", "用法：", 1) if self.language == "zh-CN" else text

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "%s: %s%s\n" % (self.prog, tr(self.language, "error: "), diagnostic(self.language, message)))


def page(source, language):
    """Translate explicitly marked static elements; never inspect evidence DOM."""
    import html
    source = source.replace('<html lang="en">', '<html lang="%s">' % language, 1)
    pattern = r'(<[a-z0-9]+\b[^<>]*\bdata-i18n="([^"]*)"[^<>]*>)[^<>]*(</[a-z0-9]+>)'
    return re.sub(pattern, lambda m: m[1] + html.escape(tr(language, html.unescape(m[2]))) + m[3], source)
