"""Offline presentation checks; fixture responses are not live Jev results."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import judge
import rules
import workbench
from localization import CATALOG, Parser, cli_language, diagnostic, request_language
from test_workbench import make_fixture, review_all, approve

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("llm_judge_language_test", ROOT / "demo/llm-judge/judge.py")
llm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(llm)


class LanguageTests(unittest.TestCase):
    def test_language_priority_quality_order_and_fallback(self):
        for path, headers, expected in [
            ("/", {}, ("en", False)),
            ("/", {"Accept-Language": "zh-TW,en;q=0.5"}, ("zh-CN", False)),
            ("/", {"Accept-Language": "zh-CN;q=0.5,en;q=0.9"}, ("en", False)),
            ("/", {"Accept-Language": "ja,zh;q=0,en;q=0.2"}, ("en", False)),
            ("/", {"Accept-Language": "fr,de;q=0.5"}, ("en", False)),
            ("/", {"Accept-Language": "en", "Cookie": "agentprov_language=zh-CN"}, ("zh-CN", False)),
            ("/?lang=en", {"Cookie": "agentprov_language=zh-CN", "Accept-Language": "zh"}, ("en", True)),
            ("/?lang=invalid", {"Cookie": "agentprov_language=zh-CN"}, ("zh-CN", False)),
        ]:
            with self.subTest(path=path, headers=headers):
                self.assertEqual(request_language(path, headers), expected)

    def test_cli_help_errors_and_flags_do_not_start_evaluation(self):
        for script, subcommand in [("llm-judge/judge.py", "judge"), ("jev-judge/judge.py", "prepare"), ("jev-judge/workbench.py", "capture")]:
            executable = str(ROOT / "demo" / script)
            for args in (["--help", "--lang", "zh-CN"], ["--lang", "zh-CN", subcommand, "--help"], [subcommand, "--help", "--lang=zh-CN"]):
                result = subprocess.run([sys.executable, executable, *args], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("显示帮助并退出", result.stdout)
                self.assertNotIn("show this help", result.stdout)
            result = subprocess.run([sys.executable, executable, subcommand, "--lang", "zh-CN"], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn("缺少必填参数", result.stderr)
            english = subprocess.run([sys.executable, executable, "--help"], capture_output=True, text=True, timeout=10)
            self.assertIn("show this help", english.stdout)
        self.assertEqual(cli_language(["--", "--lang", "zh-CN"]), "en")
        self.assertIn("模型调用次数上限", subprocess.check_output([sys.executable, str(ROOT / "demo/llm-judge/judge.py"), "judge", "--help", "--lang", "zh-CN"], text=True))

    def test_known_diagnostics_preserve_opaque_values_and_unknown_text(self):
        self.assertEqual(diagnostic("zh-CN", "Unknown choice: /tmp/Candidate approved"), "未知选项：/tmp/Candidate approved")
        self.assertEqual(diagnostic("zh-CN", "Provider returned HTTP 429; stopped, not classified as safe"), "服务商返回 HTTP 429；评估已停止，未将结果判定为安全")
        self.assertEqual(diagnostic("zh-CN", "external text Unknown choice: custom"), "external text Unknown choice: custom")
        self.assertEqual(diagnostic("en", "Unknown case"), "Unknown case")
        self.assertEqual(diagnostic("zh-CN", "argument --max-calls: invalid int value: 'abc'"), "参数 --max-calls：整数值无效：'abc'")

    def test_llm_chinese_display_does_not_change_exported_verdict_or_signals(self):
        bundle = {"risks": {"risks": [{"reason": "Candidate approved", "severity": "high", "event_id": "original-id", "type": "example"}]}}
        with tempfile.TemporaryDirectory() as directory:
            results = {}
            for language in ("en", "zh-CN"):
                paths = {key: str(Path(directory) / (language + name)) for key, name in (("verdict_out", "-verdict.json"), ("signals_out", "-signals.json"), ("tls_out", "-tls.jsonl"))}
                args = SimpleNamespace(lang=language, offline=True, agentprov="not-executed", data_dir=directory, run="run-original", payload_chars=400, budget_chars=150000, max_calls=16, **paths)
                stdout = io.StringIO()
                with patch.object(llm, "gather", return_value=bundle), patch.object(llm, "trajectory_lines", return_value=["opaque original event"]), patch.object(llm, "header_text", return_value="original header"), patch.object(llm.LLM, "call", side_effect=AssertionError("provider must not be called")), contextlib.redirect_stdout(stdout):
                    llm.cmd_judge(args)
                results[language] = [Path(path).read_bytes() for path in paths.values()]
                self.assertIn("结论=恶意" if language == "zh-CN" else "verdict=malicious", stdout.getvalue())
            self.assertEqual(results["en"], results["zh-CN"])
            self.assertIn(b"Candidate approved", results["en"][0])

    def test_chinese_capture_verification_failure_never_calls_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(lang="zh-CN", send_raw=True, data_dir=Path(directory) / "new-study",
                                   key_file=Path("not-read"), provider="typesafe", agentprov=Path("not-run"),
                                   bundle=Path("not-read"), pub_key=Path("not-read"))
            stdout = io.StringIO()
            with patch.object(judge, "make_cases", return_value={"run_id": "fixture"}), patch.object(judge, "load_key", return_value="unused-test-key"), patch.object(workbench, "run_cli", return_value={"status": "error", "error_count": 1}), patch.object(judge, "evaluate") as evaluate, contextlib.redirect_stdout(stdout):
                with self.assertRaisesRegex(ValueError, "Graph verification failed"):
                    workbench.capture(args)
                evaluate.assert_not_called()
            self.assertIn("正在校验签名证据包和证据图", stdout.getvalue())

    def test_catalog_covers_authored_rules_without_mutating_them(self):
        profiles = rules.profiles()
        before = judge.encode(profiles)
        for profile in profiles.values():
            self.assertIn(profile["description"], CATALOG)
            for question in profile["questions"].values():
                self.assertIn(question["instructions"], CATALOG)
                for criterion in question["criteria"].values():
                    self.assertIn(criterion, CATALOG)
        self.assertEqual(judge.encode(profiles), before)

    def test_http_language_selection_does_not_change_artifacts_or_api(self):
        with tempfile.TemporaryDirectory() as directory:
            study = make_fixture(Path(directory))
            review_all(study)
            approve(study)
            before = {p: p.read_bytes() for p in Path(directory).rglob("*.json")}
            server = workbench.make_server(study, 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = "http://127.0.0.1:%d" % server.server_port
            def get(path, **headers):
                with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers), timeout=5) as response:
                    return response.read(), response.headers
            try:
                english, headers = get("/", **{"Accept-Language": "fr"})
                self.assertIn(b'<html lang="en">', english)
                self.assertIsNone(headers.get("Set-Cookie"))
                chinese, headers = get("/?lang=zh-CN", **{"Accept-Language": "en"})
                self.assertIn('证据与评审'.encode(), chinese)
                self.assertEqual(headers.get("Content-Language"), "zh-CN")
                self.assertIn("HttpOnly", headers.get("Set-Cookie"))
                self.assertIn("script-src 'self'", headers.get("Content-Security-Policy"))
                for path in ("/api/state", "/api/signals", "/api/artifact/v1/runtime_evidence/request.json", "/api/artifact/v2/runtime_evidence/response.json"):
                    en, _ = get(path, Cookie="agentprov_language=en")
                    zh, _ = get(path, Cookie="agentprov_language=zh-CN")
                    self.assertEqual(en, zh, path)
                catalog, _ = get("/i18n.json")
                self.assertEqual(json.loads(catalog), CATALOG)
                with self.assertRaises(urllib.error.HTTPError) as error:
                    get("/i18n.json", Origin="http://untrusted.example")
                self.assertEqual(error.exception.code, 403)
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=5)
            self.assertEqual(before, {p: p.read_bytes() for p in Path(directory).rglob("*.json")})


if __name__ == "__main__":
    unittest.main()
