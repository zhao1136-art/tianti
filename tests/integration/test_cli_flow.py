"""CLI 端到端流程 + 本地 API 冒烟测试（M6 验收）。"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from tianti.api.httpd import create_server
from tianti.cli import build_parser, main
from tianti.report.base import RESULT_SCHEMA

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "traces" / "golden_ransom_sim.json"
VERDICTS = ("clean", "suspicious", "malicious")
SUBCOMMANDS = {"version", "trace", "replay", "rules", "detectors", "report", "scan", "serve"}


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliReplayTests(unittest.TestCase):
    def test_replay_json_end_to_end(self):
        code, out, err = run_cli(["replay", str(GOLDEN)])
        self.assertEqual(code, 0, err)
        self.assertNotIn("Traceback", err)
        payload = json.loads(out)
        self.assertEqual(payload["schema"], RESULT_SCHEMA)
        self.assertIn(payload["verdict"]["verdict"], VERDICTS)
        self.assertIsInstance(payload["verdict"]["score"], (int, float))
        self.assertIsInstance(payload["verdict"]["confidence"], (int, float))
        self.assertEqual(payload["sample"]["name"], "demo_ransom.ps1")
        self.assertEqual(payload["trace"]["trace_id"], "20261024T103500Z-7f3a9c21")
        self.assertIsInstance(payload["matches"], list)
        self.assertIsInstance(payload["hits"], list)
        self.assertTrue(payload["events"], "replay 应保留事件以支撑证据链")
        self.assertIn("notes", payload)
        self.assertIn("thresholds", payload["extra"])

    def test_replay_summary_format(self):
        code, out, err = run_cli(["replay", str(GOLDEN), "--format", "summary"])
        self.assertEqual(code, 0, err)
        self.assertIn("结论:", out)
        self.assertIn("demo_ransom.ps1", out)
        self.assertTrue(any(verdict in out for verdict in VERDICTS), out)

    def test_replay_writes_result_file(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "result.json"
            code, out, err = run_cli(["replay", str(GOLDEN), "--out", str(path)])
            self.assertEqual(code, 0, err)
            self.assertTrue(path.exists())
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], RESULT_SCHEMA)
            self.assertIn(payload["verdict"]["verdict"], VERDICTS)

    def test_report_generates_html(self):
        with TemporaryDirectory() as tmp:
            result_path = Path(tmp) / "result.json"
            html_path = Path(tmp) / "report.html"
            code, _, err = run_cli(["replay", str(GOLDEN), "--out", str(result_path)])
            self.assertEqual(code, 0, err)
            code, out, err = run_cli(["report", str(result_path), "--out", str(html_path)])
            self.assertEqual(code, 0, err)
            self.assertTrue(html_path.exists())
            text = html_path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("<!DOCTYPE html>"))
            self.assertIn("危险行为", text)
            self.assertIn("评分明细", text)
            self.assertNotIn("<script", text)
            self.assertNotIn("http://", text)
            self.assertIn(str(html_path), out)

    def test_scan_trace_produces_json_and_html(self):
        with TemporaryDirectory() as tmp:
            code, out, err = run_cli(["scan", str(GOLDEN), "--out", tmp, "--format", "both"])
            self.assertEqual(code, 0, err)
            files = [path.name for path in Path(tmp).iterdir()]
            self.assertTrue(any(name.endswith(".result.json") for name in files), files)
            self.assertTrue(any(name.endswith(".report.html") for name in files), files)
            self.assertTrue(any(verdict in out for verdict in VERDICTS), out)

    def test_scan_directory_mode_serial_and_unique_filenames(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "in"
            (source / "a").mkdir(parents=True)
            (source / "b").mkdir()
            shutil.copyfile(GOLDEN, source / "a" / "same.json")
            shutil.copyfile(GOLDEN, source / "b" / "same.json")
            out_dir = root / "out"
            code, out, err = run_cli(["scan", str(source), "--out", str(out_dir), "--format", "both"])
            self.assertEqual(code, 0, err)
            names = sorted(path.name for path in out_dir.iterdir())
            self.assertEqual(len(names), 4, names)
            self.assertEqual(len(set(names)), 4, f"目录模式输出文件名冲突: {names}")
            self.assertEqual(sum(name.endswith(".result.json") for name in names), 2, names)
            self.assertEqual(sum(name.endswith(".report.html") for name in names), 2, names)
            self.assertIn("[1/2]", out)
            self.assertIn("[2/2]", out)

    def test_directory_scan_cap_is_200(self):
        import tianti.cli as cli

        self.assertEqual(cli.MAX_DIR_FILES, 200)


class CliSurfaceTests(unittest.TestCase):
    def test_version_still_works(self):
        code, out, _ = run_cli(["version"])
        self.assertEqual(code, 0)
        self.assertIn("0.1.0", out)
        self.assertIn("tianti.trace/1", out)
        code, out, _ = run_cli(["version", "--check"])
        self.assertEqual(code, 0)
        self.assertIn("self-test: ok", out)

    def test_no_subcommand_prints_help(self):
        code, out, _ = run_cli([])
        self.assertEqual(code, 0)
        self.assertIn("usage:", out)

    def test_every_subcommand_help(self):
        for command in sorted(SUBCOMMANDS):
            with self.subTest(command=command):
                with self.assertRaises(SystemExit) as caught:
                    run_cli([command, "--help"])
                self.assertEqual(caught.exception.code, 0)

    def test_unknown_argument_exit_code_two(self):
        with self.assertRaises(SystemExit) as caught:
            run_cli(["version", "--definitely-not-an-option"])
        self.assertEqual(caught.exception.code, 2)

    def test_stub_commands_gone(self):
        import tianti.cli as cli

        self.assertFalse(hasattr(cli, "cmd_stub"))
        parser = build_parser()
        sub_actions = [action for action in parser._actions if isinstance(action, argparse._SubParsersAction)]
        self.assertEqual(len(sub_actions), 1)
        choices = sub_actions[0].choices
        self.assertEqual(set(choices), SUBCOMMANDS)
        for name, subparser in choices.items():
            func = subparser.get_default("func")
            self.assertIsNotNone(func, f"{name} 未绑定命令函数")
            self.assertEqual(func.__name__, "cmd_" + name)

    def test_missing_sample_is_friendly_error(self):
        code, _, err = run_cli(["scan", "definitely-missing-sample-xyz.bin"])
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)
        self.assertIn("tianti.sample", err)

    def test_missing_trace_for_trace_command(self):
        code, _, err = run_cli(["trace", "definitely-missing-sample-xyz.bin"])
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)
        self.assertIn("tianti.sample", err)

    def test_rule_and_detector_listing(self):
        code, out, err = run_cli(["rules", "list"])
        self.assertEqual(code, 0, err)
        self.assertIn("规则", out)
        code, out, err = run_cli(["detectors", "list"])
        self.assertEqual(code, 0, err)
        self.assertIn("检测器", out)


class ApiSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = create_server(port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[0], self.server.server_address[1]
        self.base = "http://" + str(host) + ":" + str(port)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _get(self, path: str) -> tuple[int, dict]:
        with urllib.request.urlopen(self.base + path, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def _post(self, path: str, payload: dict) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def test_health_rules_metrics(self):
        status, payload = self._get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result_schema"], RESULT_SCHEMA)
        status, rules = self._get("/rules")
        self.assertEqual(status, 200)
        self.assertIn("available", rules)
        self.assertIn("count", rules)
        status, metrics = self._get("/metrics")
        self.assertEqual(status, 200)
        self.assertIn("requests", metrics)
        self.assertIn("tasks", metrics)

    def test_scan_trace_then_fetch_result(self):
        status, payload = self._post("/scan", {"path": str(GOLDEN)})
        self.assertEqual(status, 202)
        task_id = payload["task_id"]
        deadline = time.time() + 20
        body: dict = {}
        while time.time() < deadline:
            status, body = self._get("/result/" + task_id)
            if status == 200:
                break
            self.assertEqual(status, 202, body)
            time.sleep(0.05)
        else:
            self.fail("API 扫描超时")
        self.assertEqual(body["status"], "done")
        result = body["result"]
        self.assertEqual(result["schema"], RESULT_SCHEMA)
        self.assertIn(result["verdict"]["verdict"], VERDICTS)
        self.assertEqual(result["trace"]["trace_id"], "20261024T103500Z-7f3a9c21")

    def test_api_errors_are_json(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self._get("/result/does-not-exist")
        self.assertEqual(caught.exception.code, 404)
        payload = json.loads(caught.exception.read().decode("utf-8"))
        self.assertEqual(payload["error"], "tianti.api.task_not_found")

        with self.assertRaises(urllib.error.HTTPError) as caught:
            self._post("/scan", {"path": "definitely-missing-sample-xyz.bin"})
        self.assertEqual(caught.exception.code, 404)
        payload = json.loads(caught.exception.read().decode("utf-8"))
        self.assertTrue("错误" in payload["message"] or "不存在" in payload["message"], payload)

        with self.assertRaises(urllib.error.HTTPError) as caught:
            self._post("/scan", {"nope": 1})
        self.assertEqual(caught.exception.code, 400)
        payload = json.loads(caught.exception.read().decode("utf-8"))
        self.assertEqual(payload["error"], "tianti.api.bad_request")

    def test_non_loopback_bind_refused(self):
        with self.assertRaises(ValueError):
            create_server("0.0.0.0", 0)


if __name__ == "__main__":
    unittest.main()
