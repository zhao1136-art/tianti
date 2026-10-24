"""CLI 冒烟测试（阶段容忍：M0 stub 与 M6 真实实现都应通过）。"""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from tianti.cli import EXIT_OK, main


class CliTests(unittest.TestCase):
    def test_version_text(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["version"])
        self.assertEqual(code, EXIT_OK)
        text = out.getvalue()
        self.assertIn("0.1.0", text)
        self.assertIn("tianti.trace/1", text)

    def test_version_json(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["version", "--json"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["schema"], "tianti.trace/1")
        self.assertIn("deep", payload["policies"])
        self.assertIn("replay", payload["backends"])

    def test_version_check(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["version", "--check"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("self-test: ok", out.getvalue())

    def test_scan_missing_path_does_not_crash(self):
        """M0 阶段返回 3（未实现），M6 阶段返回 1（样本不存在）；两者都不得抛 traceback。"""
        err = io.StringIO()
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["scan", "Z:\\__tianti_missing__\\nope.bin"])
        self.assertNotEqual(code, EXIT_OK)
        combined = out.getvalue() + err.getvalue()
        self.assertNotIn("Traceback", combined)
        self.assertTrue(combined.strip(), "至少应有错误提示")

    def test_unknown_command_is_argparse_error(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                main(["definitely-not-a-command"])
        self.assertEqual(ctx.exception.code, 2)
