"""CLI 冒烟测试（M0 只需 version 可用）。"""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from tianti.cli import EXIT_NOT_IMPLEMENTED, EXIT_OK, main


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
        self.assertIn("containment", payload["backends"])

    def test_version_check(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["version", "--check"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("self-test: ok", out.getvalue())

    def test_stub_command(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main(["scan", "samples"])
        self.assertEqual(code, EXIT_NOT_IMPLEMENTED)
        self.assertIn("尚未实现", err.getvalue())
