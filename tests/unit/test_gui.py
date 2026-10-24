"""Tk 前端测试：格式化助手 + 用法解析 + 可选窗口冒烟（无显示器自动 skip）。"""

from __future__ import annotations

import unittest
from pathlib import Path

from tianti.api import pipeline
from tianti.gui import format as fmt
from tianti.trace import schema

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "traces"
TRACE = FIXTURES / "golden_ransom_sim.json"


class GuiFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = pipeline.analyze_trace(schema.load(TRACE))

    def test_verdict_labels(self) -> None:
        self.assertEqual(fmt.verdict_label("malicious"), "恶意")
        self.assertEqual(fmt.verdict_label("clean"), "干净")
        self.assertIn("X", fmt.verdict_icon("malicious"))

    def test_score_and_confidence(self) -> None:
        self.assertRegex(fmt.score_text(self.result), r"^\d+\.\d{2}$")
        self.assertTrue(fmt.confidence_text(self.result).endswith("%"))

    def test_capability_rows_sorted_and_complete(self) -> None:
        rows = fmt.capability_rows(self.result)
        self.assertGreater(len(rows), 0)
        self.assertEqual(len(rows), len(self.result.matches))
        namespaces = [row["namespace"] for row in rows]
        self.assertEqual(namespaces, sorted(namespaces))
        self.assertTrue(all(row["name"] for row in rows))

    def test_detector_rows_sorted_by_severity(self) -> None:
        rows = fmt.detector_rows(self.result)
        self.assertGreater(len(rows), 0)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        keys = [order.get(row["severity"], 9) for row in rows]
        self.assertEqual(keys, sorted(keys))

    def test_event_rows_and_line(self) -> None:
        rows = fmt.event_rows(self.result, limit=5)
        self.assertEqual(len(rows), 5)
        line = fmt.event_line(rows[0])
        self.assertIn(rows[0]["id"], line)
        self.assertIn(rows[0]["kind"], line)

    def test_summary_text_has_core_sections(self) -> None:
        text = fmt.summary_text(self.result)
        for key in ("【样本】", "判定", "【评分明细】", "规则命中", "事件统计"):
            self.assertIn(key, text)
        self.assertIn(self.result.sample_name, text)

    def test_json_text_is_valid_json(self) -> None:
        import json

        payload = json.loads(fmt.json_text(self.result))
        self.assertEqual(payload["schema"], "tianti.result/1")
        self.assertEqual(payload["sample"]["name"], self.result.sample_name)

    def test_notes_text_has_analysis_switch(self) -> None:
        text = fmt.notes_text(self.result)
        self.assertIn("【分析开关】", text)

    def test_static_signal_rows_empty_for_replay(self) -> None:
        self.assertEqual(fmt.static_signal_rows(self.result), [])

    def test_human_size(self) -> None:
        self.assertEqual(fmt._human_size(0), "0 B")
        self.assertEqual(fmt._human_size(2048), "2.0 KB")



class BatchSummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ransom = pipeline.analyze_trace(schema.load(FIXTURES / "golden_ransom_sim.json"))
        cls.injection = pipeline.analyze_trace(schema.load(FIXTURES / "golden_injection.json"))
        cls.benign = pipeline.analyze_trace(schema.load(FIXTURES / "golden_benign_installer.json"))

    def test_matrix_rows_sorted_by_score(self) -> None:
        rows = fmt.matrix_rows([self.benign, self.ransom, self.injection])
        self.assertEqual(len(rows), 3)
        scores = [row["score"] for row in rows]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(rows[0]["verdict"], "malicious")
        self.assertTrue(all(row["name"] for row in rows))

    def test_summary_stats(self) -> None:
        stats = fmt.summary_stats([self.ransom, self.injection, self.benign], errors=1, elapsed_s=2.5)
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["malicious"], 2)
        self.assertEqual(stats["suspicious"], 1)
        self.assertEqual(stats["clean"], 0)
        self.assertEqual(stats["errors"], 1)
        self.assertGreater(stats["hits"], 0)
        self.assertIn("TA0003", stats["tactics"])
        line = fmt.stats_line(stats)
        self.assertIn("共 3 个结果", line)
        self.assertIn("失败 1 个文件", line)

    def test_matrix_csv(self) -> None:
        text = fmt.matrix_csv(fmt.matrix_rows([self.ransom]))
        lines = text.strip().splitlines()
        self.assertTrue(lines[0].startswith("name,verdict,score"))
        self.assertIn(self.ransom.sample_name, lines[1])

    def test_empty_summary(self) -> None:
        stats = fmt.summary_stats([])
        self.assertEqual(stats["total"], 0)
        self.assertEqual(fmt.matrix_rows([]), [])


class ForceKillTests(unittest.TestCase):
    def _make_app(self):
        try:
            import tkinter as tk
        except ImportError:  # pragma: no cover
            self.skipTest("tkinter 不可用")
        try:
            root = tk.Tk()
        except tk.TclError:  # pragma: no cover
            self.skipTest("没有可用显示器")
        root.withdraw()
        from tianti.gui.app import TiantiApp

        return root, TiantiApp(root)

    def test_kill_process_tree(self) -> None:
        import subprocess
        import sys

        root, app = self._make_app()
        try:
            proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            self.assertIsNone(proc.poll())
            app._kill_process_tree(proc)
            proc.wait(timeout=10)
            self.assertIsNotNone(proc.poll())
        finally:
            root.destroy()

    def test_force_kill_without_process_returns_false(self) -> None:
        root, app = self._make_app()
        try:
            self.assertFalse(app._force_kill_current())
        finally:
            root.destroy()

class GuiWiringTests(unittest.TestCase):
    def test_cli_parser_has_gui_command(self) -> None:
        from tianti.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["gui", "--smoke"])
        self.assertEqual(args.command, "gui")
        self.assertTrue(args.smoke)

    def test_app_constructs_and_renders_row(self) -> None:
        try:
            import tkinter as tk
        except ImportError:  # pragma: no cover
            self.skipTest("tkinter 不可用")
        try:
            root = tk.Tk()
        except tk.TclError:  # pragma: no cover
            self.skipTest("没有可用显示器")
        root.withdraw()
        try:
            from tianti.gui.app import TiantiApp

            app = TiantiApp(root)
            root.update_idletasks()
            app._add_row(pipeline.analyze_trace(schema.load(TRACE)))
            self.assertEqual(len(app.results), 1)
            self.assertEqual(len(app.tree.get_children()), 1)
            self.assertIn("【样本】", app.summary_text.get("1.0", "end"))
        finally:
            root.destroy()
