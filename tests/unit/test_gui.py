"""Tk 前端测试：格式化助手 + 用法解析 + 可选窗口冒烟（无显示器自动 skip）。"""

from __future__ import annotations

import unittest
from pathlib import Path

from tianti.api import pipeline
from tianti.gui import format as fmt
from tianti.trace import schema

TRACE = Path(__file__).resolve().parents[1] / "fixtures" / "traces" / "golden_ransom_sim.json"


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
