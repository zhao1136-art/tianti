"""报告层单元测试：ScanResult JSON round-trip、HTML 渲染、XSS 转义、ATT&CK 矩阵。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tianti.core.errors import ReportError
from tianti.core.verdict import ScoreItem, Verdict
from tianti.detect.base import DetectorHit
from tianti.report import html as report_html
from tianti.report import jsonr, mitre
from tianti.report.base import RESULT_SCHEMA, ScanResult
from tianti.rules.base import RuleMatch

XSS_NAME = '<script>alert("xss")</script>.ps1'
XSS_TARGET = '<img src=x onerror=alert(1)>'


def build_result() -> ScanResult:
    match = RuleMatch(
        name='写入 Run 键实现自启动 <script>bad()</script>',
        namespace="persistence/registry/run-key",
        scope="process",
        instance={"pid": 4120},
        attack=["Persistence::Registry Run Keys / Startup Folder [T1547.001]"],
        evidence={"registry set: HKCU\\...\\Run": ["e00003"]},
        confidence="high",
    )
    hit = DetectorHit(
        detector_id="ransomware_mass_ops",
        name="短时间批量高熵文件改写",
        severity="critical",
        tactic="TA0040",
        technique="T1486",
        score=40.0,
        evidence=["e00004", "e00005"],
        detail="3 个文件在 1s 内被高熵改写",
    )
    verdict = Verdict(
        verdict="malicious",
        score=72.5,
        confidence=0.83,
        tactics=["TA0003", "TA0040"],
        techniques=["T1547.001", "T1486"],
        items=[
            ScoreItem(kind="capability", ref="persistence/registry/run-key", score=10.0, evidence=["e00003"]),
            ScoreItem(kind="detector", ref="ransomware_mass_ops", score=40.0, evidence=["e00004", "e00005"]),
            ScoreItem(
                kind="detector",
                ref="suppressed_detector",
                score=0.0,
                suppressed=True,
                suppress_reason="路径命中白名单",
                evidence=["e00001"],
            ),
        ],
        notes=["规则命中 2 条"],
    )
    events = [
        {
            "id": "e00003",
            "ts": 0.61,
            "pid": 4120,
            "image": "C:/Windows/System32/powershell.exe",
            "category": "registry",
            "action": "set",
            "target": XSS_TARGET,
            "args": {"value": XSS_TARGET},
            "source": "etw:registry",
            "confidence": "high",
        },
        {
            "id": "e00004",
            "ts": 0.9,
            "pid": 4120,
            "category": "file",
            "action": "write",
            "target": "C:/work/report.docx.locked",
            "args": {"entropy": 7.61},
            "source": "etw:file",
            "confidence": "high",
        },
    ]
    return ScanResult(
        sample={
            "name": XSS_NAME,
            "sha256": "a" * 64,
            "size": 2048,
            "type": "script/powershell",
            "origin": "file",
        },
        static={
            "available": True,
            "signals": ["PowerShell 脚本", XSS_TARGET],
            "score": 2.0,
        },
        trace={
            "trace_id": "20261024T103500Z-7f3a9c21",
            "created_at": "2026-10-24T10:35:00+08:00",
            "engine": {"version": "0.1.0", "backend": "replay", "policy": "deep"},
            "sandbox": {
                "host": "WIN10-19045",
                "isolation": ["restricted_token"],
                "limits": {"timeout_s": 20, "mem_mb": 512, "cpu_s": 10, "network": "blocked"},
                "started_at": "2026-10-24T10:35:00+08:00",
                "ended_at": "2026-10-24T10:35:04+08:00",
                "terminated_by": "exited",
            },
            "summary": {
                "processes": 1,
                "file_writes": 3,
                "reg_sets": 1,
                "event_count": 2,
                "truncated": False,
            },
        },
        events=events,
        matches=[match],
        hits=[hit],
        verdict=verdict,
        notes=["备注 <b>粗体</b> 不应被当作 HTML", "静态结果来自模拟测试"],
        extra={
            "thresholds": {"clean_below": 10.0, "malicious_at": 40.0},
            "source_path": "C:/samples/" + XSS_NAME,
        },
    )


class ScanResultTests(unittest.TestCase):
    def test_result_dict_roundtrip(self):
        result = build_result()
        payload = result.to_dict()
        self.assertEqual(payload["schema"], RESULT_SCHEMA)
        restored = ScanResult.from_dict(payload)
        self.assertEqual(restored.to_dict(), payload)
        self.assertEqual(restored.sample_name, XSS_NAME)
        self.assertEqual(restored.verdict.verdict, "malicious")
        self.assertEqual(len(restored.matches), 1)
        self.assertEqual(len(restored.hits), 1)

    def test_jsonr_dumps_loads_and_files(self):
        result = build_result()
        text = jsonr.dumps(result)
        self.assertIn('"schema": "tianti.result/1"', text)
        self.assertIn("</script>.ps1", text)
        self.assertEqual(jsonr.loads(text).to_dict(), result.to_dict())
        with tempfile.TemporaryDirectory() as tmp:
            path = jsonr.save_result(result, Path(tmp) / "nested" / "result.json")
            self.assertTrue(path.exists())
            self.assertEqual(jsonr.load_result(path).to_dict(), result.to_dict())

    def test_bad_schema_rejected(self):
        payload = build_result().to_dict()
        payload["schema"] = "tianti.result/999"
        with self.assertRaises(ReportError):
            ScanResult.from_dict(payload)
        with self.assertRaises(ReportError):
            jsonr.loads("not json")

    def test_result_filename_safe(self):
        name = jsonr.result_filename(XSS_NAME)
        self.assertTrue(name.endswith(".result.json"))
        for char in '<>:"/\\|?*':
            self.assertNotIn(char, name)


class HtmlReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = build_result()
        self.html = report_html.render_html(self.result)

    def test_renders_single_file_report(self):
        self.assertTrue(self.html.startswith("<!DOCTYPE html>"))
        self.assertIn('lang="zh-CN"', self.html)
        self.assertIn("<style>", self.html)
        for marker in [
            "天体引擎",
            "结论 VERDICT",
            "文件信息",
            "静态信号",
            "沙箱执行摘要",
            "行为时间线",
            "capa 能力识别",
            "危险行为",
            "评分明细",
            "战术矩阵",
            "免责声明",
            "观测保真度",
        ]:
            self.assertIn(marker, self.html)
        self.assertIn("恶意", self.html)
        self.assertIn("72.5", self.html)

    def test_xss_payloads_are_escaped(self):
        self.assertNotIn(XSS_NAME, self.html)
        self.assertNotIn("<script>", self.html)
        self.assertNotIn("<img", self.html)
        self.assertNotIn("<b>粗体</b>", self.html)
        self.assertIn("&lt;script&gt;", self.html)
        self.assertIn("&lt;img", self.html)

    def test_no_external_resources(self):
        for marker in ("<script", "<link", "<img", "http://", "https://"):
            self.assertNotIn(marker, self.html)

    def test_evidence_links_to_timeline(self):
        self.assertIn('id="ev-e00003"', self.html)
        self.assertIn('href="#ev-e00003"', self.html)

    def test_static_signals_are_rendered_as_dicts(self):
        result = build_result()
        result.static = {
            "available": True,
            "signals": [
                {
                    "id": "strings.ransom_note",
                    "severity": "high",
                    "detail": "发现勒索提示文本",
                    "score": 10.0,
                },
                {
                    "id": "strings.ip_address",
                    "severity": "low",
                    "detail": "发现裸 IP 地址",
                    "score": 2.0,
                },
            ],
            "max_severity": "high",
            "signal_count": 2,
        }
        rendered = report_html.render_html(result)
        self.assertIn("strings.ransom_note", rendered)
        self.assertIn("发现勒索提示文本", rendered)
        self.assertIn("badge high", rendered)
        self.assertNotIn("{&#x27;id&#x27;", rendered)
        self.assertNotIn("{'id'", rendered)

    def test_empty_result_renders_clean_report(self):
        empty = ScanResult()
        rendered = report_html.render_html(empty)
        self.assertIn("干净", rendered)
        self.assertIn("未命中", rendered)
        self.assertNotIn("<script", rendered)

    def test_save_html_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = report_html.save_html(self.result, Path(tmp) / "out" / "report.html")
            self.assertTrue(path.exists())
            text = path.read_text(encoding="utf-8")
            self.assertEqual(text, self.html)


class MitreTests(unittest.TestCase):
    def test_tactic_and_technique_lookup(self):
        self.assertEqual(mitre.tactic_for_technique("T1547.001"), "TA0003")
        self.assertEqual(mitre.tactic_for_technique("t1486"), "TA0040")
        self.assertEqual(mitre.tactic_name("TA0003"), "持久化")
        self.assertEqual(mitre.tactic_name("TA0003", zh=False), "Persistence")
        self.assertIn("加密", mitre.technique_name("T1486"))
        self.assertIsNone(mitre.tactic_for_technique("T9999"))

    def test_build_matrix(self):
        matrix = mitre.build_matrix(
            ["TA0003"],
            ["T1547.001", "T1486", "T9999"],
        )
        columns = {column["id"]: column for column in matrix["columns"]}
        self.assertEqual(len(columns), len(mitre.TACTICS))
        self.assertTrue(columns["TA0003"]["hit"])
        self.assertTrue(columns["TA0040"]["hit"])
        self.assertFalse(columns["TA0001"]["hit"])
        self.assertTrue(any(tech["id"] == "T1486" for tech in columns["TA0040"]["techniques"]))
        self.assertEqual([item["id"] for item in matrix["unmapped"]], ["T9999"])


if __name__ == "__main__":
    unittest.main()