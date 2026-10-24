"""report2trace 转换器测试：CAPE/capa 报告 -> tianti.trace/1 契约。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tianti.api import pipeline
from tianti.core.errors import TraceError
from tianti.trace import schema
from tools.report2trace import convert_file, convert_report, load_report


def build_cape_report() -> dict:
    """最小合成 CAPE 报告：AmsiScanBuffer / VirtualAllocEx / WriteProcessMemory /
    RegSetValueExW / CreateFileW / WriteFile / connect。"""
    return {
        "info": {"machine": {"name": "WIN10-LAB"}},
        "target": {
            "file": {
                "name": "demo_ransom.exe",
                "size": 12345,
                "type": "PE32",
                "sha256": "a" * 64,
            }
        },
        "behavior": {
            "processes": [
                {
                    "process_id": 4120,
                    "parent_id": 4100,
                    "process_name": "C:/Windows/System32/powershell.exe",
                    "command_line": "powershell.exe -NoProfile -File demo.ps1",
                    "calls": [
                        {
                            "api": "AmsiScanBuffer",
                            "category": "security",
                            "arguments": {"buffer": "payload", "length": 128},
                            "return_value": 0,
                            "timestamp": 1700000000.10,
                            "thread_id": 4124,
                        },
                        {
                            "api": "VirtualAllocEx",
                            "category": "memory",
                            "arguments": {"process_handle": 1234, "size": 4096, "protect": "RWX"},
                            "return_value": 123456,
                            "timestamp": 1700000000.20,
                            "thread_id": 4124,
                        },
                        {
                            "api": "WriteProcessMemory",
                            "category": "memory",
                            "arguments": {"process_handle": 1234, "buffer": "payload"},
                            "return_value": 1,
                            "timestamp": 1700000000.30,
                            "thread_id": 4124,
                        },
                        {
                            "api": "RegSetValueExW",
                            "category": "registry",
                            "arguments": {
                                "key_name": "HKCU/Software/Microsoft/Windows/CurrentVersion/Run",
                                "value_name": "Updater",
                                "data": "C:/Users/Public/a.exe",
                            },
                            "return_value": 0,
                            "timestamp": 1700000000.40,
                            "thread_id": 4124,
                        },
                        {
                            "api": "CreateFileW",
                            "category": "file",
                            "arguments": {
                                "file_name": "C:/Users/Public/a.txt",
                                "desired_access": "GENERIC_WRITE",
                            },
                            "return_value": 8,
                            "timestamp": 1700000000.50,
                            "thread_id": 4124,
                        },
                        {
                            "api": "WriteFile",
                            "category": "file",
                            "arguments": {"file_name": "C:/Users/Public/a.txt", "size": 64},
                            "return_value": 1,
                            "timestamp": 1700000000.60,
                            "thread_id": 4124,
                        },
                        {
                            "api": "connect",
                            "category": "network",
                            "arguments": {"ip": "45.148.10.82", "port": 8443},
                            "return_value": 0,
                            "timestamp": 1700000000.70,
                            "thread_id": 4124,
                        },
                    ],
                }
            ]
        },
    }


def build_capa_report() -> dict:
    """capa 官方动态报告的 calls[] 风格（无 processes 包装）。"""
    return {
        "target": {"name": "sample.bin", "type": "pe64"},
        "calls": [
            {
                "api": "RegSetValueExW",
                "args": [{"name": "key_name", "value": "HKCU/Software/Test"}, {"name": "value_name", "value": "x"}],
                "timestamp": 12.5,
                "thread": {"process_id": 900, "thread_id": 901},
            },
            {
                "api": "CreateProcessW",
                "args": {"application_name": "C:/Windows/System32/cmd.exe", "command_line": "cmd.exe /c whoami"},
                "timestamp": 13.0,
            },
        ],
    }


class ConvertReportTests(unittest.TestCase):
    def test_cape_report_converts_to_valid_trace(self):
        trace = convert_report(build_cape_report(), source_name="cape_report.json")
        payload = trace.to_dict()
        self.assertEqual(schema.validate_payload(payload), [])
        self.assertEqual(trace.sample.name, "demo_ransom.exe")
        self.assertEqual(trace.sample.sha256, "a" * 64)
        categories = {event.category for event in trace.events}
        for expected in ("api", "file", "registry", "network", "process", "memory"):
            self.assertIn(expected, categories)

        api_events = [event for event in trace.events if event.category == "api"]
        api_names = [event.args.get("api") for event in api_events]
        for expected in ("AmsiScanBuffer", "VirtualAllocEx", "WriteProcessMemory", "RegSetValueExW", "CreateFileW"):
            self.assertIn(expected, api_names)
        self.assertTrue(all(event.action == "call" for event in api_events))
        self.assertTrue(all(event.pid == 4120 for event in api_events))
        self.assertTrue(all(event.tid == 4124 for event in api_events))
        self.assertTrue(all("api" in event.args for event in api_events))

        self.assertGreaterEqual(trace.summary.file_writes, 1)
        self.assertGreaterEqual(trace.summary.reg_sets, 1)
        self.assertGreaterEqual(trace.summary.net_connects, 1)
        self.assertEqual(trace.engine.backend, "replay")
        self.assertIn("report2trace", trace.engine.policy)

    def test_capa_calls_style_is_supported(self):
        trace = convert_report(build_capa_report(), source_name="capa.json")
        self.assertEqual(schema.validate_payload(trace.to_dict()), [])
        api_names = [event.args.get("api") for event in trace.events if event.category == "api"]
        self.assertIn("RegSetValueExW", api_names)
        self.assertIn("CreateProcessW", api_names)
        self.assertTrue(any(event.category == "registry" for event in trace.events))
        self.assertTrue(any(event.category == "process" for event in trace.events))

    def test_missing_sha256_generates_valid_digest(self):
        report = build_cape_report()
        report["target"]["file"]["sha256"] = "not-a-hash"
        trace = convert_report(report)
        self.assertRegex(trace.sample.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(schema.validate_payload(trace.to_dict()), [])

    def test_invalid_report_raises(self):
        with self.assertRaises(TraceError):
            convert_report({})
        with self.assertRaises(TraceError):
            convert_report({"calls": "not-a-list", "processes": []})

    def test_convert_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "cape.json"
            report_path.write_text(json.dumps(build_cape_report()), encoding="utf-8")
            out = Path(tmp) / "trace.json"
            path = convert_file(report_path, out)
            self.assertTrue(path.exists())
            trace = schema.load(path)
            self.assertEqual(trace.sample.name, "demo_ransom.exe")
            self.assertTrue(trace.events)
            self.assertEqual(load_report(report_path)["target"]["file"]["name"], "demo_ransom.exe")

    def test_upstream_rules_can_match_converted_api_trace(self):
        root = Path(__file__).resolve().parents[2]
        upstream = root / "rules" / "upstream"
        if not upstream.is_dir() or not any(upstream.rglob("*.yml")):
            self.skipTest("rules/upstream 未就绪（等待 rules 完成上游 capa 规则导入）")
        trace = convert_report(build_cape_report(), source_name="cape_report.json")
        matches, note = pipeline.run_rules(trace, include_upstream=True)
        if note:
            self.skipTest(f"上游规则尚未接通: {note}")
        self.assertTrue(matches, "上游规则应至少命中一条 api 级规则")
        api_ids = {event.id for event in trace.events if event.category == "api"}
        matched_ids = {
            event_id
            for match in matches
            for ids in match.evidence.values()
            for event_id in ids
        }
        self.assertTrue(matched_ids & api_ids, f"命中证据未引用 api 事件: {matched_ids & api_ids}")


if __name__ == "__main__":
    unittest.main()
