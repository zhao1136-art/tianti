# -*- coding: utf-8 -*-
"""M5 单元测试：检测器 DSL 算子 / 聚合 / 窗口 / 时序 / 抑制 / 加载 / 异常隔离。

说明：检测器正反例使用合成 Trace；直接匹配进程/文件/注册表事件，
不保存任何真实恶意命令，测试文件也尽量降低工具链特征密度。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tianti.core.errors import DetectorError
from tianti.detect.base import SEVERITIES, DetectorHit
from tianti.detect.detectors import (
    clear_python_detectors,
    load_detectors,
    python_detector,
    run_detectors,
    run_detectors_detailed,
)
from tianti.detect.dsl import compile_detector, compile_node
from tianti.detect.suppress import Suppressor, TrustStore, compile_rule, sample_image_for_trace
from tianti.trace.schema import Event, EngineInfo, SampleInfo, SandboxInfo, Trace, TraceSummary

SHA = "a" * 64
TRACE_ID = "20261024T103500Z-7f3a9c21"


def spec(ts: float, category: str, action: str, **kwargs) -> dict:
    payload = {"ts": float(ts), "category": category, "action": action}
    payload.update(kwargs)
    return payload


def make_trace(specs: list[dict]) -> Trace:
    events: list[Event] = []
    for item in specs:
        events.append(
            Event(
                id="pending",
                ts=float(item["ts"]),
                category=str(item["category"]),
                action=str(item["action"]),
                pid=item.get("pid", 100),
                ppid=item.get("ppid"),
                image=item.get("image"),
                target=item.get("target"),
                args=dict(item.get("args") or {}),
                source=str(item.get("source", "etw:test")),
                confidence=str(item.get("confidence", "high")),
            )
        )
    events.sort(key=lambda event: event.ts)
    for index, event in enumerate(events, 1):
        event.id = f"e{index:05d}"
    trace = Trace(
        trace_id=TRACE_ID,
        sample=SampleInfo(name="synthetic.bin", sha256=SHA, size=1024, type="script/powershell"),
        engine=EngineInfo(version="0.1.0", backend="replay", policy="deep"),
        sandbox=SandboxInfo(isolation=["unit-test"]),
        events=events,
        summary=TraceSummary.from_events(events),
        created_at="2026-10-24T10:35:00+08:00",
    )
    trace.validate()
    return trace


def detector_payload(detector_id: str, match: dict, **kwargs) -> dict:
    payload = {"detector": detector_id, "severity": "high", "score": 10, "match": match}
    payload.update(kwargs)
    return payload


class TestDetectorLoading(unittest.TestCase):
    def test_all_detectors_load_without_errors(self) -> None:
        loaded = load_detectors()
        self.assertGreaterEqual(len(loaded.detectors), 26)
        self.assertEqual(loaded.errors, [])
        ids = [detector.id for detector in loaded.detectors]
        self.assertEqual(len(ids), len(set(ids)))
        for detector in loaded.detectors:
            spec_obj = detector.spec
            self.assertIn(spec_obj.severity, SEVERITIES)
            self.assertGreater(spec_obj.score, 0)
            self.assertRegex(spec_obj.tactic, r"^TA\d{4}$")
            self.assertRegex(spec_obj.technique, r"^T\d{4}(?:\.\d{3})?$")
            self.assertTrue(spec_obj.name)

    def test_yaml_covers_required_tactics(self) -> None:
        loaded = load_detectors()
        tactics = {detector.spec.tactic for detector in loaded.detectors}
        for tactic in ("TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0040"):
            self.assertIn(tactic, tactics)

    def test_unknown_fields_rejected(self) -> None:
        with self.assertRaises(DetectorError):
            compile_detector(detector_payload("bad_top", {"category": "file"}, mystery=1))
        with self.assertRaises(DetectorError):
            compile_detector(detector_payload("bad_leaf", {"category": "file", "mystery": True}))
        with self.assertRaises(DetectorError):
            compile_detector({"detector": "bad_id!", "match": {"category": "file"}})

    def test_invalid_yaml_file_is_isolated_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "broken.yml").write_text(
                "detector: broken\nmatch:\n  all:\n    - category: file\n   action: write\n",
                encoding="utf-8",
            )
            loaded = load_detectors(tmp)
            self.assertEqual(loaded.detectors, [])
            self.assertTrue(loaded.errors)
            self.assertIn("broken.yml", loaded.errors[0])


class TestDslOperators(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = make_trace(
            [
                spec(0.1, "process", "create", target=r"C:\Users\Public\demo.exe", image=r"C:\Windows\System32\cmd.exe"),
                spec(0.2, "registry", "set", target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x"),
                spec(0.3, "file", "write", target=r"C:\Windows\System32\drivers\etc\hosts"),
            ]
        )

    def test_leaf_category_action_target(self) -> None:
        node = compile_node({"category": "registry", "action": "set", "target": "*CurrentVersion\\Run*"})
        events = node.match(self.trace.events)
        self.assertIsNotNone(events)
        self.assertEqual([event.id for event in events], ["e00002"])

        node = compile_node({"category": "file", "action": ["write"], "target": "*\\drivers\\etc\\hosts"})
        self.assertIsNotNone(node.match(self.trace.events))

    def test_case_insensitive_glob(self) -> None:
        node = compile_node({"target": "*DEMO.EXE"})
        self.assertIsNotNone(node.match(self.trace.events))

    def test_all_any_not(self) -> None:
        node = compile_node(
            {
                "all": [
                    {"category": "process", "action": "create"},
                    {"any": [{"target": "*\\cmd.exe"}, {"target": "*\\demo.exe"}]},
                    {"not": {"target": "*\\blocked.exe"}},
                ]
            }
        )
        events = node.match(self.trace.events)
        self.assertIsNotNone(events)
        self.assertEqual([event.id for event in events], ["e00001"])

        blocked = compile_node({"all": [{"category": "process"}, {"not": {"target": "*DEMO.EXE"}}]})
        self.assertIsNone(blocked.match(self.trace.events))

    def test_any_operator(self) -> None:
        node = compile_node({"any": [{"category": "registry"}, {"category": "file"}]})
        events = node.match(self.trace.events)
        self.assertIsNotNone(events)
        self.assertEqual([event.id for event in events], ["e00002", "e00003"])

    def test_regex_arg_and_numeric_leaf(self) -> None:
        trace = make_trace(
            [
                spec(0.1, "file", "write", target="C:\\a.locked", args={"size": 9000, "entropy": 7.8}),
                spec(0.2, "file", "write", target="C:\\b.txt", args={"size": 1, "entropy": 3.0}),
            ]
        )
        self.assertIsNotNone(compile_node({"target_regex": r"\.lock(ed)?$"}).match(trace.events))
        self.assertIsNotNone(compile_node({"file_ext_in": [".locked"]}).match(trace.events))
        self.assertIsNotNone(compile_node({"entropy_gt": 7.2, "size_gte": 4096}).match(trace.events))
        self.assertIsNone(compile_node({"entropy_gt": 7.9}).match(trace.events))


class TestAggregateWindowSequence(unittest.TestCase):
    def test_aggregate_distinct_count(self) -> None:
        node = compile_node(
            {
                "aggregate": {
                    "distinct": ["target"],
                    "count": ">= 20",
                    "of": {"category": "file", "action": "write"},
                }
            }
        )
        nineteen = make_trace(
            [spec(0.01 * index, "file", "write", target=f"C:\\data\\f{index}.locked") for index in range(19)]
        )
        twenty = make_trace(
            [spec(0.01 * index, "file", "write", target=f"C:\\data\\f{index}.locked") for index in range(20)]
        )
        self.assertIsNone(node.match(nineteen.events))
        self.assertIsNotNone(node.match(twenty.events))

    def test_aggregate_duplicate_targets_not_counted(self) -> None:
        node = compile_node({"aggregate": {"distinct": ["target"], "count": ">= 3", "of": {"category": "file"}}})
        trace = make_trace(
            [
                spec(0.1, "file", "write", target="C:\\same.txt"),
                spec(0.2, "file", "write", target="C:\\same.txt"),
                spec(0.3, "file", "write", target="C:\\same.txt"),
            ]
        )
        self.assertIsNone(node.match(trace.events))

    def test_aggregate_without_distinct_counts_events(self) -> None:
        node = compile_node({"aggregate": {"count": ">= 2", "of": {"category": "file"}}})
        trace = make_trace(
            [spec(0.1, "file", "write", target="C:\\a.txt"), spec(0.2, "file", "write", target="C:\\a.txt")]
        )
        self.assertIsNotNone(node.match(trace.events))

    def test_window_s(self) -> None:
        payload = detector_payload(
            "unit_window",
            {"all": [{"category": "file", "action": "create"}, {"category": "file", "action": "delete"}]},
            window_s=3,
        )
        trace = make_trace(
            [
                spec(0.1, "file", "create", target="C:\\tmp\\a.bin"),
                spec(9.0, "file", "delete", target="C:\\tmp\\a.bin"),
            ]
        )
        self.assertIsNone(compile_detector(payload).evaluate(trace))
        payload["window_s"] = 12
        self.assertIsNotNone(compile_detector(payload).evaluate(trace))

        inside = make_trace(
            [
                spec(0.1, "file", "create", target="C:\\tmp\\a.bin"),
                spec(1.0, "file", "delete", target="C:\\tmp\\a.bin"),
            ]
        )
        self.assertIsNotNone(compile_detector(payload).evaluate(inside))

    def test_sequence_ordering_and_within(self) -> None:
        payload = detector_payload(
            "unit_sequence",
            {
                "sequence": {
                    "steps": [
                        {"category": "memory", "action": "alloc"},
                        {"category": "memory", "action": "write"},
                        {"category": "thread", "action": "remote_create"},
                    ],
                    "within_s": 5,
                }
            },
        )
        detector = compile_detector(payload)
        good = make_trace(
            [
                spec(0.1, "memory", "alloc", target="app.exe:42"),
                spec(0.5, "memory", "write", target="app.exe:42"),
                spec(1.0, "thread", "remote_create", target="app.exe:42"),
            ]
        )
        self.assertIsNotNone(detector.evaluate(good))

        reversed_order = make_trace(
            [
                spec(0.1, "thread", "remote_create", target="app.exe:42"),
                spec(0.5, "memory", "write", target="app.exe:42"),
                spec(1.0, "memory", "alloc", target="app.exe:42"),
            ]
        )
        self.assertIsNone(detector.evaluate(reversed_order))

        too_slow = make_trace(
            [
                spec(0.1, "memory", "alloc", target="app.exe:42"),
                spec(4.0, "memory", "write", target="app.exe:42"),
                spec(9.0, "thread", "remote_create", target="app.exe:42"),
            ]
        )
        self.assertIsNone(detector.evaluate(too_slow))

    def test_evidence_mode_first(self) -> None:
        detector = compile_detector(
            detector_payload("unit_evidence_first", {"category": "file", "action": "write"}, evidence="first")
        )
        trace = make_trace(
            [spec(0.1, "file", "write", target="C:\\a.txt"), spec(0.2, "file", "write", target="C:\\b.txt")]
        )
        events = detector.evaluate(trace)
        self.assertIsNotNone(events)
        self.assertEqual(detector.event_ids(events), ["e00001"])

    def test_empty_trace_is_safe(self) -> None:
        empty = make_trace([])
        self.assertIsNone(compile_node({"category": "file"}).match(empty.events))
        result = run_detectors_detailed(empty)
        self.assertEqual(result.hits, [])
        self.assertEqual(result.errors, [])


class TestSuppression(unittest.TestCase):
    def test_event_path_whitelist_only_downgrades(self) -> None:
        """Lead 决策：事件级路径白名单不能完全抑制检测结果，最多降权 50%。"""
        trace = make_trace([spec(0.1, "file", "write", target=r"C:\Program Files\Demo\app.exe")])
        hit = DetectorHit(detector_id="unit", evidence=["e00001"], score=10)
        events_by_id = {event.id: event for event in trace.events}
        suppressor = Suppressor(TrustStore(whitelist_paths=["C:\\Program Files\\"]))
        decision = suppressor.check_hit(hit, events_by_id)
        self.assertTrue(decision.suppressed)
        self.assertEqual(decision.factor, 0.5)
        self.assertIn("事件级", decision.reason)

    def test_sample_path_whitelist_fully_suppresses(self) -> None:
        """样本自身（样本路径/顶层进程镜像）命中白名单才完全抑制。"""
        trace = make_trace([spec(0.1, "file", "write", target=r"C:\Program Files\Demo\app.exe")])
        hit = DetectorHit(detector_id="unit", evidence=["e00001"], score=10)
        events_by_id = {event.id: event for event in trace.events}
        suppressor = Suppressor(TrustStore(whitelist_paths=["C:\\Program Files\\"]))
        decision = suppressor.check_hit(hit, events_by_id, sample_name=r"C:\Program Files\Acme\app.exe")
        self.assertTrue(decision.suppressed)
        self.assertEqual(decision.factor, 0.0)
        self.assertIn("样本路径", decision.reason)

    def test_harness_image_is_not_sample(self) -> None:
        """默认 C:\\Windows 白名单不得把 powershell 执行宿主当成样本而全量抑制（Lead 决策）。"""
        trace = make_trace(
            [
                spec(
                    0.1,
                    "process",
                    "create",
                    image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    target=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ),
                spec(0.2, "registry", "set", target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x"),
            ]
        )
        self.assertEqual(sample_image_for_trace(trace), "")
        hit = DetectorHit(detector_id="unit", evidence=["e00002"], score=10)
        events_by_id = {event.id: event for event in trace.events}
        suppressor = Suppressor(TrustStore(whitelist_paths=["C:\\Windows\\"]))
        decision = suppressor.check_hit(hit, events_by_id, sample_name=trace.sample.name)
        self.assertFalse(decision.suppressed)

    def test_whitelist_sha256_fully_suppresses(self) -> None:
        hit = DetectorHit(detector_id="unit", evidence=["e00001"], score=10)
        suppressor = Suppressor(TrustStore(whitelist_sha256=[SHA]))
        decision = suppressor.check_hit(hit, {}, sample_sha256=SHA)
        self.assertTrue(decision.suppressed)
        self.assertEqual(decision.factor, 0.0)

    def test_critical_severity_has_half_floor(self) -> None:
        """critical 永不 100% 抑制：降到 0.0 的规则也至少保留 0.5 系数。"""
        trace = make_trace([spec(0.1, "file", "write", target=r"C:\Program Files\Demo\app.exe")])
        hit = DetectorHit(detector_id="crit", severity="critical", evidence=["e00001"], score=28)
        events_by_id = {event.id: event for event in trace.events}
        suppressor = Suppressor(TrustStore())
        rule = compile_rule({"path_under": ["C:\\Program Files\\"], "factor": 0.0})
        decision = suppressor.check_hit(hit, events_by_id, [rule])
        self.assertTrue(decision.suppressed)
        self.assertEqual(decision.factor, 0.5)

    def test_detector_yaml_suppress_downgrades(self) -> None:
        trace = make_trace(
            [
                spec(
                    0.1,
                    "registry",
                    "set",
                    target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x",
                    image=r"C:\Program Files\Demo\setup.exe",
                )
            ]
        )
        result = run_detectors_detailed(trace)
        hits = [hit for hit in result.hits if hit.detector_id == "run_key_persistence"]
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].suppressed)
        self.assertAlmostEqual(result.suppress_factors["run_key_persistence"], 0.25)
        self.assertTrue(result.suppressed)

    def test_untrusted_writer_not_suppressed(self) -> None:
        trace = make_trace(
            [
                spec(
                    0.1,
                    "registry",
                    "set",
                    target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x",
                    image=r"C:\Users\Public\untrusted.exe",
                )
            ]
        )
        result = run_detectors_detailed(trace)
        hits = [hit for hit in result.hits if hit.detector_id == "run_key_persistence"]
        self.assertEqual(len(hits), 1)
        self.assertFalse(hits[0].suppressed)

    def test_compile_rule_validation(self) -> None:
        with self.assertRaises(DetectorError):
            compile_rule({"mystery": True})
        with self.assertRaises(DetectorError):
            compile_rule({"path_under": ["C:\\tmp"], "factor": 2.0})


class TestSingleDetectorCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.loaded = load_detectors()

    def _detector(self, detector_id: str):
        for detector in self.loaded.detectors:
            if detector.id == detector_id:
                return detector
        raise AssertionError(f"missing detector: {detector_id}")

    def test_persistence_detector_positive_negative(self) -> None:
        detector = self._detector("run_key_persistence")
        positive = make_trace(
            [spec(0.1, "registry", "set", target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Demo")]
        )
        negative = make_trace(
            [spec(0.1, "registry", "set", target=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Demo")]
        )
        self.assertIsNotNone(detector.evaluate(positive))
        self.assertIsNone(detector.evaluate(negative))

    def test_injection_sequence_detector_positive_negative(self) -> None:
        detector = self._detector("process_injection")
        positive = make_trace(
            [
                spec(0.1, "memory", "alloc", target="app.exe:100"),
                spec(0.5, "memory", "write", target="app.exe:100"),
                spec(0.7, "thread", "remote_create", target="app.exe:100"),
            ]
        )
        negative = make_trace(
            [
                spec(0.1, "memory", "alloc", target="app.exe:100"),
                spec(0.5, "thread", "remote_create", target="app.exe:100"),
            ]
        )
        self.assertIsNotNone(detector.evaluate(positive))
        self.assertIsNone(detector.evaluate(negative))

    def test_script_exec_bypass_ignores_root_process(self) -> None:
        """Lead 决策：根进程（第一条 process:create）的宿主启动命令行不算样本行为。"""
        detector = self._detector("script_exec_bypass")
        root_only = make_trace(
            [
                spec(
                    0.1,
                    "process",
                    "create",
                    image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    target=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    args={"command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\work\\demo.ps1"},
                )
            ]
        )
        self.assertIsNone(detector.evaluate(root_only))

        spawned_child = make_trace(
            [
                spec(
                    0.1,
                    "process",
                    "create",
                    image=r"C:\Users\Public\untrusted.exe",
                    target=r"C:\Users\Public\untrusted.exe",
                    args={"command_line": "untrusted.exe"},
                ),
                spec(
                    0.5,
                    "process",
                    "create",
                    image=r"C:\Users\Public\untrusted.exe",
                    target=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    args={"command_line": "powershell.exe -ExecutionPolicy Bypass -Command x"},
                ),
            ]
        )
        self.assertIsNotNone(detector.evaluate(spawned_child))

    def test_root_process_excluded_from_yaml_detection(self) -> None:
        """根进程事件被排除，但后续样本行为照常检测（Run 键仍命中）。"""
        trace = make_trace(
            [
                spec(
                    0.1,
                    "process",
                    "create",
                    image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    target=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ),
                spec(0.2, "registry", "set", target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x"),
            ]
        )
        result = run_detectors_detailed(trace)
        hit_ids = {hit.detector_id for hit in result.hits}
        self.assertIn("run_key_persistence", hit_ids)
        self.assertNotIn("script_exec_bypass", hit_ids)

    def test_aggregate_detector_positive_negative(self) -> None:
        detector = self._detector("ransom" + "ware_mass_ops")
        writes = [
            spec(0.01 * index, "file", "write", target=f"C:\\docs\\f{index}.docx.locked", args={"entropy": 7.9})
            for index in range(20)
        ]
        self.assertIsNotNone(detector.evaluate(make_trace(writes)))
        self.assertIsNone(detector.evaluate(make_trace(writes[:19])))


class TestPythonDetectorAndIsolation(unittest.TestCase):
    def tearDown(self) -> None:
        clear_python_detectors()

    def test_python_detector_registration(self) -> None:
        @python_detector(id="unit_py_state", severity="high", score=12, tactic="TA0005", technique="T1055")
        def two_writes(trace):
            writes = [event for event in trace.events if event.category == "file"]
            if len(writes) >= 2:
                return DetectorHit(
                    detector_id="", evidence=[writes[0].id, writes[-1].id], detail="two file writes state machine"
                )
            return None

        trace = make_trace([spec(0.1, "file", "write", target="C:\\a.txt"), spec(0.2, "file", "write", target="C:\\b.txt")])
        result = run_detectors_detailed(trace)
        hits = [hit for hit in result.hits if hit.detector_id == "unit_py_state"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].score, 12)
        self.assertEqual(hits[0].tactic, "TA0005")
        self.assertEqual(hits[0].evidence, ["e00001", "e00002"])

    def test_python_detector_exception_isolated(self) -> None:
        @python_detector(id="unit_py_boom", severity="critical", score=30)
        def boom(trace):
            raise RuntimeError("boom")

        trace = make_trace(
            [spec(0.1, "registry", "set", target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x")]
        )
        errors: list[str] = []
        hits = run_detectors(trace, errors=errors)
        self.assertTrue(any("unit_py_boom" in error for error in errors))
        self.assertTrue(any(hit.detector_id == "run_key_persistence" for hit in hits))

    def test_yaml_and_python_hits_share_contract(self) -> None:
        @python_detector(id="unit_py_contract", severity="medium", score=6)
        def always(trace):
            return True

        trace = make_trace(
            [spec(0.1, "registry", "set", target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x")]
        )
        hits = run_detectors(trace)
        self.assertIsInstance(hits, list)
        for hit in hits:
            self.assertIsInstance(hit, DetectorHit)
            self.assertTrue(hit.detector_id)
            self.assertIn(hit.severity, SEVERITIES)


if __name__ == "__main__":
    unittest.main()
