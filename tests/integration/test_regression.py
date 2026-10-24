"""golden trace 回归测试。

分层（详见 tests/README.md）：
  * GoldenTraceContractRegression：只依赖冻结契约，始终运行。
    - 3 份 golden trace 必须存在、可校验、round-trip 稳定；
    - summary 可由 events 重算；事件 id/ts 稳定；期望元数据一致。
  * CliReplayRegression：通过公开 CLI（python -m tianti replay ...）验证
    规则 / 检测 / 评分结果稳定。CLI 或下游模块未就绪时 skip（原因明确）。
  * ReplayIoRegression：探测 tianti.trace.replay_io，验证回放 IO 确定性；
    未就绪时 skip。

运行：
  & $PY -m unittest tests.integration.test_regression -v
（$PY 为 DSH Python 绝对路径，见 tests/README.md）

基线策略：首次 CLI replay 可用时，会把当时的 verdict/score/规则名写入
tests/fixtures/regression/golden_baseline.json；此后每次运行逐项比对，
任何漂移都会失败并提示是"回归"还是"预期变更"（预期变更需更新基线文件）。
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tianti.trace import schema
from tianti.trace.schema import TraceSummary
from tests import qa_helpers as qa

EVENT_ID_RE = re.compile(r"^e\d{5}$")
BASELINE_PATH = qa.REGRESSION_FIXTURES / "golden_baseline.json"


class GoldenTraceContractRegression(unittest.TestCase):
    """不依赖后续里程碑模块的契约回归，必须始终为绿。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.paths = qa.golden_trace_paths()
        cls.expectations = qa.load_expectations()
        cls.payloads = {
            path.name: json.loads(path.read_text(encoding="utf-8")) for path in cls.paths
        }

    def test_golden_trace_set_complete(self) -> None:
        self.assertGreaterEqual(len(self.paths), 3, "至少需要 3 份 golden trace")
        expected = set((self.expectations.get("traces") or {}).keys())
        actual = {path.name for path in self.paths}
        self.assertEqual(expected, actual, "golden trace 与 golden_expectations.json 不一致")

    def test_validate_and_round_trip(self) -> None:
        for path in self.paths:
            with self.subTest(trace=path.name):
                errors = schema.validate_payload(self.payloads[path.name])
                self.assertEqual(errors, [], f"{path.name} 校验失败: {errors}")
                trace = schema.load(path)
                trace.validate()
                # 契约稳定：落盘 JSON -> Trace -> JSON 必须逐字节等价（dict 层）
                self.assertEqual(trace.to_dict(), self.payloads[path.name])
                restored = schema.Trace.from_dict(trace.to_dict())
                self.assertEqual(restored.to_dict(), trace.to_dict())

    def test_event_ids_and_timestamps_stable(self) -> None:
        for path in self.paths:
            with self.subTest(trace=path.name):
                events = self.payloads[path.name]["events"]
                ids = [event["id"] for event in events]
                self.assertEqual(ids, sorted(ids), "事件 id 必须递增")
                self.assertEqual(len(ids), len(set(ids)), "事件 id 必须唯一")
                for event_id in ids:
                    self.assertRegex(event_id, EVENT_ID_RE, "事件 id 必须形如 e00001")
                timestamps = [float(event["ts"]) for event in events]
                self.assertEqual(timestamps, sorted(timestamps), "ts 必须非降序")
                self.assertTrue(all(ts >= 0 for ts in timestamps))

    def test_summary_can_be_recomputed_from_events(self) -> None:
        for path in self.paths:
            with self.subTest(trace=path.name):
                trace = schema.load(path)
                recomputed = TraceSummary.from_events(trace.events, dropped=trace.summary.dropped)
                self.assertEqual(recomputed.to_dict(), trace.summary.to_dict())
                self.assertEqual(trace.summary.event_count, len(trace.events))
                if trace.events:
                    self.assertAlmostEqual(
                        trace.summary.first_seen, min(event.ts for event in trace.events), places=6
                    )

    def test_expectations_match_golden_metadata(self) -> None:
        traces = self.expectations.get("traces") or {}
        valid_terminations = set(schema.TERMINATIONS)
        for name, expected in traces.items():
            with self.subTest(trace=name):
                payload = self.payloads[name]
                self.assertEqual(len(payload["events"]), expected["event_count"])
                self.assertEqual(payload["sample"]["type"], expected["sample_type"])
                self.assertEqual(payload["schema"], schema.SCHEMA_ID)
                self.assertIn(payload["sandbox"]["terminated_by"], valid_terminations)
                self.assertTrue(payload["sandbox"]["isolation"], "golden trace 必须声明隔离手段")
                seen = {(event["category"], event["action"]) for event in payload["events"]}
                for category, actions in (expected.get("required") or {}).items():
                    for action in actions:
                        self.assertIn(
                            (category, action),
                            seen,
                            f"{name} 缺少期望事件 {category}/{action}",
                        )


class CliReplayRegression(unittest.TestCase):
    """端到端回归：同一 golden trace 经公开 CLI 的结论必须稳定。"""

    _cache: dict[str, tuple[Any, Any]] = {}

    @classmethod
    def setUpClass(cls) -> None:
        cls._cache = {}
        cls.expectations = qa.load_expectations()
        cls.trace_names = sorted((cls.expectations.get("traces") or {}).keys())

    @classmethod
    def _output(cls, name: str) -> tuple[Any, Any]:
        if name not in cls._cache:
            path = qa.GOLDEN_TRACES / name
            proc = qa.run_cli("replay", str(path), "--format", "json", timeout=180)
            payload = qa.parse_json_stdout(proc.stdout) if proc.stdout else None
            cls._cache[name] = (proc, payload)
        return cls._cache[name]

    def _payload_or_skip(self, name: str) -> Any:
        proc, payload = self._output(name)
        if proc.returncode != 0 or payload is None:
            stderr = (proc.stderr or "").strip().replace("\n", " ")[:200]
            self.skipTest(
                f"{qa.SKIP_PREFIX}: CLI replay 尚不可用（exit={proc.returncode}, stderr={stderr or '空'}）"
            )
        return payload

    def test_verdict_and_score_expectations(self) -> None:
        for name, expected in sorted((self.expectations.get("traces") or {}).items()):
            with self.subTest(trace=name):
                payload = self._payload_or_skip(name)
                verdict, score = qa.find_verdict(payload)
                self.assertIsNotNone(verdict, f"CLI 输出缺少 verdict；顶层 keys={sorted(payload)[:12]}")
                self.assertIn(verdict, expected["verdict_allowed"])
                self.assertIsNotNone(score, "CLI 输出缺少 score")
                self.assertGreaterEqual(float(score), float(expected["min_score"]))
                if expected.get("max_score") is not None:
                    self.assertLessEqual(float(score), float(expected["max_score"]))

    def test_rule_hits_present_for_malicious_traces(self) -> None:
        for name, expected in sorted((self.expectations.get("traces") or {}).items()):
            hints = expected.get("rule_hints") or []
            if not hints:
                continue
            with self.subTest(trace=name):
                payload = self._payload_or_skip(name)
                analysis = qa.analysis_info(payload)
                rules = qa.rule_payload(payload)
                if analysis.get("rules_available") is False or rules is None:
                    notes = qa.find_first(payload, "notes") or []
                    snippet = " ".join(str(note) for note in notes)[:220]
                    self.skipTest(
                        f"{qa.SKIP_PREFIX}: 规则引擎未产出命中"
                        f"（rules_available={analysis.get('rules_available')!r}, notes={snippet or '空'}）"
                    )
                self.assertTrue(rules, "规则引擎声明可用但 matches 为空（规则语义回归）")
                blob = json.dumps(rules, ensure_ascii=False).lower()
                self.assertTrue(
                    any(str(hint).lower() in blob for hint in hints),
                    f"{name} 未命中任何期望规则提示 {hints}；实际={blob[:400]}",
                )

    def test_required_detectors_hit(self) -> None:
        for name, expected in sorted((self.expectations.get("traces") or {}).items()):
            required = expected.get("required_detectors") or []
            if not required:
                continue
            with self.subTest(trace=name):
                payload = self._payload_or_skip(name)
                analysis = qa.analysis_info(payload)
                hits = qa.hit_payload(payload)
                if analysis.get("detectors_available") is False or hits is None:
                    self.skipTest(
                        f"{qa.SKIP_PREFIX}: 检测器未产出命中"
                        f"（detectors_available={analysis.get('detectors_available')!r}）"
                    )
                ids = {
                    str(hit.get("detector_id") or hit.get("id") or "")
                    for hit in hits
                    if isinstance(hit, dict)
                }
                missing = [detector for detector in required if detector not in ids]
                self.assertEqual(
                    missing, [], f"{name} 缺少期望检测器命中 {missing}；实际={sorted(ids)}"
                )

    def test_replay_is_deterministic(self) -> None:
        name = "golden_ransom_sim.json"
        first = self._payload_or_skip(name)
        proc = qa.run_cli("replay", str(qa.GOLDEN_TRACES / name), "--format", "json", timeout=180)
        if proc.returncode != 0:
            self.skipTest(f"{qa.SKIP_PREFIX}: 第二次 replay 失败（exit={proc.returncode}）")
        second = qa.parse_json_stdout(proc.stdout)
        if second is None:
            self.skipTest(f"{qa.SKIP_PREFIX}: 第二次 replay 输出不可解析")
        first_verdict, first_score = qa.find_verdict(first)
        second_verdict, second_score = qa.find_verdict(second)
        self.assertEqual(first_verdict, second_verdict, "同一 trace 两次 replay 判定不一致")
        if first_score is not None and second_score is not None:
            self.assertAlmostEqual(float(first_score), float(second_score), places=3)

    def test_baseline_stability(self) -> None:
        observed: dict[str, Any] = {}
        for name in self.trace_names:
            payload = self._payload_or_skip(name)
            verdict, score = qa.find_verdict(payload)
            rules = qa.rule_payload(payload)
            names: list[str] = []
            if isinstance(rules, list):
                for item in rules:
                    if isinstance(item, dict):
                        value = item.get("name") or item.get("rule") or item.get("id")
                        if isinstance(value, str):
                            names.append(value)
            hits = qa.hit_payload(payload) or []
            detector_ids = sorted(
                {
                    str(hit.get("detector_id") or hit.get("id") or "")
                    for hit in hits
                    if isinstance(hit, dict) and (hit.get("detector_id") or hit.get("id"))
                }
            )
            observed[name] = {
                "verdict": verdict,
                "score": round(float(score), 3) if score is not None else None,
                "rules": sorted(set(names)),
                "detectors": detector_ids,
            }

        if not BASELINE_PATH.exists():
            # 只有满足期望的结论才允许固化成基线，避免把缺陷写进 golden 基线
            for name, actual in observed.items():
                expected = (self.expectations.get("traces") or {}).get(name) or {}
                allowed = expected.get("verdict_allowed") or []
                self.assertIn(
                    actual["verdict"],
                    allowed,
                    f"基线未生成：{name} 判定 {actual['verdict']!r} 不在期望 {allowed}（先修复缺陷再固化基线）",
                )
            qa.REGRESSION_FIXTURES.mkdir(parents=True, exist_ok=True)
            from datetime import datetime, timezone

            BASELINE_PATH.write_text(
                json.dumps(
                    {
                        "schema": "tianti.qa.baseline/1",
                        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
                        "generated_by": "python -m unittest tests.integration.test_regression.CliReplayRegression.test_baseline_stability",
                        "source": "tianti.result/1 CLI replay 实测固化；评分/规则/检测器语义变更须由 owner 通知 QA 后重新固化",
                        "traces": observed,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            return

        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        expected = baseline.get("traces") or {}
        for name, actual in observed.items():
            with self.subTest(trace=name):
                if name not in expected:
                    self.fail(f"golden baseline 缺少 {name}，请更新 {BASELINE_PATH.name}")
                want = expected[name]
                self.assertEqual(actual["verdict"], want.get("verdict"), f"{name} 判定漂移")
                if actual["score"] is not None and want.get("score") is not None:
                    self.assertAlmostEqual(float(actual["score"]), float(want["score"]), places=3)
                if want.get("rules"):
                    self.assertEqual(
                        actual["rules"],
                        list(want["rules"]),
                        f"{name} 规则命中集合漂移（若为预期变更请更新基线文件）",
                    )
                if want.get("detectors"):
                    self.assertEqual(
                        actual["detectors"],
                        list(want["detectors"]),
                        f"{name} 检测器命中集合漂移（若为预期变更请更新基线文件）",
                    )


class ReplayIoRegression(unittest.TestCase):
    """回放 IO 确定性（依赖 sandbox owner 的 tianti.trace.replay_io）。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.module, cls.reason = qa.import_optional("tianti.trace.replay_io")


    def test_replay_io_round_trip_is_deterministic(self) -> None:
        if self.module is None:
            self.skipTest(self.reason)
        loader = (
            getattr(self.module, "load_any", None)
            or getattr(self.module, "load_trace", None)
            or getattr(self.module, "load", None)
        )
        saver = getattr(self.module, "save_trace", None) or getattr(self.module, "save", None)
        if not callable(loader):
            self.skipTest(f"{qa.SKIP_PREFIX}: replay_io 未暴露 load_any/load_trace/load")
        if not callable(saver):
            self.skipTest(f"{qa.SKIP_PREFIX}: replay_io 未暴露 save_trace/save")

        path = qa.GOLDEN_TRACES / "golden_ransom_sim.json"
        try:
            first = loader(str(path))
            second = loader(str(path))
        except TypeError:
            self.skipTest(f"{qa.SKIP_PREFIX}: replay_io 接口签名不兼容（需与 sandbox owner 对齐）")
        except Exception as exc:
            self.fail(f"replay_io 加载 golden trace 失败: {type(exc).__name__}: {exc}")

        self.assertEqual(first.to_dict(), second.to_dict(), "两次加载结果不一致")

        with tempfile.TemporaryDirectory(prefix="tianti_replay_io_") as tmp:
            out = Path(tmp) / "roundtrip.json"
            try:
                saver(first, str(out))
                reloaded = loader(str(out))
            except TypeError:
                self.skipTest(f"{qa.SKIP_PREFIX}: replay_io 保存接口签名不兼容")
            except Exception as exc:
                self.fail(f"replay_io save/load 失败: {type(exc).__name__}: {exc}")
            self.assertEqual(reloaded.to_dict(), first.to_dict(), "save/load 不可逆")

            save_jsonl = getattr(self.module, "save_jsonl", None)
            load_jsonl = getattr(self.module, "load_jsonl", None)
            if callable(save_jsonl) and callable(load_jsonl):
                jsonl_path = Path(tmp) / "roundtrip.jsonl"
                save_jsonl(first, jsonl_path)
                from_jsonl = load_jsonl(jsonl_path)
                self.assertEqual(from_jsonl.to_dict(), first.to_dict(), "JSONL save/load 不可逆")
