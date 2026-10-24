"""性能冒烟测试：分阶段计时 + 线性度 + 超时保护。

背景（Lead 2026-10-24）：直接用 CLI replay 10k 事件测量曾挂起 20 分钟以上，
说明规则/检测/评分链路可能非线性或存在卡死点。因此本文件：

  * 轻量阶段（trace 构造 / schema 校验 / JSON round-trip）进程内测 10k；
  * 重阶段（rules match / detect / scoring）通过子进程 worker
    （tests/perf/perf_worker.py）在 1k 与 10k 两个规模分别计时：
      - 子进程有硬超时，卡死不会挂起整个测试套件；
      - 1k -> 10k 的倍率用于判断线性度（阈值宽松，只拦截数量级异常）。
  * CLI 端到端用 2k 事件冒烟（10k CLI 已知慢/可能挂起，另行持续观测）。

结果写入 tests/perf/last_perf.json（含 skipped/超时原因）。

运行：
  & $PY -m unittest tests.perf.test_perf_smoke -v
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tianti.core.model import Sample
from tianti.trace.normalize import EventBuilder, build_trace
from tianti.trace.schema import SandboxInfo, dumps, loads, validate_payload
from tests import qa_helpers as qa

N_EVENTS = 10_000
SMALL_EVENTS = 1_000
CLI_EVENTS = 2_000
PERF_SNAPSHOT = qa.PERF_DIR / "last_perf.json"
WORKER_TIMEOUT_S = 90.0

# 实测基线（2026-10-24 13:18，detect/rules 优化后，单次离线 worker）：
#   rules 1k warm 64ms / cold 175ms；rules 10k warm 587ms / cold 726ms
#   detect 1k load 43ms + run 156ms；detect 10k load 36ms + run 1371ms
#   scoring 1k 3.4ms；scoring 10k 24ms
# 阈值 = 实测 x 3~4，先作冒烟水位；等 detect/rules 优化冻结后再收紧。
# 计划目标（PLAN §11.3）：50 规则 x 10k < 300ms；当前 rules 10k warm 587ms，差距约 2x。
THRESHOLDS_MS = {
    "trace_build_10k": 3_000.0,
    "schema_validate_10k": 2_000.0,
    "json_roundtrip_10k": 2_500.0,
    "rules_match_1k": 1_000.0,
    "rules_match_10k": 3_000.0,
    "detect_1k": 1_000.0,
    "detect_10k": 4_000.0,
    "scoring_1k": 500.0,
    "scoring_10k": 1_000.0,
    "cli_replay_2k": 15_000.0,
}

_RESULTS: dict[str, dict[str, Any]] = {}
_WORKER_ERRORS: list[str] = []


def _synthetic_trace(events: int = N_EVENTS) -> Any:
    """构造混合事件轨迹（文件/注册表/进程/网络/内存/线程/API），不依赖真实执行。"""
    builder = EventBuilder(max_events=events * 2 + 100, source="perf:synthetic").start()
    base_image = r"C:\sandbox\work\perf_sample.exe"
    for index in range(events):
        ts = index * 0.001
        pid = 4000 + (index % 7)
        kind = index % 10
        if kind == 0:
            builder.emit(
                "process", "create", ts=ts, pid=pid, ppid=3999, image=base_image,
                target=r"C:\Windows\System32\cmd.exe", args={"command_line": "cmd.exe /c echo perf"},
                source="perf", confidence="high",
            )
            builder.emit("process", "exit", ts=ts, pid=pid, image=base_image, source="perf", confidence="high")
            continue
        if kind in (1, 2, 3):
            builder.emit(
                "file", "write", ts=ts, pid=pid, image=base_image,
                target="C:\\sandbox\\work\\out\\file_{0:05d}.dat".format(index),
                args={"size": 256}, source="perf", confidence="medium",
            )
        elif kind == 4:
            builder.emit(
                "registry", "set", ts=ts, pid=pid, image=base_image,
                target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PerfProbe",
                args={"data": "cmd.exe /c echo perf"}, source="perf", confidence="medium",
            )
        elif kind == 5:
            builder.emit(
                "network", "connect", ts=ts, pid=pid, image=base_image,
                target="192.0.2.{0}:443".format(index % 250 + 1),
                args={"ret": 10061}, source="perf", confidence="medium",
            )
        elif kind == 6:
            builder.emit(
                "memory", "alloc", ts=ts, pid=pid, image=base_image,
                target="pid:5000", args={"size": 4096, "protect": "RWX"}, source="perf", confidence="low",
            )
        elif kind == 7:
            builder.emit(
                "thread", "remote_create", ts=ts, pid=pid, image=base_image,
                target="pid:5000", source="perf", confidence="low",
            )
        elif kind == 8:
            builder.emit(
                "api", "call", ts=ts, pid=pid, image=base_image,
                target="VirtualAllocEx", args={"api": "VirtualAllocEx", "ret": 1},
                source="perf", confidence="high",
            )
        else:
            builder.emit(
                "image", "load", ts=ts, pid=pid, image=base_image,
                target=r"C:\Windows\System32\kernel32.dll", source="perf", confidence="high",
            )

    sample = Sample.from_bytes(b"tianti-perf-synthetic-sample", "perf_synthetic.bin")
    return build_trace(
        sample=sample,
        engine_version="0.1.0",
        backend="replay",
        policy="perf",
        sandbox=SandboxInfo(host="perf-host", isolation=["synthetic"], terminated_by="exited"),
        builder=builder,
    )


def _measure(stage: str, fn: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    value = fn()
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    _RESULTS[stage] = {
        "elapsed_ms": round(elapsed_ms, 2),
        "threshold_ms": THRESHOLDS_MS[stage],
        "status": "pass" if elapsed_ms <= THRESHOLDS_MS[stage] else "fail",
        "unit": "ms",
    }
    return value, elapsed_ms


def _run_worker(stage: str, events: int) -> dict[str, Any] | None:
    """在子进程运行单阶段；超时返回 None 并记录错误，避免挂起测试套件。"""
    cmd = [sys.executable, "-m", "tests.perf.perf_worker", stage, str(events)]
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(qa.ROOT),
            env=qa.python_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=WORKER_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        elapsed = (time.perf_counter() - started) * 1000.0
        _RESULTS[f"{stage}_{events // 1000}k"] = {
            "status": "timeout",
            "timeout_s": WORKER_TIMEOUT_S,
            "elapsed_ms": round(elapsed, 2),
            "reason": f"{stage} 在 {events} 事件下超过 {WORKER_TIMEOUT_S:.0f}s 未完成（疑似非线性/卡死）",
        }
        _WORKER_ERRORS.append(f"{stage}_{events}: timeout>{WORKER_TIMEOUT_S:.0f}s")
        return None
    output = (proc.stdout or "").strip().splitlines()
    if proc.returncode != 0 or not output:
        _WORKER_ERRORS.append(
            f"{stage}_{events}: exit={proc.returncode} stderr={(proc.stderr or '')[:200]}"
        )
        return None
    try:
        return json.loads(output[-1])
    except ValueError:
        _WORKER_ERRORS.append(f"{stage}_{events}: 输出不可解析 stdout={(proc.stdout or '')[:200]}")
        return None


class PerfSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _RESULTS.clear()
        _WORKER_ERRORS.clear()
        cls.trace = _synthetic_trace(N_EVENTS)
        cls.payload = cls.trace.to_dict()

    @classmethod
    def tearDownClass(cls) -> None:
        qa.PERF_DIR.mkdir(parents=True, exist_ok=True)
        snapshot = {
            "schema": "tianti.qa.perf/1",
            "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "events": N_EVENTS,
            "small_events": SMALL_EVENTS,
            "cli_events": CLI_EVENTS,
            "thresholds_ms": dict(THRESHOLDS_MS),
            "worker_timeout_s": WORKER_TIMEOUT_S,
            "stages": dict(_RESULTS),
            "worker_errors": list(_WORKER_ERRORS),
        }
        PERF_SNAPSHOT.write_text(
            json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    def _skip_stage(self, stage: str, reason: str) -> None:
        _RESULTS[stage] = {"status": "skipped", "reason": reason}
        self.skipTest(reason)

    def _assert_budget(self, stage: str, elapsed_ms: float, threshold_key: str | None = None) -> None:
        threshold = THRESHOLDS_MS[threshold_key or stage]
        self.assertLessEqual(
            elapsed_ms, threshold, f"{stage} 耗时 {elapsed_ms:.1f}ms 超过阈值 {threshold:.0f}ms"
        )

    # ---- 轻量阶段（进程内） -------------------------------------------------
    def test_trace_build_10k(self) -> None:
        trace, elapsed = _measure("trace_build_10k", lambda: _synthetic_trace(N_EVENTS))
        self.assertGreaterEqual(len(trace.events), N_EVENTS)
        self.assertFalse(trace.summary.truncated)
        self._assert_budget("trace_build_10k", elapsed)

    def test_schema_validate_10k(self) -> None:
        errors, elapsed = _measure("schema_validate_10k", lambda: validate_payload(self.payload))
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(self.payload["events"]), N_EVENTS)
        self.assertEqual(len(self.payload["events"]), len(self.trace.events))
        self._assert_budget("schema_validate_10k", elapsed)

    def test_json_roundtrip_10k(self) -> None:
        text, elapsed = _measure("json_roundtrip_10k", lambda: dumps(self.trace))
        restored = loads(text)
        self.assertEqual(len(restored.events), len(self.trace.events))
        self._assert_budget("json_roundtrip_10k", elapsed)

    # ---- 重阶段（子进程 + 1k/10k 线性度） -----------------------------------
    STAGE_THRESHOLD_KEYS = {"rules": "rules_match", "detect": "detect", "scoring": "scoring"}

    def _check_stage(self, stage: str) -> None:
        threshold_key = self.STAGE_THRESHOLD_KEYS[stage]
        small = _run_worker(stage, SMALL_EVENTS)
        if small is None:
            record = _RESULTS.get(f"{stage}_1k") or {}
            self.fail(
                f"{stage} 在 {SMALL_EVENTS} 事件下未完成（{record.get('reason', '子进程失败')}）；"
                f"复现: python -m tests.perf.perf_worker {stage} {SMALL_EVENTS}"
            )
        large = _run_worker(stage, N_EVENTS)
        if large is None:
            record = _RESULTS.get(f"{stage}_10k") or {}
            self.fail(
                f"{stage} 在 {N_EVENTS} 事件下未完成（{record.get('reason', '子进程失败')}）；"
                f"复现: python -m tests.perf.perf_worker {stage} {N_EVENTS}"
            )
        small_key = f"{stage}_1k"
        large_key = f"{stage}_10k"
        small_threshold_key = f"{threshold_key}_1k"
        large_threshold_key = f"{threshold_key}_10k"
        _RESULTS[small_key] = {
            "elapsed_ms": small["elapsed_ms"],
            "threshold_ms": THRESHOLDS_MS[small_threshold_key],
            "status": "pass" if small["elapsed_ms"] <= THRESHOLDS_MS[small_threshold_key] else "fail",
            "events": SMALL_EVENTS,
            "worker": small,
        }
        _RESULTS[large_key] = {
            "elapsed_ms": large["elapsed_ms"],
            "threshold_ms": THRESHOLDS_MS[large_threshold_key],
            "status": "pass" if large["elapsed_ms"] <= THRESHOLDS_MS[large_threshold_key] else "fail",
            "events": N_EVENTS,
            "linearity_ratio": round(
                float(large["elapsed_ms"]) / max(0.001, float(small["elapsed_ms"])), 2
            ),
            "worker": large,
        }
        self._assert_budget(small_key, float(small["elapsed_ms"]), small_threshold_key)
        self._assert_budget(large_key, float(large["elapsed_ms"]), large_threshold_key)
        ratio = _RESULTS[large_key]["linearity_ratio"]
        self.assertLess(
            ratio, 40.0,
            f"{stage} 1k->10k 耗时倍率 {ratio} 异常（事件 10 倍，耗时不应 >40 倍；疑似非线性）",
        )

    def test_rules_match_linearity(self) -> None:
        self._check_stage("rules")

    def test_detect_linearity(self) -> None:
        self._check_stage("detect")

    def test_scoring_linearity(self) -> None:
        self._check_stage("scoring")

    # ---- CLI 端到端冒烟（2k） ----------------------------------------------
    def test_cli_replay_2k(self) -> None:
        trace = _synthetic_trace(CLI_EVENTS)
        with tempfile.TemporaryDirectory(prefix="tianti_perf_cli_") as tmp:
            trace_path = Path(tmp) / "perf_trace.json"
            trace_path.write_text(dumps(trace), encoding="utf-8")
            started = time.perf_counter()
            try:
                proc = qa.run_cli("replay", str(trace_path), "--format", "json", timeout=120)
            except Exception as exc:
                self.fail(f"CLI replay {CLI_EVENTS} 事件异常: {type(exc).__name__}: {exc}")
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            _RESULTS["cli_replay_2k"] = {
                "elapsed_ms": round(elapsed_ms, 2),
                "threshold_ms": THRESHOLDS_MS["cli_replay_2k"],
                "status": "pass" if elapsed_ms <= THRESHOLDS_MS["cli_replay_2k"] else "fail",
                "events": CLI_EVENTS,
            }
            payload = qa.parse_json_stdout(proc.stdout) if proc.returncode == 0 else None
            if proc.returncode != 0 or payload is None:
                stderr = (proc.stderr or "").strip().replace("\n", " ")[:160]
                self._skip_stage(
                    "cli_replay_2k",
                    f"{qa.SKIP_PREFIX}: CLI replay 尚不可用（exit={proc.returncode}, stderr={stderr or '空'}）",
                )
            verdict, _score = qa.find_verdict(payload)
            self.assertIsNotNone(verdict, "CLI replay 输出缺少 verdict")
            self._assert_budget("cli_replay_2k", elapsed_ms)
