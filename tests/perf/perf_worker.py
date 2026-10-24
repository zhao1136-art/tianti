"""perf 单阶段 worker（由 tests/perf/test_perf_smoke.py 以子进程调用）。

用法：
  python -m tests.perf.perf_worker <stage> <events>
stage ∈ rules | detect | scoring
输出：stdout 最后一行一个 JSON；把"加载"与"运行"分开计时，便于定位瓶颈。
只构造合成 Trace，不执行样本、不触碰沙箱。
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

from tests.perf.test_perf_smoke import _synthetic_trace


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000.0, 2)


def main(argv: list[str]) -> int:
    stage = argv[1] if len(argv) > 1 else "rules"
    events = int(argv[2]) if len(argv) > 2 else 1000
    result: dict[str, Any] = {"stage": stage, "events": events}

    started = time.perf_counter()
    trace = _synthetic_trace(events)
    result["trace_build_ms"] = _ms(started)

    if stage == "rules":
        from tianti.rules.engine import RuleEngine, match_trace

        # 冷启动：加载规则包 + 首次匹配
        started = time.perf_counter()
        cold_matches = match_trace(trace)
        result["cold_ms"] = _ms(started)
        result["cold_matches"] = len(cold_matches)
        # 热匹配：引擎已缓存，只计匹配
        started = time.perf_counter()
        matches = match_trace(trace)
        result["elapsed_ms"] = _ms(started)
        result["matches"] = len(matches)
        result["engine_rules"] = len(RuleEngine())

    elif stage == "detect":
        from tianti.detect.detectors import load_detectors, run_detectors

        # 检测器加载（YAML 解析/编译），单独计时
        started = time.perf_counter()
        detector_set = load_detectors()
        result["load_ms"] = _ms(started)
        result["detectors"] = len(detector_set)
        # 只计运行
        started = time.perf_counter()
        hits = run_detectors(trace, detector_set=detector_set)
        result["elapsed_ms"] = _ms(started)
        result["hits"] = len(hits)

    elif stage == "scoring":
        from tianti.detect.detectors import run_detectors
        from tianti.detect.scoring import evaluate
        from tianti.rules.engine import match_trace

        started = time.perf_counter()
        matches = match_trace(trace)
        result["rules_ms"] = _ms(started)
        started = time.perf_counter()
        hits = run_detectors(trace)
        result["detect_ms"] = _ms(started)
        started = time.perf_counter()
        verdict = evaluate(trace, matches, hits)
        result["elapsed_ms"] = _ms(started)
        result["matches"] = len(matches)
        result["hits"] = len(hits)
        result["verdict"] = getattr(verdict, "verdict", "")
        result["score"] = round(float(getattr(verdict, "score", 0.0)), 3)

    else:
        result["error"] = f"unknown stage: {stage}"
        print(json.dumps(result, ensure_ascii=False))
        return 2

    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
