"""QA 公共工具：仓库路径、可选模块探测、CLI 调用、心跳文件观测。

只被 tests/ 下用例 import，不属于引擎运行时。
约定：模块未就绪时返回 (None, "未就绪: ...")，用例据此 skipTest（原因必须写明）。
"""

from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
GOLDEN_TRACES = TESTS / "fixtures" / "traces"
REGRESSION_FIXTURES = TESTS / "fixtures" / "regression"
PERF_DIR = TESTS / "perf"
SAMPLES = ROOT / "samples"
SIM_SAMPLES = SAMPLES / "sim"
BENIGN_SAMPLES = SAMPLES / "benign"

# skip 原因统一前缀，便于全量测试输出按"未就绪"聚合
SKIP_PREFIX = "未就绪"


def python_env() -> dict[str, str]:
    """让子进程 (python -m tianti) 能从仓库根 import tianti 与 tests。"""
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    parts = [str(ROOT)]
    if existing:
        parts.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env


def run_cli(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    """以当前解释器在仓库根执行 python -m tianti ...。"""
    return subprocess.run(
        [sys.executable, "-m", "tianti", *args],
        cwd=str(ROOT),
        env=python_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def import_optional(module: str) -> tuple[Any | None, str]:
    """导入可选模块；缺失/导入异常都视为"未就绪"并返回原因。"""
    try:
        return importlib.import_module(module), ""
    except ModuleNotFoundError as exc:
        return None, f"{SKIP_PREFIX}: 模块缺失 {module} ({exc})"
    except Exception as exc:  # 导入期异常不能拖垮整个测试进程
        return None, f"{SKIP_PREFIX}: 模块 {module} 导入失败 ({type(exc).__name__}: {exc})"


def first_callable(module: Any, names: list[str]) -> tuple[str | None, Any | None]:
    """在模块上按顺序找第一个可调用属性。"""
    for name in names:
        fn = getattr(module, name, None)
        if callable(fn):
            return name, fn
    return None, None


def containment_backend() -> tuple[Any | None, str]:
    """探测 containment 后端是否就绪。返回 (BACKEND, 原因)。"""
    module, reason = import_optional("tianti.sandbox.containment")
    if module is None:
        return None, reason
    backend = getattr(module, "BACKEND", None)
    if backend is None:
        return None, f"{SKIP_PREFIX}: tianti.sandbox.containment 未导出 BACKEND"
    available = getattr(backend, "available", None)
    if not callable(available):
        return None, f"{SKIP_PREFIX}: containment.BACKEND 缺少 available()"
    try:
        ok, why = available()
    except Exception as exc:
        return None, f"{SKIP_PREFIX}: containment.available() 异常 ({type(exc).__name__}: {exc})"
    if not ok:
        return None, f"{SKIP_PREFIX}: containment 不可用 ({why})"
    if not callable(getattr(backend, "run", None)):
        return None, f"{SKIP_PREFIX}: containment.BACKEND 缺少 run()"
    return backend, ""


def golden_trace_paths() -> list[Path]:
    return sorted(GOLDEN_TRACES.glob("*.json"))


def load_expectations() -> dict[str, Any]:
    path = REGRESSION_FIXTURES / "golden_expectations.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {}


def parse_json_stdout(text: str) -> Any | None:
    """从 CLI stdout 提取 JSON（容忍前后日志行）。"""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except ValueError:
            return None
    return None


def deep_find(payload: Any, key: str) -> list[Any]:
    """递归查找所有同名 key 的值（只用于对输出结构做宽松适配）。"""
    found: list[Any] = []
    if isinstance(payload, dict):
        for name, value in payload.items():
            if name == key:
                found.append(value)
            found.extend(deep_find(value, key))
    elif isinstance(payload, list):
        for item in payload:
            found.extend(deep_find(item, key))
    return found


def find_first(payload: Any, key: str) -> Any | None:
    values = deep_find(payload, key)
    return values[0] if values else None


VALID_VERDICTS = ("clean", "suspicious", "malicious")


def _score_to_float(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def find_verdict(payload: Any) -> tuple[str | None, float | None]:
    """从任意 CLI JSON 输出中宽松提取 (verdict, score)。

    兼容两种形态：
      * {"verdict": "malicious", "score": 42}
      * {"verdict": {"verdict": "malicious", "score": 42}}
    以及 tianti.result/1 的嵌套结构。
    """
    for value in deep_find(payload, "verdict"):
        if isinstance(value, str) and value in VALID_VERDICTS:
            return value, _score_to_float(find_first(payload, "score"))
        if isinstance(value, dict):
            label = value.get("verdict") or value.get("label") or value.get("value")
            if isinstance(label, str) and label in VALID_VERDICTS:
                score = _score_to_float(value.get("score"))
                if score is None:
                    score = _score_to_float(find_first(payload, "score"))
                return label, score
    return None, _score_to_float(find_first(payload, "score"))


def analysis_info(payload: Any) -> dict[str, Any]:
    """取 tianti.result/1 的 extra.analysis（下游模块就绪度信息）。"""
    extra = find_first(payload, "extra")
    if isinstance(extra, dict) and isinstance(extra.get("analysis"), dict):
        return dict(extra["analysis"])
    analysis = find_first(payload, "analysis")
    return dict(analysis) if isinstance(analysis, dict) else {}


def hit_payload(payload: Any) -> list[Any] | None:
    """提取检测器命中列表（hits/detector_hits）。"""
    for key in ("hits", "detector_hits"):
        for value in deep_find(payload, key):
            if isinstance(value, list):
                return value
    return None


def rule_payload(payload: Any) -> Any | None:
    """提取规则命中列表（兼容 rules / capabilities / rule_matches / matches 命名）。"""
    for key in ("rules", "capabilities", "rule_matches", "matches"):
        values = deep_find(payload, key)
        for value in values:
            if isinstance(value, list) and value:
                return value
    return None


def safe_rmtree(path: str | Path) -> None:
    shutil.rmtree(str(path), ignore_errors=True)


def unique_token(prefix: str = "qa") -> str:
    return f"{prefix}_{os.getpid()}_{int(time.time() * 1000)}"


def file_signature(path: str | Path) -> tuple[int, int] | None:
    """(size, mtime_ns)；文件不存在返回 None。"""
    p = Path(path)
    try:
        stat = p.stat()
    except OSError:
        return None
    return int(stat.st_size), int(stat.st_mtime_ns)


def wait_heartbeat_stopped(
    path: str | Path,
    *,
    quiet_s: float = 1.5,
    timeout_s: float = 8.0,
    poll_s: float = 0.2,
) -> bool:
    """等待心跳文件停止增长：连续 quiet_s 秒签名不变即视为进程已死。"""
    last = file_signature(path)
    stable_since = time.monotonic()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        time.sleep(poll_s)
        current = file_signature(path)
        if current != last:
            last = current
            stable_since = time.monotonic()
        elif time.monotonic() - stable_since >= quiet_s:
            return True
    return False


def live_processes_matching(token: str, *, timeout_s: float = 20.0) -> list[dict[str, Any]]:
    """用 Get-CimInstance 查命令行包含 token 的存活进程（排除查询进程自身）。"""
    if not token or not token.isalnum() and "_" not in token:
        token = token.replace("'", "")
    command = (
        "Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and "
        "$_.CommandLine -like '*" + token + "*' } | "
        "Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    text = (proc.stdout or "").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    if isinstance(payload, dict):
        return [payload]
    return [item for item in payload if isinstance(item, dict)]


def wait_no_processes(token: str, *, timeout_s: float = 6.0, poll_s: float = 0.4) -> list[dict[str, Any]]:
    """等待匹配 token 的进程全部退出；返回最终残留列表（空表示无残留）。"""
    deadline = time.monotonic() + timeout_s
    found = live_processes_matching(token)
    while found and time.monotonic() < deadline:
        time.sleep(poll_s)
        found = live_processes_matching(token)
    return found


def locate_file(trace: Any, workdir: str | Path, filename: str) -> Path | None:
    """先在 trace 的 file/process target 中找，再到 workdir 下搜索同名文件。"""
    suffix = filename.lower()
    for event in getattr(trace, "events", []):
        target = getattr(event, "target", None)
        if not isinstance(target, str):
            continue
        if target.lower().endswith(suffix):
            candidate = Path(target)
            if candidate.exists():
                return candidate
    matches = sorted(Path(workdir).rglob(filename))
    return matches[0] if matches else None
