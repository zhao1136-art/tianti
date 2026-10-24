"""Trace 读写与批量回放 IO：JSON / JSONL / 目录。

JSON 格式复用 tianti.trace.schema（单一事实来源）。JSONL 为“首行信封 + 逐行事件”：

    line 1: {..., "events": []}             # Trace 顶层字段，events 留空
    line 2+: {"id": "e00001", ...}          # 每条事件一行

这样既能流式追加事件，也能复用 schema 的校验逻辑。
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.errors import TraceError
from ..core.model import Sample, SampleType
from .schema import Trace, load, save, validate_payload

TRACE_SUFFIXES = (".json", ".jsonl", ".ndjson")


def is_trace_path(path: str | Path) -> bool:
    return str(path).lower().endswith(TRACE_SUFFIXES)


def trace_from_payload(payload: object) -> Trace:
    errors = validate_payload(payload)
    if errors:
        raise TraceError("Trace 校验失败: " + "; ".join(errors[:8]), errors=errors)
    return Trace.from_dict(payload)  # type: ignore[arg-type]


def save_trace(trace: Trace, path: str | Path) -> Path:
    """按后缀写 JSON 或 JSONL。"""
    target = Path(path)
    if target.suffix.lower() in (".jsonl", ".ndjson"):
        return save_jsonl(trace, target)
    return save(trace, target)


def load_any(path: str | Path) -> Trace:
    """按后缀读取 JSON / JSONL（其余按 JSON 处理）。"""
    p = Path(path)
    if p.suffix.lower() in (".jsonl", ".ndjson"):
        return load_jsonl(p)
    return load(p)


def save_jsonl(trace: Trace, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = trace.to_dict()
    events = payload.pop("events", []) or []
    payload["events"] = []
    lines = [json.dumps(payload, ensure_ascii=False)]
    lines.extend(json.dumps(event, ensure_ascii=False) for event in events)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def load_jsonl(path: str | Path) -> Trace:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise TraceError(f"Trace JSONL 读取失败: {p}: {exc}", path=str(p)) from exc
    rows = [line for line in text.splitlines() if line.strip()]
    if not rows:
        raise TraceError(f"Trace JSONL 为空: {p}", path=str(p))
    try:
        envelope = json.loads(rows[0])
        events = [json.loads(line) for line in rows[1:]]
    except ValueError as exc:
        raise TraceError(f"Trace JSONL 解析失败: {p}: {exc}", path=str(p)) from exc
    if not isinstance(envelope, dict):
        raise TraceError(f"Trace JSONL 首行必须是对象: {p}", path=str(p))
    envelope["events"] = events
    return trace_from_payload(envelope)


def discover_traces(root: str | Path, *, recursive: bool = True) -> list[Path]:
    """在目录下发现 trace 文件（.json/.jsonl/.ndjson），按路径排序保证确定性。"""
    base = Path(root)
    if base.is_file():
        return [base]
    if not base.is_dir():
        return []
    pattern = "**/*" if recursive else "*"
    found = [p for p in base.glob(pattern) if p.is_file() and is_trace_path(p)]
    return sorted(found, key=lambda p: str(p).lower())


def load_directory(root: str | Path, *, recursive: bool = True) -> list[Trace]:
    """批量读取目录下全部 trace（任一损坏则抛出 TraceError，便于 CI 早失败）。"""
    return [load_any(path) for path in discover_traces(root, recursive=recursive)]


def sample_from_trace(trace: Trace, *, origin: str = "replay") -> Sample:
    """由 trace.sample 构造 Sample，供 ReplayBackend.run 使用。"""
    try:
        sample_type = SampleType(trace.sample.type)
    except ValueError:
        sample_type = SampleType.UNKNOWN
    return Sample(
        name=trace.sample.name,
        sha256=trace.sample.sha256,
        size=trace.sample.size,
        type=sample_type,
        origin=origin,
    )


def replay_directory(
    root: str | Path,
    *,
    recursive: bool = True,
    policy: object | None = None,
    backend: object | None = None,
) -> list[Trace]:
    """目录批量回放：逐个 trace 走 ReplayBackend，返回新的 Trace 列表。"""
    from ..sandbox.base import SandboxPolicy  # 延迟导入，避免 L2 反向依赖 L1

    traces = load_directory(root, recursive=recursive)
    sandbox_policy = policy if policy is not None else SandboxPolicy(name="replay", backend="replay")
    out: list[Trace] = []
    for trace in traces:
        target = backend
        if target is None:
            from ..sandbox.replay import ReplayBackend

            target = ReplayBackend(trace)
        out.append(target.run(sample_from_trace(trace), sandbox_policy))  # type: ignore[attr-defined]
    return out
