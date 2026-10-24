"""回放后端（ReplayBackend）：从已落盘的 Trace 重新产出事件流，不执行样本。

用途：规则/检测器/评分开发与 CI、演示、跨环境复现。数据来源可以是单个
trace 文件、目录、Trace 对象或它们的列表。回放严格按事件时间序重新产出，
事件 id 由 EventBuilder 重新分配（e00001...），其余字段保持不变。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .. import __version__
from ..core.errors import SandboxError, SandboxUnavailable
from ..core.model import Sample, SampleType
from ..trace.normalize import EventBuilder, build_trace
from ..trace.schema import Event, SandboxInfo, Trace
from .base import BaseSandboxBackend, SandboxPolicy

SourceLike = str | Path | Trace


def _as_sample(info: object) -> Sample:
    """把 trace.sample 或 passed Sample 统一成 Sample（类型无法解析时降级 UNKNOWN）。"""
    if isinstance(info, Sample):
        return info
    payload = getattr(info, "to_dict", None)
    data = payload() if callable(payload) else dict(info)  # type: ignore[arg-type]
    try:
        sample_type = SampleType(str(data.get("type", SampleType.UNKNOWN.value)))
    except ValueError:
        sample_type = SampleType.UNKNOWN
    return Sample(
        name=str(data.get("name", "")),
        sha256=str(data.get("sha256", "")),
        size=int(data.get("size", 0) or 0),
        type=sample_type,
        origin="replay",
    )


def _valid_sample(sample: Sample | None) -> bool:
    return bool(sample and sample.name and len(sample.sha256) == 64)


class ReplayBackend(BaseSandboxBackend):
    """把 trace 当作“样本执行结果”回放；不触碰真实系统。"""

    name = "replay"

    def __init__(
        self,
        source: SourceLike | Sequence[SourceLike] | None = None,
        *,
        realtime: bool = False,
        trace_gap_s: float = 0.001,
    ) -> None:
        self.source = source
        self.realtime = bool(realtime)
        self.trace_gap_s = max(0.0, float(trace_gap_s))

    # -- 可用性 -------------------------------------------------------
    def available(self) -> tuple[bool, str]:
        return True, "replay 后端：读取已落盘 trace，无需执行样本（零风险）"

    # -- 数据源解析 ---------------------------------------------------
    @classmethod
    def from_path(cls, path: str | Path, **kwargs: object) -> "ReplayBackend":
        return cls(Path(path), **kwargs)  # type: ignore[arg-type]

    def _resolve_sources(self, sample: Sample | None) -> list[SourceLike]:
        if self.source is not None:
            if isinstance(self.source, Trace):
                return [self.source]
            if isinstance(self.source, (str, Path)):
                return [self.source]
            return list(self.source)  # type: ignore[arg-type]
        extra = dict(getattr(sample, "extra", None) or {})
        for key in ("trace_path", "trace", "traces", "trace_paths"):
            value = extra.get(key)
            if isinstance(value, (str, Path)):
                return [value]
            if isinstance(value, Trace):
                return [value]
            if isinstance(value, (list, tuple)) and value:
                return list(value)
        path = getattr(sample, "path", None)
        if path and str(path).lower().endswith((".json", ".jsonl", ".ndjson")):
            return [path]
        raise SandboxUnavailable(
            "ReplayBackend 未指定回放数据源：请构造 ReplayBackend(trace_path) "
            "或在 sample.extra 中提供 trace_path/traces",
            backend="replay",
        )

    def _load_traces(self, sample: Sample | None) -> list[Trace]:
        from ..trace import replay_io

        traces: list[Trace] = []
        for item in self._resolve_sources(sample):
            if isinstance(item, Trace):
                item.validate()
                traces.append(item)
            else:
                traces.append(replay_io.load_any(Path(item)))
        if not traces:
            raise SandboxUnavailable("ReplayBackend 数据源为空", backend="replay")
        return traces

    # -- 运行（回放） -------------------------------------------------
    def run(
        self,
        sample: Sample | None,
        policy: SandboxPolicy,
        *,
        on_event: Callable[[Event], None] | None = None,
    ) -> Trace:
        traces = self._load_traces(sample)
        first = traces[0]
        chosen = sample if _valid_sample(sample) else _as_sample(first.sample)

        builder = EventBuilder(max_events=policy.max_events, source="replay", on_event=on_event)
        builder.start()
        offset = 0.0
        previous_ts = -1.0
        for index, trace in enumerate(traces):
            events = sorted(trace.events, key=lambda ev: (ev.ts, ev.id))
            for event in events:
                emitted = builder.emit(
                    event.category,
                    event.action,
                    ts=offset + event.ts,
                    pid=event.pid,
                    tid=event.tid,
                    ppid=event.ppid,
                    image=event.image,
                    target=event.target,
                    args=dict(event.args),
                    source=event.source,
                    confidence=event.confidence,
                )
                if self.realtime and emitted is not None:
                    gap = emitted.ts - previous_ts if previous_ts >= 0 else 0.0
                    time.sleep(min(0.05, max(0.0, gap)))
                if emitted is not None:
                    previous_ts = emitted.ts
            if events:
                offset += max(ev.ts for ev in events) + (self.trace_gap_s if index + 1 < len(traces) else 0.0)

        sandbox_src = first.sandbox
        isolation = list(sandbox_src.isolation)
        if "replay" not in isolation:
            isolation.append("replay")
        sandbox = SandboxInfo(
            host=sandbox_src.host,
            isolation=isolation,
            limits=policy.limits(),
            started_at=sandbox_src.started_at,
            ended_at=traces[-1].sandbox.ended_at or sandbox_src.ended_at,
            terminated_by=traces[-1].sandbox.terminated_by or sandbox_src.terminated_by or "exited",
        )
        trace = build_trace(
            sample=chosen,
            engine_version=__version__,
            backend="replay",
            policy=policy.name,
            sandbox=sandbox,
            builder=builder,
            extra={
                "replay": {
                    "sources": [t.trace_id for t in traces],
                    "source_count": len(traces),
                    "realtime": self.realtime,
                }
            },
        )
        return trace


BACKEND = ReplayBackend()
