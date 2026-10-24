"""Trace 构造工具：EventBuilder（事件去重、编号、裁剪）+ build_trace。

约定：
- 事件 id 在单次 trace 内连续且稳定：e00001, e00002, ...
- ts 为沙箱启动后的相对秒数；不传则由 builder 用 monotonic 计算。
- 超过 max_events 后丢弃事件并计数（summary.dropped / truncated 置位）。
"""

from __future__ import annotations

import time
from typing import Any, Callable

from ..core.model import Sample
from .schema import (
    CATEGORIES,
    CONFIDENCES,
    EngineInfo,
    Event,
    SampleInfo,
    SandboxInfo,
    Trace,
    TraceSummary,
    new_trace_id,
)


class EventBuilder:
    def __init__(
        self,
        *,
        max_events: int = 20000,
        source: str = "unknown",
        on_event: Callable[[Event], None] | None = None,
    ) -> None:
        self.max_events = max(1, int(max_events))
        self.source = source
        self.on_event = on_event
        self.events: list[Event] = []
        self.dropped = 0
        self._seq = 0
        self._t0: float | None = None

    def start(self) -> "EventBuilder":
        self._t0 = time.monotonic()
        return self

    def elapsed(self) -> float:
        if self._t0 is None:
            return 0.0
        return time.monotonic() - self._t0

    def emit(
        self,
        category: str,
        action: str,
        *,
        ts: float | None = None,
        pid: int | None = None,
        tid: int | None = None,
        ppid: int | None = None,
        image: str | None = None,
        target: str | None = None,
        args: dict[str, Any] | None = None,
        source: str | None = None,
        confidence: str | None = None,
    ) -> Event | None:
        """追加一条事件；超上限返回 None 并累加 dropped。"""
        if category not in CATEGORIES:
            raise ValueError(f"未知事件类别: {category}")
        if action not in CATEGORIES[category]:
            raise ValueError(f"类别 {category} 不支持动作 {action}")
        if len(self.events) >= self.max_events:
            self.dropped += 1
            return None
        self._seq += 1
        event = Event(
            id=f"e{self._seq:05d}",
            ts=round(float(ts) if ts is not None else self.elapsed(), 6),
            category=category,
            action=action,
            pid=pid,
            tid=tid,
            ppid=ppid,
            image=image,
            target=target,
            args=dict(args or {}),
            source=source or self.source,
            confidence=confidence or "medium",
        )
        self.events.append(event)
        if self.on_event is not None:
            self.on_event(event)
        return event

    def extend(self, events: list[Event]) -> None:
        for event in events:
            if len(self.events) >= self.max_events:
                self.dropped += 1
                continue
            self._seq += 1
            self.events.append(
                Event(
                    id=f"e{self._seq:05d}",
                    ts=event.ts,
                    category=event.category,
                    action=event.action,
                    pid=event.pid,
                    tid=event.tid,
                    ppid=event.ppid,
                    image=event.image,
                    target=event.target,
                    args=dict(event.args),
                    source=event.source,
                    confidence=event.confidence,
                )
            )

    def build_summary(self) -> TraceSummary:
        return TraceSummary.from_events(self.events, dropped=self.dropped)


def build_trace(
    *,
    sample: Sample,
    engine_version: str,
    backend: str,
    policy: str,
    sandbox: SandboxInfo,
    builder: EventBuilder,
    extra: dict[str, Any] | None = None,
) -> Trace:
    """把 builder 的事件固化成不可变契约对象，并补齐 summary。"""
    trace = Trace(
        trace_id=new_trace_id(),
        sample=SampleInfo(
            name=sample.name,
            sha256=sample.sha256,
            size=sample.size,
            type=sample.type.value,
        ),
        engine=EngineInfo(version=engine_version, backend=backend, policy=policy),
        sandbox=sandbox,
        events=list(builder.events),
        summary=builder.build_summary(),
        extra=dict(extra or {}),
    )
    trace.sort_events()
    trace.validate()
    return trace
