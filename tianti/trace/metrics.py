"""派生指标：从 Trace 计算规则/检测器/报告共用的统计量。

只依赖 tianti.trace 契约，不做匹配与判定。所有输出 JSON 可序列化。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .schema import Event, Trace


@dataclass
class EntropyStats:
    count: int = 0
    min: float = 0.0
    max: float = 0.0
    mean: float = 0.0
    high_count: int = 0
    total_bytes: int = 0
    threshold: float = 7.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "min": round(self.min, 4),
            "max": round(self.max, 4),
            "mean": round(self.mean, 4),
            "high_count": self.high_count,
            "total_bytes": self.total_bytes,
            "threshold": self.threshold,
        }


@dataclass
class Timeline:
    bucket_s: float = 1.0
    counts: list[int] = field(default_factory=list)
    start: float = 0.0
    end: float = 0.0
    peak_bucket: int = -1
    peak_count: int = 0

    @property
    def total(self) -> int:
        return sum(self.counts)

    def bucket_of(self, ts: float) -> int:
        return int(ts // self.bucket_s) if self.bucket_s > 0 else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "bucket_s": self.bucket_s,
            "counts": list(self.counts),
            "start": round(self.start, 6),
            "end": round(self.end, 6),
            "peak_bucket": self.peak_bucket,
            "peak_count": self.peak_count,
        }


@dataclass
class TraceMetrics:
    trace_id: str = ""
    event_count: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_action: dict[str, int] = field(default_factory=dict)
    process_event_counts: dict[int, int] = field(default_factory=dict)
    process_count: int = 0
    distinct_targets: dict[str, int] = field(default_factory=dict)
    file_writes: int = 0
    file_write_bytes: int = 0
    file_write_paths: list[str] = field(default_factory=list)
    file_write_entropy: EntropyStats = field(default_factory=EntropyStats)
    dropped_files: int = 0
    registry_sets: int = 0
    registry_keys: list[str] = field(default_factory=list)
    net_connects: int = 0
    net_targets: dict[str, int] = field(default_factory=dict)
    net_ports: list[int] = field(default_factory=list)
    timeline: Timeline = field(default_factory=Timeline)
    window_s: float = 10.0
    max_writes_in_window: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "event_count": self.event_count,
            "by_category": dict(sorted(self.by_category.items())),
            "by_action": dict(sorted(self.by_action.items())),
            "process_event_counts": {str(k): v for k, v in sorted(self.process_event_counts.items())},
            "process_count": self.process_count,
            "distinct_targets": dict(sorted(self.distinct_targets.items())),
            "file_writes": self.file_writes,
            "file_write_bytes": self.file_write_bytes,
            "file_write_paths": list(self.file_write_paths),
            "file_write_entropy": self.file_write_entropy.to_dict(),
            "dropped_files": self.dropped_files,
            "registry_sets": self.registry_sets,
            "registry_keys": list(self.registry_keys),
            "net_connects": self.net_connects,
            "net_targets": dict(sorted(self.net_targets.items())),
            "net_ports": list(self.net_ports),
            "timeline": self.timeline.to_dict(),
            "window_s": self.window_s,
            "max_writes_in_window": self.max_writes_in_window,
            "first_ts": round(self.first_ts, 6),
            "last_ts": round(self.last_ts, 6),
            "duration": round(self.duration, 6),
        }


# ---------------------------------------------------------------------------
# 单指标函数（规则/检测器可直接复用）
# ---------------------------------------------------------------------------

def process_event_counts(trace: Trace) -> dict[int, int]:
    counts: dict[int, int] = {}
    for event in trace.events:
        if event.pid is None:
            continue
        counts[int(event.pid)] = counts.get(int(event.pid), 0) + 1
    return counts


def distinct_targets(trace: Trace, category: str | None = None) -> list[str]:
    seen: set[str] = set()
    for event in trace.events:
        if category is not None and event.category != category:
            continue
        if event.target:
            seen.add(event.target)
    return sorted(seen)


def file_write_events(trace: Trace) -> list[Event]:
    return [ev for ev in trace.events if ev.category == "file" and ev.action == "write"]


def file_write_entropy_stats(trace: Trace, *, threshold: float = 7.0) -> EntropyStats:
    values: list[float] = []
    total_bytes = 0
    for event in file_write_events(trace):
        raw = event.args.get("entropy")
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            values.append(float(raw))
        size = event.args.get("size")
        if isinstance(size, int) and not isinstance(size, bool) and size > 0:
            total_bytes += size
    stats = EntropyStats(count=len(values), threshold=threshold, total_bytes=total_bytes)
    if values:
        stats.min = min(values)
        stats.max = max(values)
        stats.mean = sum(values) / len(values)
        stats.high_count = sum(1 for v in values if v >= threshold)
    return stats


def network_targets(trace: Trace) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in trace.events:
        if event.category == "network" and event.action in ("connect", "dns") and event.target:
            counts[event.target] = counts.get(event.target, 0) + 1
    return counts


def timeline_buckets(trace: Trace, *, bucket_s: float = 1.0) -> Timeline:
    bucket = bucket_s if bucket_s > 0 else 1.0
    timeline = Timeline(bucket_s=bucket)
    if not trace.events:
        return timeline
    timeline.start = float(min(ev.ts for ev in trace.events))
    timeline.end = float(max(ev.ts for ev in trace.events))
    size = int(timeline.end // bucket) + 1
    timeline.counts = [0] * size
    for event in trace.events:
        index = int(float(event.ts) // bucket)
        if index < 0:
            index = 0
        if index >= len(timeline.counts):
            timeline.counts.extend([0] * (index + 1 - len(timeline.counts)))
        timeline.counts[index] += 1
    peak_index = max(range(len(timeline.counts)), key=lambda i: timeline.counts[i])
    timeline.peak_bucket = peak_index
    timeline.peak_count = timeline.counts[peak_index]
    return timeline


def max_events_in_window(events: Iterable[Event], *, window_s: float) -> int:
    """滑动时间窗内最大事件数（events 需已按 ts 升序）。"""
    ordered = sorted(events, key=lambda ev: ev.ts)
    if not ordered or window_s <= 0:
        return 0
    best = 0
    left = 0
    for right, event in enumerate(ordered):
        while event.ts - ordered[left].ts > window_s:
            left += 1
        best = max(best, right - left + 1)
    return best


# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

def compute(
    trace: Trace,
    *,
    bucket_s: float = 1.0,
    window_s: float = 10.0,
    entropy_threshold: float = 7.0,
) -> TraceMetrics:
    result = TraceMetrics(trace_id=trace.trace_id, event_count=len(trace.events))

    for event in trace.events:
        result.by_category[event.category] = result.by_category.get(event.category, 0) + 1
        result.by_action[event.action] = result.by_action.get(event.action, 0) + 1

    result.process_event_counts = process_event_counts(trace)
    result.process_count = sum(
        1 for ev in trace.events if ev.category == "process" and ev.action == "create"
    )

    for category in ("file", "registry", "network", "process", "service", "scheduled_task", "image", "memory"):
        targets = distinct_targets(trace, category)
        if targets:
            result.distinct_targets[category] = len(targets)

    writes = file_write_events(trace)
    result.file_writes = len(writes)
    result.file_write_paths = sorted({ev.target for ev in writes if ev.target})
    result.file_write_entropy = file_write_entropy_stats(trace, threshold=entropy_threshold)
    result.file_write_bytes = result.file_write_entropy.total_bytes

    result.dropped_files = sum(
        1 for ev in trace.events if ev.category == "file" and ev.action == "create"
    )

    reg_sets = [ev for ev in trace.events if ev.category == "registry" and ev.action == "set"]
    result.registry_sets = len(reg_sets)
    result.registry_keys = sorted({ev.target for ev in reg_sets if ev.target})

    result.net_targets = network_targets(trace)
    connects = [ev for ev in trace.events if ev.category == "network" and ev.action == "connect"]
    result.net_connects = len(connects)
    ports: set[int] = set()
    for event in connects:
        port = event.args.get("remote_port") or event.args.get("port")
        if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
            ports.add(port)
        elif event.target and ":" in event.target:
            tail = event.target.rsplit(":", 1)[-1]
            if tail.isdigit():
                ports.add(int(tail))
    result.net_ports = sorted(ports)

    result.timeline = timeline_buckets(trace, bucket_s=bucket_s)
    result.window_s = window_s
    result.max_writes_in_window = max_events_in_window(writes, window_s=window_s)

    if trace.events:
        result.first_ts = float(min(ev.ts for ev in trace.events))
        result.last_ts = float(max(ev.ts for ev in trace.events))
        result.duration = result.last_ts - result.first_ts
    return result
