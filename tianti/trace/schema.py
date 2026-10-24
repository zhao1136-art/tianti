"""行为轨迹契约：tianti.trace/1。

这是引擎的中央契约：L1 执行层产出它，L2/L3/L4 消费它。
字段变更必须 bump SCHEMA_ID，并同步 docs/TRACE_SCHEMA.md。
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core.errors import TraceError

SCHEMA_ID = "tianti.trace/1"
TRACE_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

CATEGORIES: dict[str, tuple[str, ...]] = {
    "process": ("create", "exit", "suspend", "resume"),
    "thread": ("create", "remote_create", "exit"),
    "image": ("load", "unload"),
    "file": ("create", "write", "read", "delete", "rename", "set_attr", "open"),
    "registry": ("set", "create", "delete", "query", "rename"),
    "network": ("connect", "listen", "dns", "send", "recv", "close"),
    "service": ("create", "start", "config", "delete"),
    "scheduled_task": ("create", "run", "delete"),
    "token": ("impersonate", "elevate", "adjust"),
    "memory": ("alloc", "protect", "map", "write", "free"),
    "api": ("call",),
    "security": ("amsi", "etw", "defender", "other"),
}
CONFIDENCES = ("high", "medium", "low")
TERMINATIONS = ("exited", "timeout", "killed", "error", "unknown")


def new_trace_id(now: datetime | None = None) -> str:
    """生成稳定格式的 trace_id：YYYYMMDDThhmmssZ-xxxxxxxx。"""
    moment = now or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)


def _iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@dataclass
class Event:
    """一条行为事件。ts 为沙箱启动后的相对秒数。"""

    id: str
    ts: float
    category: str
    action: str
    pid: int | None = None
    tid: int | None = None
    ppid: int | None = None
    image: str | None = None
    target: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "ts": round(float(self.ts), 6)}
        if self.pid is not None:
            out["pid"] = int(self.pid)
        if self.tid is not None:
            out["tid"] = int(self.tid)
        if self.ppid is not None:
            out["ppid"] = int(self.ppid)
        if self.image is not None:
            out["image"] = str(self.image)
        out["category"] = self.category
        out["action"] = self.action
        if self.target is not None:
            out["target"] = str(self.target)
        if self.args:
            out["args"] = self.args
        out["source"] = self.source
        out["confidence"] = self.confidence
        return out

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Event":
        return cls(
            id=str(payload.get("id", "")),
            ts=float(payload.get("ts", 0.0)),
            category=str(payload.get("category", "")),
            action=str(payload.get("action", "")),
            pid=payload.get("pid"),
            tid=payload.get("tid"),
            ppid=payload.get("ppid"),
            image=payload.get("image"),
            target=payload.get("target"),
            args=dict(payload.get("args") or {}),
            source=str(payload.get("source", "unknown")),
            confidence=str(payload.get("confidence", "medium")),
        )


@dataclass
class SampleInfo:
    name: str
    sha256: str
    size: int
    type: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "sha256": self.sha256, "size": self.size, "type": self.type}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SampleInfo":
        return cls(
            name=str(payload.get("name", "")),
            sha256=str(payload.get("sha256", "")),
            size=int(payload.get("size", 0) or 0),
            type=str(payload.get("type", "unknown")),
        )


@dataclass
class EngineInfo:
    version: str
    backend: str
    policy: str

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "backend": self.backend, "policy": self.policy}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EngineInfo":
        return cls(
            version=str(payload.get("version", "")),
            backend=str(payload.get("backend", "")),
            policy=str(payload.get("policy", "")),
        )


@dataclass
class SandboxLimits:
    timeout_s: int = 20
    mem_mb: int = 512
    cpu_s: int = 10
    network: str = "blocked"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timeout_s": self.timeout_s,
            "mem_mb": self.mem_mb,
            "cpu_s": self.cpu_s,
            "network": self.network,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SandboxLimits":
        return cls(
            timeout_s=int(payload.get("timeout_s", 20)),
            mem_mb=int(payload.get("mem_mb", 512)),
            cpu_s=int(payload.get("cpu_s", 10)),
            network=str(payload.get("network", "blocked")),
        )


@dataclass
class SandboxInfo:
    host: str = ""
    isolation: list[str] = field(default_factory=list)
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    started_at: str = ""
    ended_at: str = ""
    terminated_by: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "isolation": list(self.isolation),
            "limits": self.limits.to_dict(),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "terminated_by": self.terminated_by,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SandboxInfo":
        return cls(
            host=str(payload.get("host", "")),
            isolation=[str(x) for x in (payload.get("isolation") or [])],
            limits=SandboxLimits.from_dict(dict(payload.get("limits") or {})),
            started_at=str(payload.get("started_at", "")),
            ended_at=str(payload.get("ended_at", "")),
            terminated_by=str(payload.get("terminated_by", "unknown")),
        )


@dataclass
class TraceSummary:
    processes: int = 0
    threads: int = 0
    file_writes: int = 0
    file_drops: int = 0
    reg_sets: int = 0
    net_connects: int = 0
    dns_queries: int = 0
    services: int = 0
    tasks: int = 0
    apis: int = 0
    first_seen: float = 0.0
    event_count: int = 0
    dropped: int = 0
    truncated: bool = False
    dropped_files: list[str] = field(default_factory=list)

    @classmethod
    def from_events(cls, events: list[Event], *, dropped: int = 0) -> "TraceSummary":
        summary = cls(event_count=len(events), dropped=dropped, truncated=dropped > 0)
        if events:
            summary.first_seen = round(min(ev.ts for ev in events), 6)
        for ev in events:
            if ev.category == "process" and ev.action == "create":
                summary.processes += 1
            elif ev.category == "thread":
                summary.threads += 1
            elif ev.category == "file" and ev.action == "write":
                summary.file_writes += 1
            elif ev.category == "file" and ev.action == "create":
                summary.file_drops += 1
            elif ev.category == "registry" and ev.action == "set":
                summary.reg_sets += 1
            elif ev.category == "network" and ev.action == "connect":
                summary.net_connects += 1
            elif ev.category == "network" and ev.action == "dns":
                summary.dns_queries += 1
            elif ev.category == "service":
                summary.services += 1
            elif ev.category == "scheduled_task":
                summary.tasks += 1
            elif ev.category == "api":
                summary.apis += 1
        return summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "processes": self.processes,
            "threads": self.threads,
            "file_writes": self.file_writes,
            "file_drops": self.file_drops,
            "reg_sets": self.reg_sets,
            "net_connects": self.net_connects,
            "dns_queries": self.dns_queries,
            "services": self.services,
            "tasks": self.tasks,
            "apis": self.apis,
            "first_seen": self.first_seen,
            "event_count": self.event_count,
            "dropped": self.dropped,
            "truncated": self.truncated,
            "dropped_files": list(self.dropped_files),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TraceSummary":
        return cls(
            processes=int(payload.get("processes", 0)),
            threads=int(payload.get("threads", 0)),
            file_writes=int(payload.get("file_writes", 0)),
            file_drops=int(payload.get("file_drops", 0)),
            reg_sets=int(payload.get("reg_sets", 0)),
            net_connects=int(payload.get("net_connects", 0)),
            dns_queries=int(payload.get("dns_queries", 0)),
            services=int(payload.get("services", 0)),
            tasks=int(payload.get("tasks", 0)),
            apis=int(payload.get("apis", 0)),
            first_seen=float(payload.get("first_seen", 0.0)),
            event_count=int(payload.get("event_count", 0)),
            dropped=int(payload.get("dropped", 0)),
            truncated=bool(payload.get("truncated", False)),
            dropped_files=[str(x) for x in (payload.get("dropped_files") or [])],
        )


@dataclass
class Trace:
    trace_id: str
    sample: SampleInfo
    engine: EngineInfo
    sandbox: SandboxInfo
    events: list[Event] = field(default_factory=list)
    summary: TraceSummary = field(default_factory=TraceSummary)
    created_at: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "trace_id": self.trace_id,
            "schema": SCHEMA_ID,
            "created_at": self.created_at or _iso_now(),
            "sample": self.sample.to_dict(),
            "engine": self.engine.to_dict(),
            "sandbox": self.sandbox.to_dict(),
            "events": [ev.to_dict() for ev in self.events],
            "summary": self.summary.to_dict(),
        }
        if self.extra:
            out["extra"] = self.extra
        return out

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Trace":
        events = [Event.from_dict(ev) for ev in (payload.get("events") or []) if isinstance(ev, dict)]
        return cls(
            trace_id=str(payload.get("trace_id", "")),
            sample=SampleInfo.from_dict(dict(payload.get("sample") or {})),
            engine=EngineInfo.from_dict(dict(payload.get("engine") or {})),
            sandbox=SandboxInfo.from_dict(dict(payload.get("sandbox") or {})),
            events=events,
            summary=TraceSummary.from_dict(dict(payload.get("summary") or {})),
            created_at=str(payload.get("created_at", "")),
            extra=dict(payload.get("extra") or {}),
        )

    def events_of(self, category: str) -> list[Event]:
        return [ev for ev in self.events if ev.category == category]

    def validate(self) -> None:
        errors = validate_payload(self.to_dict())
        if errors:
            raise TraceError("Trace 校验失败: " + "; ".join(errors[:8]), errors=errors)

    def sort_events(self) -> None:
        """稳定按时间排序（相同 ts 保留原 id 顺序）。"""
        self.events.sort(key=lambda ev: (ev.ts, ev.id))


def validate_payload(payload: Any) -> list[str]:
    """轻量结构校验（零依赖，不依赖 jsonschema）。返回错误列表。"""
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["trace payload 必须是 JSON 对象"]

    if payload.get("schema") != SCHEMA_ID:
        errors.append(f"schema 必须是 {SCHEMA_ID!r}，实际 {payload.get('schema')!r}")

    trace_id = payload.get("trace_id")
    if not isinstance(trace_id, str) or not TRACE_ID_RE.match(trace_id):
        errors.append(f"trace_id 非法: {trace_id!r}")

    sample = payload.get("sample")
    if not isinstance(sample, dict):
        errors.append("sample 必须是对象")
    else:
        if not isinstance(sample.get("name"), str) or not sample.get("name"):
            errors.append("sample.name 必须是非空字符串")
        sha = sample.get("sha256")
        if not isinstance(sha, str) or not SHA256_RE.match(sha):
            errors.append(f"sample.sha256 必须是 64 位小写十六进制: {sha!r}")
        size = sample.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            errors.append(f"sample.size 必须是非负整数: {size!r}")
        if not isinstance(sample.get("type"), str) or not sample.get("type"):
            errors.append("sample.type 必须是非空字符串")

    for key in ("engine", "sandbox", "summary"):
        if not isinstance(payload.get(key), dict):
            errors.append(f"{key} 必须是对象")

    events = payload.get("events")
    if not isinstance(events, list):
        errors.append("events 必须是数组")
        return errors

    seen: set[str] = set()
    last_ts = -1.0
    for index, event in enumerate(events):
        where = f"events[{index}]"
        if not isinstance(event, dict):
            errors.append(f"{where} 必须是对象")
            continue
        event_id = event.get("id")
        if not isinstance(event_id, str) or not event_id:
            errors.append(f"{where}.id 必须是非空字符串")
        elif event_id in seen:
            errors.append(f"{where}.id 重复: {event_id}")
        else:
            seen.add(event_id)
        ts = event.get("ts")
        if not isinstance(ts, (int, float)) or isinstance(ts, bool) or float(ts) < 0:
            errors.append(f"{where}.ts 必须是非负数字")
        else:
            if float(ts) < last_ts:
                errors.append(f"{where}.ts 未按时间升序: {ts} < {last_ts}")
            last_ts = float(ts)
        category = event.get("category")
        if category not in CATEGORIES:
            errors.append(f"{where}.category 未知: {category!r}")
            continue
        action = event.get("action")
        if action not in CATEGORIES[category]:
            errors.append(f"{where}.action 对 {category} 非法: {action!r}")
        confidence = event.get("confidence", "medium")
        if confidence not in CONFIDENCES:
            errors.append(f"{where}.confidence 非法: {confidence!r}")
        if "args" in event and not isinstance(event.get("args"), dict):
            errors.append(f"{where}.args 必须是对象")
        if "pid" in event and event["pid"] is not None and (
            not isinstance(event["pid"], int) or isinstance(event["pid"], bool)
        ):
            errors.append(f"{where}.pid 必须是整数或 null")
        if not isinstance(event.get("source", "unknown"), str):
            errors.append(f"{where}.source 必须是字符串")
    return errors


def json_schema() -> dict[str, Any]:
    """返回文档用途的 JSON Schema（draft-07）。"""
    event_schema = {
        "type": "object",
        "required": ["id", "ts", "category", "action", "source", "confidence"],
        "properties": {
            "id": {"type": "string", "minLength": 1},
            "ts": {"type": "number", "minimum": 0},
            "category": {"type": "string", "enum": sorted(CATEGORIES)},
            "action": {"type": "string"},
            "pid": {"type": ["integer", "null"]},
            "tid": {"type": ["integer", "null"]},
            "ppid": {"type": ["integer", "null"]},
            "image": {"type": ["string", "null"]},
            "target": {"type": ["string", "null"]},
            "args": {"type": "object"},
            "source": {"type": "string"},
            "confidence": {"type": "string", "enum": list(CONFIDENCES)},
        },
        "additionalProperties": True,
    }
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://tianti.local/schema/tianti.trace/1.json",
        "title": "tianti.trace/1",
        "type": "object",
        "required": [
            "trace_id",
            "schema",
            "created_at",
            "sample",
            "engine",
            "sandbox",
            "events",
            "summary",
        ],
        "properties": {
            "trace_id": {"type": "string", "pattern": TRACE_ID_RE.pattern},
            "schema": {"const": SCHEMA_ID},
            "created_at": {"type": "string"},
            "sample": {
                "type": "object",
                "required": ["name", "sha256", "size", "type"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "sha256": {"type": "string", "pattern": SHA256_RE.pattern},
                    "size": {"type": "integer", "minimum": 0},
                    "type": {"type": "string"},
                },
            },
            "engine": {
                "type": "object",
                "required": ["version", "backend", "policy"],
                "properties": {
                    "version": {"type": "string"},
                    "backend": {"type": "string"},
                    "policy": {"type": "string"},
                },
            },
            "sandbox": {
                "type": "object",
                "required": ["host", "isolation", "limits", "started_at", "ended_at", "terminated_by"],
            },
            "events": {"type": "array", "items": event_schema},
            "summary": {"type": "object"},
        },
        "additionalProperties": True,
    }


def dumps(trace: Trace, *, indent: int = 2) -> str:
    return json.dumps(trace.to_dict(), ensure_ascii=False, indent=indent)


def save(trace: Trace, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dumps(trace), encoding="utf-8")
    return target


def loads(text: str) -> Trace:
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise TraceError(f"Trace JSON 解析失败: {exc}") from exc
    return _trace_from_payload(payload)


def load(path: str | Path) -> Trace:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise TraceError(f"Trace 读取失败: {p}: {exc}", path=str(p)) from exc
    return loads(text)


def _trace_from_payload(payload: Any) -> Trace:
    errors = validate_payload(payload)
    if errors:
        raise TraceError("Trace 校验失败: " + "; ".join(errors[:8]), errors=errors)
    return Trace.from_dict(payload)
