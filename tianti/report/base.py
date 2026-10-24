"""扫描结果模型 ScanResult（L5 交付层统一输入）。

所有报告渲染器（JSON / HTML）和本地 API 都消费同一个 ScanResult：
样本信息 + 静态信号 + 沙箱轨迹摘要 + 规则命中 + 检测器命中 + 判定 + 备注。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..core.errors import ReportError
from ..core.verdict import ScoreItem, Verdict
from ..detect.base import DetectorHit
from ..rules.base import RuleMatch
from ..trace.schema import Trace

RESULT_SCHEMA = "tianti.result/1"


def _iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


@dataclass
class ScanResult:
    """一次扫描/回放的完整结果（可 JSON 落盘并可再次渲染报告）。"""

    sample: dict[str, Any] = field(default_factory=dict)
    static: dict[str, Any] = field(default_factory=dict)
    trace: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    matches: list[RuleMatch] = field(default_factory=list)
    hits: list[DetectorHit] = field(default_factory=list)
    verdict: Verdict = field(
        default_factory=lambda: Verdict(verdict="clean", score=0.0, confidence=0.0)
    )
    notes: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    schema: str = RESULT_SCHEMA

    # ------------------------------------------------------------------ 便捷属性
    @property
    def sample_name(self) -> str:
        return str(self.sample.get("name") or "unknown")

    @property
    def verdict_name(self) -> str:
        return str(self.verdict.verdict) if self.verdict else "clean"

    @property
    def trace_id(self) -> str:
        return str(self.trace.get("trace_id", ""))

    def event_by_id(self) -> dict[str, dict[str, Any]]:
        return {str(ev.get("id")): ev for ev in self.events if ev.get("id")}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "created_at": self.created_at or _iso_now(),
            "sample": dict(self.sample),
            "static": dict(self.static),
            "trace": dict(self.trace),
            "events": list(self.events),
            "matches": [match.to_dict() for match in self.matches],
            "hits": [hit.to_dict() for hit in self.hits],
            "verdict": self.verdict.to_dict(),
            "notes": list(self.notes),
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanResult":
        if not isinstance(payload, dict):
            raise ReportError("ScanResult 必须是 JSON 对象")
        schema = payload.get("schema")
        if schema is not None and schema != RESULT_SCHEMA:
            raise ReportError(
                f"结果 schema 不兼容：期望 {RESULT_SCHEMA}，实际 {schema!r}",
                schema=schema,
            )
        matches = [
            item if isinstance(item, RuleMatch) else RuleMatch.from_dict(item)
            for item in (payload.get("matches") or [])
            if isinstance(item, (RuleMatch, dict))
        ]
        hits = [
            item if isinstance(item, DetectorHit) else DetectorHit.from_dict(item)
            for item in (payload.get("hits") or [])
            if isinstance(item, (DetectorHit, dict))
        ]
        verdict_payload = payload.get("verdict")
        if isinstance(verdict_payload, Verdict):
            verdict = verdict_payload
        elif isinstance(verdict_payload, dict):
            verdict = Verdict.from_dict(verdict_payload)
        else:
            verdict = Verdict(verdict="clean", score=0.0, confidence=0.0)
        return cls(
            schema=schema or RESULT_SCHEMA,
            created_at=str(payload.get("created_at", "")),
            sample=dict(payload.get("sample") or {}),
            static=dict(payload.get("static") or {}),
            trace=dict(payload.get("trace") or {}),
            events=_dict_list(payload.get("events")),
            matches=matches,
            hits=hits,
            verdict=verdict,
            notes=[str(note) for note in (payload.get("notes") or [])],
            extra=dict(payload.get("extra") or {}),
        )

    @classmethod
    def from_trace(
        cls,
        trace: Trace,
        *,
        static: dict[str, Any] | None = None,
        matches: Iterable[RuleMatch] | None = None,
        hits: Iterable[DetectorHit] | None = None,
        verdict: Verdict | None = None,
        notes: Iterable[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> "ScanResult":
        """从行为轨迹构造结果骨架（规则/检测器/判定由调用方补充）。"""
        payload = trace.to_dict()
        return cls(
            sample=dict(payload.get("sample") or {}),
            static=dict(static or {}),
            trace={
                "trace_id": payload.get("trace_id", ""),
                "created_at": payload.get("created_at", ""),
                "engine": dict(payload.get("engine") or {}),
                "sandbox": dict(payload.get("sandbox") or {}),
                "summary": dict(payload.get("summary") or {}),
                "extra": dict(payload.get("extra") or {}),
            },
            events=_dict_list(payload.get("events")),
            matches=list(matches or []),
            hits=list(hits or []),
            verdict=verdict or Verdict(verdict="clean", score=0.0, confidence=0.0),
            notes=[str(note) for note in (notes or [])],
            extra=dict(extra or {}),
        )

    # ------------------------------------------------------------------ 落盘/读取
    def dumps(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def save(self, path: str | Path, *, indent: int = 2) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.dumps(indent=indent) + "\n", encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path) -> "ScanResult":
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReportError(f"结果读取失败: {p}: {exc}", path=str(p)) from exc
        try:
            payload = json.loads(text)
        except ValueError as exc:
            raise ReportError(f"结果 JSON 解析失败: {p}: {exc}", path=str(p)) from exc
        return cls.from_dict(payload)

    def score_items(self) -> list[ScoreItem]:
        return list(self.verdict.items) if self.verdict else []


def load(path: str | Path) -> ScanResult:
    """模块级读取便捷函数。"""
    return ScanResult.load(path)


def save(result: ScanResult, path: str | Path, *, indent: int = 2) -> Path:
    """模块级落盘便捷函数。"""
    return result.save(path, indent=indent)
