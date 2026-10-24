"""判定契约：Verdict（L4 输出，报告与 API 消费）。

注意：本模块不依赖 rules/detect，只依赖 dataclass，避免循环 import。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

VERDICTS = ("clean", "suspicious", "malicious")


@dataclass
class ScoreItem:
    """评分明细的一项，必须可追溯。"""

    kind: str  # capability | detector | static
    ref: str  # 规则名 / 检测器 id / 静态信号名
    score: float
    detail: str = ""
    suppressed: bool = False
    suppress_reason: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": self.kind,
            "ref": self.ref,
            "score": round(float(self.score), 3),
            "detail": self.detail,
            "suppressed": self.suppressed,
            "evidence": list(self.evidence),
        }
        if self.suppress_reason:
            out["suppress_reason"] = self.suppress_reason
        return out


@dataclass
class Verdict:
    verdict: str
    score: float
    confidence: float
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    items: list[ScoreItem] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "score": round(float(self.score), 3),
            "confidence": round(float(self.confidence), 3),
            "tactics": list(self.tactics),
            "techniques": list(self.techniques),
            "items": [item.to_dict() for item in self.items],
            "suppressed": list(self.suppressed),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Verdict":
        items = [
            ScoreItem(
                kind=str(x.get("kind", "")),
                ref=str(x.get("ref", "")),
                score=float(x.get("score", 0.0)),
                detail=str(x.get("detail", "")),
                suppressed=bool(x.get("suppressed", False)),
                suppress_reason=str(x.get("suppress_reason", "")),
                evidence=[str(e) for e in (x.get("evidence") or [])],
            )
            for x in (payload.get("items") or [])
            if isinstance(x, dict)
        ]
        return cls(
            verdict=str(payload.get("verdict", "clean")),
            score=float(payload.get("score", 0.0)),
            confidence=float(payload.get("confidence", 0.0)),
            tactics=[str(t) for t in (payload.get("tactics") or [])],
            techniques=[str(t) for t in (payload.get("techniques") or [])],
            items=items,
            suppressed=[str(s) for s in (payload.get("suppressed") or [])],
            notes=[str(n) for n in (payload.get("notes") or [])],
        )


def decide(score: float, *, critical_hit: bool, clean_below: float, malicious_at: float) -> str:
    """阈值判定；critical 命中至少 suspicious 起步，达到阈值即 malicious。"""
    if critical_hit and score >= malicious_at * 0.5:
        return "malicious"
    if score >= malicious_at:
        return "malicious"
    if score >= clean_below:
        return "suspicious"
    if critical_hit:
        return "suspicious"
    return "clean"


def confidence_from(score: float, evidence_count: int, source_quality: float, suppressed_ratio: float) -> float:
    """证据数量 + 来源保真度 + 抑制比例 -> 置信度（0..1）。"""
    base = min(0.55, 0.20 + 0.05 * max(0, evidence_count))
    quality = 0.25 * max(0.0, min(1.0, source_quality))
    strength = min(0.20, abs(score) / 200.0)
    penalty = 0.25 * max(0.0, min(1.0, suppressed_ratio))
    return round(max(0.0, min(1.0, base + quality + strength - penalty)), 3)
