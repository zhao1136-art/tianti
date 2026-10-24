"""检测器契约：DetectorSpec（声明）+ DetectorHit（命中）。

检测器可以是 YAML DSL 编译出来的谓词，也可以是 Python 状态机，
但输出必须统一为 DetectorHit，且 evidence 必须引用 trace 事件 id。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class DetectorSpec:
    id: str
    name: str = ""
    tactic: str = ""
    technique: str = ""
    severity: str = "medium"
    score: float = 10.0
    window_s: float = 0.0
    source_path: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic,
            "technique": self.technique,
            "severity": self.severity,
            "score": self.score,
            "window_s": self.window_s,
            "source_path": self.source_path,
        }


@dataclass
class DetectorHit:
    detector_id: str
    name: str = ""
    severity: str = "medium"
    tactic: str = ""
    technique: str = ""
    score: float = 0.0
    evidence: list[str] = field(default_factory=list)
    detail: str = ""
    suppressed: bool = False
    suppress_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "detector_id": self.detector_id,
            "name": self.name,
            "severity": self.severity,
            "tactic": self.tactic,
            "technique": self.technique,
            "score": round(float(self.score), 3),
            "evidence": list(self.evidence),
            "detail": self.detail,
            "suppressed": self.suppressed,
        }
        if self.suppress_reason:
            out["suppress_reason"] = self.suppress_reason
        return out

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DetectorHit":
        return cls(
            detector_id=str(payload.get("detector_id", "")),
            name=str(payload.get("name", "")),
            severity=str(payload.get("severity", "medium")),
            tactic=str(payload.get("tactic", "")),
            technique=str(payload.get("technique", "")),
            score=float(payload.get("score", 0.0)),
            evidence=[str(x) for x in (payload.get("evidence") or [])],
            detail=str(payload.get("detail", "")),
            suppressed=bool(payload.get("suppressed", False)),
            suppress_reason=str(payload.get("suppress_reason", "")),
        )
