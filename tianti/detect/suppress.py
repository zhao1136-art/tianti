"""检测器抑制/白名单/降权（L3-L4 之间）。

三类抑制来源：
1. 全局白名单：路径前缀（whitelist_paths）、样本 sha256（whitelist_sha256）-> 降权到 0（完全抑制）。
2. 检测器 YAML suppress 声明：可信签名镜像占位、可信安装目录等 -> 降权到 0.25（保留证据但基本不计分）。
3. 签名验证为占位实现：本机无证书链数据，用 TrustStore.signed_images 的 glob 作为
   “已签名/系统可信镜像”的近似，报告与 notes 必须标明 signature_placeholder。

输出 SuppressDecision：是否抑制、原因、剩余系数（factor，1.0=不降权、0=完全剔除）、
命中说明列表。评分使用 factor 计算降权后的分数，并据抑制比例下调置信度。
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..core.errors import DetectorError
from ..trace.schema import Event, Trace
from .base import DetectorHit

__all__ = [
    "CRITICAL_MIN_FACTOR",
    "DEFAULT_SIGNED_IMAGES",
    "EVENT_WHITELIST_FACTOR",
    "SuppressDecision",
    "SuppressionRule",
    "Suppressor",
    "TrustStore",
    "compile_rule",
    "compile_rules",
    "sample_image_for_trace",
]

#: 签名验证占位：Windows 系统目录与 Program Files 视为“可信/已签名”镜像。
#: 真实实现应读取 PE 安全目录做证书链校验（v1 不做，报告须标注 placeholder）。
DEFAULT_SIGNED_IMAGES: tuple[str, ...] = (
    "*\\windows\\system32\\*",
    "*\\windows\\syswow64\\*",
    "*\\windows\\winsxs\\*",
    "*\\program files\\*",
    "*\\program files (x86)\\*",
)

DEFAULT_DOWNGRADE_FACTOR = 0.25
WHITELIST_FACTOR = 0.0
#: 事件级路径命中白名单只降权 50%，不得据此完全抑制检测结果（Lead 决策）。
EVENT_WHITELIST_FACTOR = 0.5
#: critical 严重度最多降权 50%（永不 100% 抑制，仍计入证据链与硬规则）。
CRITICAL_MIN_FACTOR = 0.5

SUPPRESS_FIELDS = {
    "path_under",
    "path_glob",
    "image_under",
    "image_glob",
    "image_in",
    "image_signed",
    "sha256_in",
    "reason",
    "factor",
}


@dataclass
class TrustStore:
    """可信集合：白名单 + 签名占位。"""

    whitelist_paths: list[str] = field(default_factory=list)
    whitelist_sha256: list[str] = field(default_factory=list)
    signed_images: list[str] = field(default_factory=lambda: list(DEFAULT_SIGNED_IMAGES))
    signature_placeholder: bool = True

    def path_whitelisted(self, path: str) -> bool:
        if not path:
            return False
        normalized = _norm(path)
        for prefix in self.whitelist_paths:
            if not prefix:
                continue
            if normalized.startswith(_norm(prefix)):
                return True
        return False

    def sha256_whitelisted(self, sha256: str) -> bool:
        return bool(sha256) and sha256.lower() in {item.lower() for item in self.whitelist_sha256}

    def is_signed_image(self, image: str) -> bool:
        if not image:
            return False
        lowered = image.lower().replace("/", "\\")
        return any(fnmatch.fnmatchcase(lowered, pattern.lower().replace("/", "\\")) for pattern in self.signed_images)


def _norm(path: str) -> str:
    return (path or "").strip().lower().replace("/", "\\")


def _basename(path: str) -> str:
    return Path(str(path or "").replace("\\", "/")).name.lower()


def sample_image_for_trace(trace: Trace) -> str:
    """找出“样本自身”的进程镜像路径，用于白名单样本级判定。

    只有 process:create 事件的 image/target 与 trace.sample.name 同名时，
    才认为该镜像是样本自身；绝不把执行宿主（如 powershell.exe）当样本，
    否则 C:\\Windows 白名单会误把整条命中完全抑制（Lead 决策）。
    """
    sample_name = trace.sample.name or ""
    base = _basename(sample_name)
    if not base:
        return ""
    for event in trace.events:
        if event.category != "process" or event.action != "create":
            continue
        for candidate in (event.image, event.target):
            if candidate and _basename(candidate) == base:
                return str(candidate)
    return ""


@dataclass(frozen=True)
class SuppressDecision:
    """一次抑制判定结果。"""

    suppressed: bool = False
    reason: str = ""
    factor: float = 1.0
    matched: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "suppressed": self.suppressed,
            "reason": self.reason,
            "factor": round(float(self.factor), 3),
            "matched": list(self.matched),
        }


@dataclass
class SuppressionRule:
    """检测器 YAML 中一条 suppress 声明。"""

    path_under: list[str] = field(default_factory=list)
    path_glob: list[str] = field(default_factory=list)
    image_under: list[str] = field(default_factory=list)
    image_glob: list[str] = field(default_factory=list)
    image_in: list[str] = field(default_factory=list)
    image_signed: bool = False
    sha256_in: list[str] = field(default_factory=list)
    reason: str = ""
    factor: float = DEFAULT_DOWNGRADE_FACTOR

    def __post_init__(self) -> None:
        if not (self.path_under or self.path_glob or self.image_under or self.image_glob or self.image_in or self.image_signed or self.sha256_in):
            raise DetectorError("suppress 条目必须至少包含 path_* / image_* / sha256_in 之一")
        if not 0.0 <= float(self.factor) <= 1.0:
            raise DetectorError(f"suppress.factor 必须在 [0,1]: {self.factor!r}")

    def applies(self, events: list[Event], *, sample_sha256: str, trust: TrustStore) -> tuple[bool, str]:
        """判断该抑制条目是否适用于一组证据事件。"""
        fragments: list[str] = []
        has_path = bool(self.path_under or self.path_glob)
        has_image = bool(self.image_under or self.image_glob or self.image_in or self.image_signed)

        if self.sha256_in:
            if sample_sha256 and sample_sha256.lower() in {item.lower() for item in self.sha256_in}:
                fragments.append(f"sha256={sample_sha256.lower()[:12]}")
            else:
                return False, ""
        if has_path:
            if not events:
                return False, ""
            for event in events:
                target = _norm(event.target)
                if not target:
                    return False, ""
                matched_path = False
                if self.path_under and any(target.startswith(_norm(prefix)) for prefix in self.path_under):
                    matched_path = True
                if not matched_path and self.path_glob and any(
                    fnmatch.fnmatchcase(target, _norm(pattern)) for pattern in self.path_glob
                ):
                    matched_path = True
                if not matched_path:
                    return False, ""
            fragments.append("target 命中可信路径")
        if has_image:
            if not events:
                return False, ""
            for event in events:
                image = _norm(event.image)
                if not image:
                    return False, ""
                ok = False
                if self.image_under and any(image.startswith(_norm(prefix)) for prefix in self.image_under):
                    ok = True
                if not ok and self.image_glob and any(
                    fnmatch.fnmatchcase(image, _norm(pattern)) for pattern in self.image_glob
                ):
                    ok = True
                if not ok and self.image_in and any(
                    fnmatch.fnmatchcase(image, _norm(pattern)) for pattern in self.image_in
                ):
                    ok = True
                if not ok and self.image_signed and trust.is_signed_image(event.image or ""):
                    ok = True
                if not ok:
                    return False, ""
            fragments.append(
                "image 命中可信/已签名镜像" + ("（签名占位）" if self.image_signed and trust.signature_placeholder else "")
            )
        if not fragments:
            return False, ""
        return True, self.reason or "；".join(fragments)


def compile_rule(payload: Any) -> SuppressionRule:
    if not isinstance(payload, dict):
        raise DetectorError(f"suppress 条目必须是 mapping: {payload!r}")
    unknown = set(payload) - SUPPRESS_FIELDS
    if unknown:
        raise DetectorError(f"suppress 含未知字段: {', '.join(sorted(unknown))}")
    return SuppressionRule(
        path_under=[str(x) for x in _as_list(payload.get("path_under"))],
        path_glob=[str(x) for x in _as_list(payload.get("path_glob"))],
        image_under=[str(x) for x in _as_list(payload.get("image_under"))],
        image_glob=[str(x) for x in _as_list(payload.get("image_glob"))],
        image_in=[str(x) for x in _as_list(payload.get("image_in"))],
        image_signed=bool(payload.get("image_signed", False)),
        sha256_in=[str(x).lower() for x in _as_list(payload.get("sha256_in"))],
        reason=str(payload.get("reason") or ""),
        factor=float(payload.get("factor", DEFAULT_DOWNGRADE_FACTOR)),
    )


def compile_rules(payload: Any) -> list[SuppressionRule]:
    if payload is None:
        return []
    if not isinstance(payload, list):
        raise DetectorError("detector.suppress 必须是列表")
    return [compile_rule(item) for item in payload]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


class Suppressor:
    """对 DetectorHit 应用全局白名单 + 检测器级 suppress 规则。"""

    def __init__(
        self,
        trust: TrustStore | None = None,
        *,
        downgrade_factor: float = DEFAULT_DOWNGRADE_FACTOR,
        whitelist_factor: float = WHITELIST_FACTOR,
    ) -> None:
        self.trust = trust or TrustStore()
        self.downgrade_factor = float(downgrade_factor)
        self.whitelist_factor = float(whitelist_factor)

    def check_hit(
        self,
        hit: DetectorHit,
        events_by_id: dict[str, Event],
        rules: Iterable[SuppressionRule] = (),
        *,
        sample_sha256: str = "",
        sample_name: str = "",
        sample_image: str = "",
    ) -> SuppressDecision:
        events = [events_by_id[event_id] for event_id in hit.evidence if event_id in events_by_id]

        # 1) 样本自身白名单（sha256 / 样本路径 / 顶层进程镜像）-> 完全抑制
        if self.trust.sha256_whitelisted(sample_sha256):
            return SuppressDecision(True, f"白名单 sha256={sample_sha256.lower()[:12]}", self.whitelist_factor, ("whitelist-sha256",))
        sample_paths = [path for path in (sample_name, sample_image) if path]
        for path in sample_paths:
            if self.trust.path_whitelisted(path):
                return SuppressDecision(
                    True,
                    f"样本路径命中白名单: {path}",
                    self.whitelist_factor,
                    ("whitelist-sample",),
                )

        # 2) 事件级路径白名单：只降权 50%，不得据此完全抑制检测结果（Lead 决策）
        #    动作对象 target 与动作发起者 image 都算“事件级路径”。
        if events and self.trust.whitelist_paths and all(
            self.trust.path_whitelisted(event.target or "")
            or self.trust.path_whitelisted(event.image or "")
            for event in events
        ):
            return SuppressDecision(
                True,
                "证据事件路径命中白名单（事件级，降权 50%）",
                EVENT_WHITELIST_FACTOR,
                ("whitelist-event-path",),
            )

        # 3) 检测器级 suppress 声明 -> 降权（默认 75%；critical 最多降 50%）
        for rule in rules:
            ok, reason = rule.applies(events, sample_sha256=sample_sha256, trust=self.trust)
            if ok:
                factor = float(rule.factor)
                if factor >= self.downgrade_factor:
                    factor = min(factor, self.downgrade_factor)
                return SuppressDecision(True, reason, self.clamp_factor(hit, factor), (reason,))
        return SuppressDecision()

    @staticmethod
    def clamp_factor(hit: DetectorHit, factor: float) -> float:
        """critical 严重度降权后剩余系数不低于 CRITICAL_MIN_FACTOR。"""
        value = max(0.0, min(1.0, float(factor)))
        if hit.severity == "critical":
            value = max(value, CRITICAL_MIN_FACTOR)
        return value
