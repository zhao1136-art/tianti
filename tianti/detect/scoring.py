"""L4 评分与判定：RuleMatch + DetectorHit + 静态信号 -> Verdict。

评分模型（默认参数见 tianti/core/config.py:ScoringConfig）
--------------------------------------------------------
score = Σ capability 权重 + Σ detector.score × 抑制系数 + Σ static 信号

- capability：按命中 ATT&CK 战术基础权重计分；同一战术第 2 条起递减（×0.65、×0.30、下限 0.25），
  保证“加一条命中也只会加分/持平”（单调），又避免同类规则堆分。
- detector：YAML/Python 检测器自带 score；命中 suppress 时按系数降权（默认 0.25，白名单 0.0）。
- static：静态预筛信号（dict：name/score/detail/evidence），非负计入。
- critical 硬规则：任一 critical 检测器命中（降权后剩余系数 >=0.5）-> 分数至少抬到 malicious_at（>=40），
  判定 malicious；critical 永不 100% 抑制（最多降权 50%，仍保留证据链与 suppressed 明细）。
- 阈值：< clean_below(10) clean；[10,40) suspicious；>= malicious_at(40) malicious。
- 置信度：core.verdict.confidence_from(分数, 证据数, 来源保真度, 抑制比例)；
  >=2 个不同战术 +0.05；trace 被截断 ×0.9。
- 证据链：每个 ScoreItem.evidence 都是 trace 事件 id，可回溯。
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Iterable, Mapping

from ..core.config import ScoringConfig
from ..core.verdict import ScoreItem, Verdict, confidence_from, decide
from ..trace.schema import Trace
from .base import DetectorHit
from .suppress import (
    CRITICAL_MIN_FACTOR,
    DEFAULT_DOWNGRADE_FACTOR,
    Suppressor,
    TrustStore,
    sample_image_for_trace,
)

__all__ = ["DEFAULT_SUPPRESS_FACTOR", "SIGNATURE_PLACEHOLDER_NOTE", "evaluate", "score"]

#: 使用 path-based trust（白名单路径 / 可信镜像占位）时必须出现在 Verdict.notes 的固定说明。
SIGNATURE_PLACEHOLDER_NOTE = "签名校验为占位（基于可信路径），非证书验证"

#: 未显式提供 suppress_factors 时，已标记 suppressed 的检测器命中按此系数计分。
DEFAULT_SUPPRESS_FACTOR = DEFAULT_DOWNGRADE_FACTOR

FALLBACK_CAPABILITY = 4.0
MIN_CAPABILITY_DECAY = 0.25
CAPABILITY_DECAY_STEP = 0.35
SEVERITY_SCORE = {"low": 4.0, "medium": 8.0, "high": 18.0, "critical": 28.0}

FIDELITY = {"high": 1.0, "medium": 0.6, "low": 0.3}
DEFAULT_QUALITY = 0.5
TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
TACTIC_BY_PREFIX = {
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command-and-control": "TA0011",
    "impact": "TA0040",
}


def _tactics_from_attack(entries: Iterable[str]) -> list[str]:
    """把 'Persistence::Registry Run Keys [T1547.001]' 映射为战术编号。"""
    found: list[str] = []
    for entry in entries:
        prefix = str(entry).split("::", 1)[0].strip().lower().replace(" ", "-").replace("_", "-")
        tactic = TACTIC_BY_PREFIX.get(prefix)
        if tactic:
            found.append(tactic)
    return sorted(set(found))


def _techniques_from_attack(entries: Iterable[str]) -> list[str]:
    found: list[str] = []
    for entry in entries:
        found.extend(TECHNIQUE_RE.findall(str(entry)))
    return sorted(set(found))


def _match_sort_key(match: Any) -> tuple[str, str, str, str, str]:
    """确定性排序键：同命中集合必须得到同分数（规则引擎输出顺序变化不得影响判定）。

    顺序：主战术 -> 全部战术 -> namespace -> name -> instance 稳定 JSON。
    能力递减权重按此顺序应用，保证可回归。
    """
    attack = list(getattr(match, "attack", []) or [])
    tactics = _tactics_from_attack(attack)
    primary = tactics[0] if tactics else ""
    namespace = str(getattr(match, "namespace", "") or "")
    name = str(getattr(match, "name", "") or "")
    instance = getattr(match, "instance", {}) or {}
    try:
        instance_key = json.dumps(instance, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        instance_key = repr(instance)
    return (primary, "|".join(tactics), namespace, name, instance_key)


def _match_evidence(match: Any) -> list[str]:
    evidence: list[str] = []
    raw = getattr(match, "evidence", None)
    if isinstance(raw, dict):
        for value in raw.values():
            if isinstance(value, (list, tuple)):
                evidence.extend(str(item) for item in value)
            elif value is not None:
                evidence.append(str(value))
    instance = getattr(match, "instance", None)
    if isinstance(instance, dict):
        for key in ("event_ids", "events"):
            value = instance.get(key)
            if isinstance(value, (list, tuple)):
                evidence.extend(str(item) for item in value)
            elif isinstance(value, str):
                evidence.append(value)
    return _dedupe(evidence)


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _hit_raw_score(hit: DetectorHit) -> float:
    if hit.score and hit.score > 0:
        return float(hit.score)
    return float(SEVERITY_SCORE.get(hit.severity, 8.0))


def _source_quality(trace: Trace | None, event_ids: list[str], matches: list[Any]) -> float:
    if trace is not None:
        events_by_id = {event.id: event for event in trace.events}
        scores: list[float] = []
        for event_id in event_ids:
            event = events_by_id.get(event_id)
            if event is not None:
                scores.append(FIDELITY.get(str(event.confidence).lower(), DEFAULT_QUALITY))
        if scores:
            return sum(scores) / len(scores)
    confidences = [FIDELITY.get(str(getattr(match, "confidence", "")).lower()) for match in matches]
    usable = [value for value in confidences if value is not None]
    if usable:
        return sum(usable) / len(usable)
    return DEFAULT_QUALITY


def _static_item(signal: Any) -> ScoreItem | None:
    if isinstance(signal, dict):
        name = str(signal.get("name") or signal.get("ref") or signal.get("id") or "")
        if not name:
            return None
        raw_score = signal.get("score", 0.0)
        try:
            value = max(0.0, float(raw_score))
        except (TypeError, ValueError):
            value = 0.0
        evidence = signal.get("evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence]
        return ScoreItem(
            kind="static",
            ref=name,
            score=value,
            detail=str(signal.get("detail") or signal.get("description") or ""),
            suppressed=bool(signal.get("suppressed", False)),
            suppress_reason=str(signal.get("suppress_reason") or ""),
            evidence=[str(item) for item in evidence],
        )
    return None


def _whitelisted_sample(cfg: ScoringConfig, sample_sha256: str) -> bool:
    if not sample_sha256:
        return False
    return sample_sha256.lower() in {item.lower() for item in cfg.whitelist_sha256}


def score(
    matches: Iterable[Any] | None,
    hits: Iterable[DetectorHit] | None,
    static_signals: list[dict[str, Any]] | None = None,
    cfg: ScoringConfig | None = None,
    *,
    sample_sha256: str = "",
    trace: Trace | None = None,
    suppress_factors: Mapping[str, float] | None = None,
    detector_errors: Iterable[str] | None = None,
) -> Verdict:
    """合并规则/检测器/静态信号，输出 Verdict（带评分明细与证据链）。"""
    config = cfg or ScoringConfig()
    # 确定性排序：能力递减权重依赖顺序，必须先稳定顺序再计分（避免同集合不同分数）
    match_list = sorted(list(matches or []), key=_match_sort_key)
    hit_list = list(hits or [])
    notes: list[str] = []

    if _whitelisted_sample(config, sample_sha256):
        return Verdict(
            verdict="clean",
            score=0.0,
            confidence=0.95,
            suppressed=[f"whitelist_sha256: {sample_sha256.lower()}"],
            notes=["样本 sha256 命中白名单，跳过评分（确定性 clean）"],
        )

    items: list[ScoreItem] = []
    tactics: set[str] = set()
    techniques: set[str] = set()

    # --- 1) capability（capa 风格规则命中）--------------------------------
    tactic_counts: dict[str, int] = defaultdict(int)
    for match in match_list:
        attack = list(getattr(match, "attack", []) or [])
        match_tactics = _tactics_from_attack(attack)
        tactics.update(match_tactics)
        techniques.update(_techniques_from_attack(attack))
        primary = match_tactics[0] if match_tactics else ""
        index = tactic_counts[primary]
        tactic_counts[primary] += 1
        weight = float(config.tactic_weights.get(primary, FALLBACK_CAPABILITY)) if primary else FALLBACK_CAPABILITY
        decay = max(MIN_CAPABILITY_DECAY, 1.0 - CAPABILITY_DECAY_STEP * index)
        contribution = weight * decay
        name = str(getattr(match, "name", "") or "?")
        namespace = str(getattr(match, "namespace", "") or "")
        items.append(
            ScoreItem(
                kind="capability",
                ref=name,
                score=contribution,
                detail=f"能力命中 namespace={namespace or '-'} tactic={primary or '-'}",
                evidence=_match_evidence(match),
            )
        )

    # --- 2) detector（危险行为命中，可被抑制降权）--------------------------
    factors = dict(suppress_factors or {})
    critical_hit = False
    suppressed_raw = 0.0
    for hit in hit_list:
        raw = _hit_raw_score(hit)
        factor = 1.0
        if hit.detector_id in factors:
            try:
                factor = float(factors[hit.detector_id])
            except (TypeError, ValueError):
                factor = 1.0
        elif hit.suppressed:
            factor = DEFAULT_SUPPRESS_FACTOR
        if hit.suppressed and factor >= 1.0:
            factor = DEFAULT_SUPPRESS_FACTOR
        factor = max(0.0, min(1.0, factor))
        # critical 永不 100% 抑制：最多降权 50%，仍计入命中/证据链与硬规则
        if hit.severity == "critical":
            factor = max(factor, CRITICAL_MIN_FACTOR)
        contributed = raw * factor
        if hit.suppressed:
            suppressed_raw += raw
        if hit.severity == "critical" and factor >= CRITICAL_MIN_FACTOR:
            critical_hit = True
        if hit.tactic:
            tactics.add(str(hit.tactic))
        if hit.technique:
            techniques.add(str(hit.technique))
        items.append(
            ScoreItem(
                kind="detector",
                ref=hit.detector_id,
                score=contributed,
                detail=hit.detail or hit.name,
                suppressed=hit.suppressed,
                suppress_reason=hit.suppress_reason,
                evidence=list(hit.evidence),
            )
        )

    # --- 3) static（静态预筛信号）-----------------------------------------
    for signal in static_signals or []:
        item = _static_item(signal)
        if item is not None:
            items.append(item)

    raw_total = round(sum(item.score for item in items), 6)
    suppressed_ratio = (suppressed_raw / raw_total) if raw_total > 0 else 0.0

    # --- 4) critical 硬规则：至少 malicious 且分数抬到阈值 ---------------
    final_score = raw_total
    if critical_hit and config.critical_escalation and final_score < config.malicious_at:
        final_score = float(config.malicious_at)
        notes.append(
            f"critical 硬规则：未抑制 critical 检测器命中，分数由 {raw_total:.3f} 抬升到 {final_score:.3f}"
        )

    verdict = decide(
        final_score,
        critical_hit=critical_hit and config.critical_escalation,
        clean_below=float(config.clean_below),
        malicious_at=float(config.malicious_at),
    )

    # --- 5) 置信度与证据链 -------------------------------------------------
    evidence_ids = _dedupe(
        event_id for item in items if not item.suppressed for event_id in item.evidence
    )
    all_evidence_ids = _dedupe(event_id for item in items for event_id in item.evidence)
    quality = _source_quality(trace, all_evidence_ids, match_list)
    confidence = confidence_from(
        final_score,
        len(evidence_ids) if evidence_ids else len(all_evidence_ids),
        quality,
        suppressed_ratio,
    )
    if len(tactics) >= 2:
        confidence = min(1.0, confidence + 0.05)
        notes.append(f"跨 {len(tactics)} 个战术命中，置信度 +0.05")
    if trace is not None and trace.summary.truncated:
        confidence = round(confidence * 0.9, 3)
        notes.append("轨迹被截断（summary.truncated=true），置信度 ×0.9")
    confidence = round(max(0.0, min(1.0, confidence)), 3)

    suppressed_list = [
        f"{hit.detector_id}: {hit.suppress_reason or 'suppressed'}" for hit in hit_list if hit.suppressed
    ]
    if suppressed_ratio > 0:
        notes.append(f"抑制比例 {suppressed_ratio:.0%}（已按系数降权，置信度相应下调）")

    # 使用 path-based trust（白名单路径/可信镜像占位）时固定标注签名占位
    path_trust_used = any(
        hit.suppressed
        and any(keyword in (hit.suppress_reason or "") for keyword in ("路径", "签名", "可信"))
        for hit in hit_list
    )
    if path_trust_used:
        notes.append(SIGNATURE_PLACEHOLDER_NOTE)
    for error in detector_errors or []:
        notes.append(f"检测器错误: {error}")
    if verdict == "clean" and items:
        notes.append("存在低分证据，未达到 suspicious 阈值")

    return Verdict(
        verdict=verdict,
        score=round(final_score, 3),
        confidence=confidence,
        tactics=sorted(tactics),
        techniques=sorted(techniques),
        items=items,
        suppressed=_dedupe(suppressed_list),
        notes=notes,
    )


def evaluate(
    trace: Trace,
    matches: Iterable[Any] | None,
    hits: Iterable[DetectorHit] | None,
    static_signals: list[dict[str, Any]] | None = None,
    cfg: ScoringConfig | None = None,
    *,
    detector_errors: Iterable[str] | None = None,
) -> Verdict:
    """交付契约：给定 trace + 规则命中 + 检测器命中，产出 Verdict。

    额外应用全局白名单（cfg.whitelist_paths / whitelist_sha256）到检测器命中，
    并用 trace 的事件来源保真度计算置信度。
    """
    config = cfg or ScoringConfig()
    trust = TrustStore(
        whitelist_paths=list(config.whitelist_paths),
        whitelist_sha256=list(config.whitelist_sha256),
    )
    suppressor = Suppressor(trust)
    events_by_id = {event.id: event for event in trace.events}
    sample_image = sample_image_for_trace(trace)
    factors: dict[str, float] = {}
    for hit in list(hits or []):
        try:
            decision = suppressor.check_hit(
                hit,
                events_by_id,
                (),
                sample_sha256=trace.sample.sha256,
                sample_name=trace.sample.name,
                sample_image=sample_image,
            )
        except Exception:
            decision = None
        if decision is not None and decision.suppressed:
            hit.suppressed = True
            hit.suppress_reason = decision.reason
            factors[hit.detector_id] = float(decision.factor)
        elif hit.suppressed:
            factors[hit.detector_id] = DEFAULT_SUPPRESS_FACTOR
        else:
            factors[hit.detector_id] = 1.0
    return score(
        matches,
        hits,
        static_signals,
        config,
        sample_sha256=trace.sample.sha256,
        trace=trace,
        suppress_factors=factors,
        detector_errors=detector_errors,
    )
