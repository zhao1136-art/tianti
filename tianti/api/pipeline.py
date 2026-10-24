"""L5 编排适配层：CLI 与 API 共用的扫描/回放流水线。

设计要点：
- 只依赖冻结契约（Trace / RuleMatch / DetectorHit / Verdict）与各层公开入口；
- 对 rules/detect/static/sandbox 使用 lazy import + 能力探测，模块未就绪时返回
  明确的 notes，不抛 traceback；replay 流程在规则/检测器缺失时仍能产出判定；
- 评分优先调用 detect.scoring.evaluate；不可用时使用基于 core.verdict 的后备评分，
  并显式标注“后备适配器”，保证报告可解释。
"""

from __future__ import annotations

import importlib
import inspect
import json
import platform as _platform
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable, Iterable

from .. import __version__
from ..core.config import Config
from ..core.errors import SampleError, SandboxUnavailable, TraceError
from ..core.model import Sample, SampleType
from ..core.verdict import ScoreItem, Verdict, confidence_from, decide
from ..detect.base import SEVERITY_RANK, DetectorHit
from ..report.base import ScanResult
from ..report.mitre import tactic_for_technique
from ..rules.base import RuleMatch, RuleMeta
from ..sandbox.base import SandboxPolicy
from ..trace import schema
from ..trace.schema import Trace

RULES_MODULES = ("tianti.rules.engine", "tianti.rules.matcher", "tianti.rules.pipeline")
RULES_ENTRIES = ("match_trace", "match", "run")
DETECTOR_MODULES = ("tianti.detect.detectors", "tianti.detect.engine", "tianti.detect.runner")
DETECTOR_ENTRIES = ("run_detectors", "run", "detect")
SCORING_MODULES = ("tianti.detect.scoring",)
SCORING_ENTRIES = ("evaluate", "score", "score_trace")
STATIC_MODULES = ("tianti.static.analyzer", "tianti.static.scanner", "tianti.static.api")
STATIC_ENTRIES = ("analyze", "scan", "analyze_path")
BACKEND_ORDER = ("containment", "replay", "emulation", "vm")

# 压缩包展开安全上限（一层展开；嵌套压缩包只做归档级静态分析）
MAX_ARCHIVE_ENTRIES = 100
MAX_ARCHIVE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 2
_ARCHIVE_TYPES = (SampleType.ARCHIVE_ZIP, SampleType.ARCHIVE_RAR, SampleType.ARCHIVE_7Z)
_ARCHIVE_SUFFIXES = {".zip", ".rar", ".7z"}


# --------------------------------------------------------------------- 导入与调用
def _import_first(modules: Iterable[str]) -> tuple[Any | None, list[str]]:
    reasons: list[str] = []
    for name in modules:
        try:
            return importlib.import_module(name), reasons
        except ModuleNotFoundError as exc:
            missing = exc.name or name
            if missing == name or name.startswith(missing + "."):
                reasons.append(f"缺少模块 {name}")
            else:
                reasons.append(f"{name} 依赖缺失（{missing}）")
        except Exception as exc:  # 导入期异常不传播，转为能力探测结果
            reasons.append(f"导入 {name} 失败: {exc}")
    return None, reasons


def _resolve(modules: Iterable[str], entries: Iterable[str]) -> tuple[Callable[..., Any] | None, str, list[str]]:
    module, reasons = _import_first(modules)
    if module is None:
        return None, "", reasons
    for entry in entries:
        func = getattr(module, entry, None)
        if callable(func):
            return func, module.__name__, reasons
    reasons.append(f"{module.__name__} 未导出入口 {'/'.join(entries)}")
    return None, module.__name__, reasons


def _call_with_context(func: Callable[..., Any], context: dict[str, Any]) -> Any:
    """按参数名注入上下文；未知必填参数则回退为单参调用。"""
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return func(context.get("trace"))
    positional: list[Any] = []
    kwargs: dict[str, Any] = {}
    for parameter in signature.parameters.values():
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            continue
        if parameter.name in context:
            if parameter.kind == parameter.POSITIONAL_ONLY:
                positional.append(context[parameter.name])
            else:
                kwargs[parameter.name] = context[parameter.name]
        elif parameter.default is parameter.empty:
            return func(context.get("trace"))
    return func(*positional, **kwargs)


def _accepts_param(func: Callable[..., Any], name: str) -> bool:
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return False
    for parameter in signature.parameters.values():
        if parameter.name == name or parameter.kind == parameter.VAR_KEYWORD:
            return True
    return False


def _as_items(value: Any, *keys: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, dict):
        for key in keys:
            if key in value:
                return _as_items(value[key], *keys)
        return []
    for attr in keys:
        inner = getattr(value, attr, None)
        if inner is not None:
            return _as_items(inner, *keys)
    try:
        return list(value)
    except TypeError:
        return []


def _to_rule_matches(raw: Any) -> list[RuleMatch]:
    out: list[RuleMatch] = []
    for item in _as_items(raw, "matches", "rules", "items"):
        if isinstance(item, RuleMatch):
            out.append(item)
        elif isinstance(item, dict):
            try:
                out.append(RuleMatch.from_dict(item))
            except Exception:
                continue
    return out


def _to_detector_hits(raw: Any) -> list[DetectorHit]:
    out: list[DetectorHit] = []
    for item in _as_items(raw, "hits", "detections", "items"):
        if isinstance(item, DetectorHit):
            out.append(item)
        elif isinstance(item, dict):
            try:
                out.append(DetectorHit.from_dict(item))
            except Exception:
                continue
    return out


def _reason_text(reasons: list[str]) -> str:
    return "；".join(reasons) if reasons else "未知原因"


# --------------------------------------------------------------------- 规则 / 检测器
def run_rules(
    trace: Trace,
    *,
    config: Config | None = None,
    include_upstream: bool = False,
) -> tuple[list[RuleMatch], str | None]:
    """执行 capa 规则匹配；引擎缺失/异常时返回 (空列表, 原因)。

    include_upstream=True 时把开关传给 rules 引擎（加载 rules/upstream 官方规则）；
    旧版引擎无此参数时忽略开关并在 note 中说明，保证向后兼容。
    """
    cfg = config or Config.load()
    func, module_name, reasons = _resolve(RULES_MODULES, RULES_ENTRIES)
    if func is None:
        return [], "规则引擎尚未接通（" + _reason_text(reasons) + "），能力列表为空"
    note: str | None = None
    if include_upstream and not _accepts_param(func, "include_upstream"):
        note = "当前规则引擎未支持 include_upstream，已仅使用本地规则匹配"
    try:
        raw = _call_with_context(
            func,
            {
                "trace": trace,
                "rules_dir": cfg.paths.rules,
                "rules_path": cfg.paths.rules,
                "include_upstream": bool(include_upstream),
                "cfg": cfg,
                "config": cfg,
            },
        )
    except Exception as exc:
        return [], f"规则匹配异常（{module_name}）: {exc}"
    return _to_rule_matches(raw), note


def run_detectors(trace: Trace, *, config: Config | None = None) -> tuple[list[DetectorHit], str | None]:
    """执行危险行为检测器；模块缺失/异常时返回 (空列表, 原因)。"""
    cfg = config or Config.load()
    func, module_name, reasons = _resolve(DETECTOR_MODULES, DETECTOR_ENTRIES)
    if func is None:
        return [], "检测器尚未接通（" + _reason_text(reasons) + "），危险行为列表为空"
    error_sink: list[str] = []
    try:
        raw = _call_with_context(
            func,
            {
                "trace": trace,
                "detectors_dir": cfg.paths.detectors,
                "detectors_path": cfg.paths.detectors,
                "errors": error_sink,
                "cfg": cfg,
                "config": cfg,
            },
        )
    except Exception as exc:
        return [], f"检测器执行异常（{module_name}）: {exc}"
    hits = _to_detector_hits(raw)
    if error_sink:
        return hits, "检测器部分失败（已隔离）: " + "；".join(error_sink[:5])
    return hits, None


# --------------------------------------------------------------------- 评分 / 判定
def _source_quality(events: list[Any]) -> float:
    weights = {"high": 1.0, "medium": 0.6, "low": 0.3}
    values = [weights.get(str(getattr(event, "confidence", "medium")), 0.5) for event in events]
    if not values:
        return 0.5
    return round(sum(values) / len(values), 3)


def _static_score(static: dict[str, Any]) -> float:
    if not isinstance(static, dict):
        return 0.0
    for key in ("score", "risk_score", "total_score"):
        try:
            return float(static.get(key) or 0.0)
        except (TypeError, ValueError):
            continue
    return 0.0


def _fallback_verdict(
    trace: Trace,
    matches: list[RuleMatch],
    hits: list[DetectorHit],
    static: dict[str, Any],
    *,
    config: Config,
) -> Verdict:
    """delivery 后备评分：tactics 权重 + detector.score + static.score。"""
    scoring_cfg = config.scoring
    items: list[ScoreItem] = []
    tactics: set[str] = set()
    techniques: set[str] = set()
    score = 0.0
    for match in matches:
        meta = RuleMeta(name=match.name, attack=list(match.attack))
        match_tactics = meta.tactics()
        match_techniques = meta.techniques()
        tactics.update(match_tactics)
        techniques.update(match_techniques)
        evidence = [event_id for ids in match.evidence.values() for event_id in ids]
        for tactic in match_tactics:
            weight = float(scoring_cfg.tactic_weights.get(tactic, 5.0))
            score += weight
            items.append(
                ScoreItem(
                    kind="capability",
                    ref=match.name or match.namespace,
                    score=weight,
                    detail=f"能力命中战术 {tactic} {meta.name}",
                    evidence=evidence[:20],
                )
            )
        if not match_tactics:
            items.append(
                ScoreItem(
                    kind="capability",
                    ref=match.name or match.namespace,
                    score=0.0,
                    detail="能力命中但未标注 ATT&CK 战术，不计分",
                    evidence=evidence[:20],
                )
            )
    for hit in hits:
        tactics.add(hit.tactic)
        if hit.technique:
            techniques.add(hit.technique)
            inferred = tactic_for_technique(hit.technique)
            if inferred:
                tactics.add(inferred)
        if hit.suppressed:
            items.append(
                ScoreItem(
                    kind="detector",
                    ref=hit.detector_id,
                    score=0.0,
                    detail=hit.detail or hit.name,
                    suppressed=True,
                    suppress_reason=hit.suppress_reason,
                    evidence=list(hit.evidence),
                )
            )
            continue
        score += float(hit.score or 0.0)
        items.append(
            ScoreItem(
                kind="detector",
                ref=hit.detector_id,
                score=float(hit.score or 0.0),
                detail=hit.detail or hit.name,
                evidence=list(hit.evidence),
            )
        )
    static_value = _static_score(static)
    if static_value:
        score += static_value
        items.append(ScoreItem(kind="static", ref="static_signals", score=static_value, detail="静态信号累计"))
    total = round(max(0.0, min(100.0, score)), 3)
    critical = any(
        str(hit.severity) == "critical" and not hit.suppressed for hit in hits
    )
    verdict_name = decide(
        total,
        critical_hit=critical,
        clean_below=float(scoring_cfg.clean_below),
        malicious_at=float(scoring_cfg.malicious_at),
    )
    evidence_count = sum(len(hit.evidence) for hit in hits) + sum(
        len(ids) for match in matches for ids in match.evidence.values()
    )
    suppressed_total = sum(1 for hit in hits if hit.suppressed) + sum(1 for match in matches if not match.name)
    suppressed_ratio = (suppressed_total / len(hits)) if hits else 0.0
    confidence = confidence_from(total, evidence_count, _source_quality(trace.events), suppressed_ratio)
    notes = [
        "评分由 delivery 后备适配器生成（detect.scoring 尚未接通）："
        "tactics 权重 + detector.score + static.score，按 core.verdict 阈值判定。"
    ]
    return Verdict(
        verdict=verdict_name,
        score=total,
        confidence=confidence,
        tactics=sorted(tactics),
        techniques=sorted(techniques),
        items=items,
        suppressed=[hit.detector_id for hit in hits if hit.suppressed],
        notes=notes,
    )


def run_scoring(
    trace: Trace,
    matches: list[RuleMatch],
    hits: list[DetectorHit],
    static: dict[str, Any],
    *,
    config: Config | None = None,
) -> tuple[Verdict, str | None]:
    """优先进口 detect.scoring.evaluate；失败时使用后备评分并返回原因。"""
    cfg = config or Config.load()
    func, module_name, reasons = _resolve(SCORING_MODULES, SCORING_ENTRIES)
    if func is None:
        return _fallback_verdict(trace, matches, hits, static, config=cfg), "评分模块未接通（" + _reason_text(reasons) + "），已使用后备评分"
    static_signals: list[dict[str, Any]] = []
    if isinstance(static, dict):
        raw_signals = static.get("signals")
        if isinstance(raw_signals, list):
            static_signals = [item for item in raw_signals if isinstance(item, dict)]
        elif static.get("available") and static.get("name"):
            static_signals = [static]
    context = {
        "trace": trace,
        "matches": matches,
        "hits": hits,
        "static": static,
        "static_signals": static_signals,
        "cfg": cfg.scoring,
        "config": cfg.scoring,
    }
    try:
        raw = _call_with_context(func, context)
        if isinstance(raw, Verdict):
            return raw, None
        if isinstance(raw, dict):
            return Verdict.from_dict(raw), None
        if hasattr(raw, "to_dict"):
            return Verdict.from_dict(raw.to_dict()), None
        raise TypeError(f"评分入口返回了不支持的类型: {type(raw).__name__}")
    except Exception as exc:
        return (
            _fallback_verdict(trace, matches, hits, static, config=cfg),
            f"评分模块异常（{module_name}）: {exc}；已使用后备评分",
        )


# --------------------------------------------------------------------- 结果组装
def analyze_trace(
    trace: Trace,
    *,
    static: dict[str, Any] | None = None,
    config: Config | None = None,
    extra_notes: Iterable[str] | None = None,
    include_upstream: bool = False,
) -> ScanResult:
    """trace -> 规则 -> 检测器 -> 评分 -> ScanResult（离线可重放）。"""
    cfg = config or Config.load()
    static_payload = dict(static or {})
    matches, rules_note = run_rules(trace, config=cfg, include_upstream=include_upstream)
    hits, detectors_note = run_detectors(trace, config=cfg)
    verdict, scoring_note = run_scoring(trace, matches, hits, static_payload, config=cfg)

    tactics = set(verdict.tactics)
    techniques = set(verdict.techniques)
    for match in matches:
        meta = RuleMeta(name=match.name, attack=list(match.attack))
        tactics.update(meta.tactics())
        techniques.update(meta.techniques())
    for hit in hits:
        if hit.tactic:
            tactics.add(hit.tactic)
        if hit.technique:
            techniques.add(str(hit.technique).upper())
    for technique in list(techniques):
        inferred = tactic_for_technique(technique)
        if inferred:
            tactics.add(inferred)
    verdict.tactics = sorted(tactics)
    verdict.techniques = sorted(techniques)

    notes: list[str] = [str(note) for note in (extra_notes or []) if note]
    for note in (rules_note, detectors_note, scoring_note):
        if note:
            notes.append(note)
    if trace.summary.truncated:
        notes.append("轨迹事件被裁剪（summary.truncated=true），结论置信度需下调。")
    for note in verdict.notes:
        if note and note not in notes:
            notes.append(str(note))

    rules_available = rules_note is None or bool(matches)
    detectors_available = detectors_note is None or bool(hits)
    scoring_engine = scoring_note is None
    extra: dict[str, Any] = {
        "engine_version": __version__,
        "source_path": str(trace.extra.get("source_path") or trace.sample.name),
        "policy": trace.engine.policy,
        "thresholds": {
            "clean_below": float(cfg.scoring.clean_below),
            "malicious_at": float(cfg.scoring.malicious_at),
        },
        "analysis": {
            "rules_available": rules_available,
            "detectors_available": detectors_available,
            "scoring": "engine" if scoring_engine else "fallback",
            "include_upstream": bool(include_upstream),
            "rules_count": len(matches),
            "detectors_count": len(hits),
        },
    }
    result = ScanResult.from_trace(
        trace,
        static=static_payload,
        matches=matches,
        hits=hits,
        verdict=verdict,
        notes=notes,
        extra=extra,
    )
    return result



# --------------------------------------------------------------------- 类型与执行能力
# DLL/SYS/OCX/CPL/SCR 一律静态分析：containment 里的 DLL 加载实现（rundll32/regsvr32）
# 只作为实验代码保留，**不接入 pipeline**。原因：rundll32 调用任意导出会崩溃，曾伴随 explorer 崩溃循环。
_DYNAMIC_PE_SUFFIX_EXCLUDE = {".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi"}
_DYNAMIC_SUFFIXES = {
    SampleType.SCRIPT_POWERSHELL: {".ps1"},
    SampleType.SCRIPT_BATCH: {".bat", ".cmd"},
    SampleType.SCRIPT_JS: {".js"},
    SampleType.SCRIPT_VBS: {".vbs"},
}


def dynamically_executable(sample: Sample) -> bool:
    """判断样本能否交给沙箱动态执行（与 containment 的启动器能力一致）。"""
    suffix = Path(sample.name).suffix.lower()
    if sample.type in (SampleType.PE32, SampleType.PE64):
        return suffix not in _DYNAMIC_PE_SUFFIX_EXCLUDE
    allowed = _DYNAMIC_SUFFIXES.get(sample.type)
    return bool(allowed) and suffix in allowed


def _static_only_trace(sample: Sample, *, policy: str) -> Trace:
    """给不执行的文件构造一条空轨迹，让规则/检测/评分/报告链路仍可跑。"""
    from ..trace.normalize import EventBuilder, build_trace
    from ..trace.schema import SandboxInfo, SandboxLimits

    builder = EventBuilder(max_events=1, source="static-only")
    sandbox = SandboxInfo(
        host=_platform.node(),
        isolation=["static-only", "no-execution"],
        limits=SandboxLimits(timeout_s=0, mem_mb=0, cpu_s=0, network="n/a"),
        started_at="",
        ended_at="",
        terminated_by="not-executed",
    )
    return build_trace(
        sample=sample,
        engine_version=__version__,
        backend="static",
        policy=policy,
        sandbox=sandbox,
        builder=builder,
    )

def _archive_rank(verdict: str) -> int:
    return {"clean": 0, "suspicious": 1, "malicious": 2}.get(str(verdict), 0)


def _safe_member_name(name: str) -> tuple[str, str]:
    """校验 zip 条目路径；返回 (安全相对路径, 跳过原因)。"""
    normalized = str(name or "").replace(chr(92), "/")
    if not normalized:
        return "", "空路径"
    if normalized.startswith("/") or normalized.startswith("//"):
        return "", "绝对路径"
    if len(normalized) >= 2 and normalized[1] == ":":
        return "", "盘符路径"
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts:
        return "", "目录"
    if any(part == ".." for part in parts):
        return "", "路径穿越"
    return "/".join(parts), ""


def _member_is_symlink(info: zipfile.ZipInfo) -> bool:
    try:
        mode = (int(info.external_attr or 0) >> 16) & 0o170000
    except (TypeError, ValueError):
        return False
    return mode == 0o120000


def _archive_safe_filename(index: int, member_name: str) -> str:
    base = member_name.rsplit("/", 1)[-1] or "entry.bin"
    cleaned = "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in base).strip("._-")
    if not cleaned:
        cleaned = "entry.bin"
    return f"{index:04d}_{cleaned[:120]}"


def _archive_entry_meta(entry_name: str, result: ScanResult, *, nested: bool) -> dict[str, Any]:
    static = dict(result.static or {})
    signals = [dict(item) for item in (static.get("signals") or []) if isinstance(item, dict)]
    return {
        "name": entry_name,
        "size": int(result.sample.get("size") or 0),
        "type": str(result.sample.get("type") or "unknown"),
        "sha256": str(result.sample.get("sha256") or ""),
        "verdict": result.verdict_name,
        "score": round(float(result.verdict.score), 3),
        "confidence": round(float(result.verdict.confidence), 3),
        "signals": signals[:20],
        "nested": bool(nested),
    }


def _analyze_archive_entry(
    extracted: Path,
    entry_name: str,
    *,
    cfg: Config,
    policy: str | None,
    include_upstream: bool,
) -> ScanResult:
    """单个压缩包条目：只做静态分析，绝不执行（即使条目是 exe）。"""
    entry_sample = Sample.from_path(extracted)
    entry_sample.name = entry_name
    static_payload = run_static(extracted, config=cfg)
    trace = _static_only_trace(entry_sample, policy=(policy or cfg.default_policy))
    return analyze_trace(
        trace,
        static=static_payload,
        config=cfg,
        include_upstream=include_upstream,
    )


def _extract_zip_entries(zip_path: Path, workdir: Path) -> dict[str, Any]:
    """安全展开 zip（一层）：防穿越/符号链接/目录，限条目数、单文件与总解压量。"""
    result: dict[str, Any] = {
        "entries": [],
        "skipped": [],
        "discovered": 0,
        "truncated": False,
        "expanded_bytes": 0,
    }
    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        result["skipped"].append({"name": zip_path.name, "reason": f"压缩包解析失败: {exc}"})
        result["truncated"] = True
        return result

    with archive:
        infos = archive.infolist()
        expanded = 0
        for infos_index, info in enumerate(infos):
            raw_name = info.filename
            if info.is_dir() or str(raw_name).endswith("/"):
                result["skipped"].append({"name": raw_name, "reason": "目录"})
                continue
            result["discovered"] += 1
            if len(result["entries"]) >= MAX_ARCHIVE_ENTRIES:
                result["truncated"] = True
                result["skipped"].append({"name": raw_name, "reason": f"超出条目上限 {MAX_ARCHIVE_ENTRIES}"})
                continue
            safe_name, reason = _safe_member_name(raw_name)
            if reason:
                result["skipped"].append({"name": raw_name, "reason": reason})
                continue
            if _member_is_symlink(info):
                result["skipped"].append({"name": safe_name, "reason": "符号链接"})
                continue
            if int(info.flag_bits or 0) & 0x1:
                result["skipped"].append({"name": safe_name, "reason": "加密条目"})
                continue
            declared = int(info.file_size or 0)
            if declared > MAX_ARCHIVE_FILE_BYTES:
                result["skipped"].append(
                    {"name": safe_name, "reason": f"单文件超过上限 {MAX_ARCHIVE_FILE_BYTES} 字节"}
                )
                continue
            if expanded + declared > MAX_ARCHIVE_TOTAL_BYTES:
                result["truncated"] = True
                result["skipped"].append(
                    {"name": safe_name, "reason": f"总解压量超过上限 {MAX_ARCHIVE_TOTAL_BYTES} 字节"}
                )
                continue
            filename = _archive_safe_filename(infos_index + 1, safe_name)
            target = workdir / filename
            written = 0
            try:
                with archive.open(info) as source, target.open("wb") as dest:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_ARCHIVE_FILE_BYTES:
                            raise ValueError(f"单文件超过上限 {MAX_ARCHIVE_FILE_BYTES} 字节")
                        if expanded + written > MAX_ARCHIVE_TOTAL_BYTES:
                            raise OverflowError(f"总解压量超过上限 {MAX_ARCHIVE_TOTAL_BYTES} 字节")
                        dest.write(chunk)
            except OverflowError as exc:
                target.unlink(missing_ok=True)
                result["truncated"] = True
                result["skipped"].append({"name": safe_name, "reason": str(exc)})
                continue
            except (RuntimeError, ValueError, OSError, zipfile.BadZipFile) as exc:
                target.unlink(missing_ok=True)
                result["skipped"].append({"name": safe_name, "reason": f"解压失败: {exc}"})
                continue
            expanded += written
            result["expanded_bytes"] = expanded
            result["entries"].append(
                {
                    "name": safe_name,
                    "path": target,
                    "size": written,
                    "nested": Path(safe_name).suffix.lower() in _ARCHIVE_SUFFIXES,
                }
            )
    return result


def _build_archive_result(
    target: Path,
    sample: Sample,
    static_payload: dict[str, Any],
    *,
    cfg: Config,
    policy: str | None,
    include_upstream: bool,
    expanded: bool,
    expanded_entries: list[tuple[dict[str, Any], ScanResult]] | None = None,
    extract_info: dict[str, Any] | None = None,
) -> ScanResult:
    trace = _static_only_trace(sample, policy=(policy or cfg.default_policy))
    result = analyze_trace(
        trace,
        static=static_payload,
        config=cfg,
        include_upstream=include_upstream,
    )
    result.extra["input"] = "static-only"
    result.extra["backend"] = {
        "backend": "static",
        "requested": policy or cfg.default_policy,
        "fallback": False,
        "attempts": [],
    }
    archive_info: dict[str, Any] = {
        "expanded": bool(expanded),
        "format": sample.type.value,
        "count": 0,
        "discovered": 0,
        "entries": [],
        "skipped": [],
        "truncated": False,
        "expanded_bytes": 0,
        "max_entries": MAX_ARCHIVE_ENTRIES,
        "max_total_bytes": MAX_ARCHIVE_TOTAL_BYTES,
        "max_file_bytes": MAX_ARCHIVE_FILE_BYTES,
        "max_depth": MAX_ARCHIVE_DEPTH,
    }
    notes: list[str] = []
    if expanded and extract_info is not None and expanded_entries is not None:
        entries = [meta for meta, _ in expanded_entries]
        archive_info.update(
            {
                "count": len(entries),
                "discovered": int(extract_info.get("discovered") or 0),
                "entries": entries,
                "skipped": list(extract_info.get("skipped") or []),
                "truncated": bool(extract_info.get("truncated")),
                "expanded_bytes": int(extract_info.get("expanded_bytes") or 0),
            }
        )
        if expanded_entries:
            worst_meta, worst_result = max(
                expanded_entries,
                key=lambda pair: (_archive_rank(pair[0].get("verdict", "")), float(pair[0].get("score") or 0.0)),
            )
            tactics: set[str] = set()
            techniques: set[str] = set()
            for _, entry_result in expanded_entries:
                tactics.update(entry_result.verdict.tactics)
                techniques.update(entry_result.verdict.techniques)
            confidence = max(
                float(entry_result.verdict.confidence) for _, entry_result in expanded_entries
            )
            worst_score = max(float(entry.verdict.score) for _, entry in expanded_entries)
            items = list(result.verdict.items)
            items.append(
                ScoreItem(
                    kind="static",
                    ref=f"archive/{worst_meta.get('name', '')}",
                    score=float(worst_meta.get("score") or 0.0),
                    detail=(
                        f"压缩包最严重条目（汇总取 max）：{worst_meta.get('name', '')} "
                        f"{worst_meta.get('verdict', '')} score={worst_meta.get('score', 0)}"
                    ),
                )
            )
            result.verdict.verdict = str(worst_meta.get("verdict") or result.verdict.verdict)
            result.verdict.score = round(worst_score, 3)
            result.verdict.confidence = round(min(1.0, confidence), 3)
            result.verdict.tactics = sorted(tactics)
            result.verdict.techniques = sorted(techniques)
            result.verdict.items = items
            notes.append(
                f"压缩包内共 {archive_info['discovered']} 个文件，已静态分析 {len(entries)} 个，"
                f"最严重条目 {worst_meta.get('name', '')}（score={worst_meta.get('score', 0):.2f}，"
                f"{worst_meta.get('verdict', '')}）"
            )
            notes.append("压缩包条目只做静态分析（不执行），避免批量可执行文件动态执行；结论置信度按静态信号加权。")
        else:
            notes.append(
                f"压缩包内共 {archive_info['discovered']} 个文件，安全限制下未静态分析任何条目，"
                "仅归档级静态信号可用。"
            )
        if archive_info["truncated"]:
            notes.append(
                f"压缩包展开触发安全上限（条目<={MAX_ARCHIVE_ENTRIES}、总量<={MAX_ARCHIVE_TOTAL_BYTES} 字节），"
                "结果已截断（truncated=True），仅分析前部条目。"
            )
        if archive_info["skipped"]:
            notes.append(
                f"跳过 {len(archive_info['skipped'])} 个条目（路径穿越/符号链接/目录/加密/超限等），详见 extra.archive.skipped。"
            )
        nested_names = [meta["name"] for meta in entries if meta.get("nested")]
        if nested_names:
            notes.append(
                f"嵌套压缩包仅做归档级静态分析、不递归解压（深度上限 {MAX_ARCHIVE_DEPTH}）："
                + ", ".join(nested_names[:5])
            )
    else:
        if sample.type == SampleType.ARCHIVE_ZIP:
            notes.append("已禁用压缩包展开（--no-archive-expand），仅归档级静态分析。")
        elif sample.type in (SampleType.ARCHIVE_RAR, SampleType.ARCHIVE_7Z):
            notes.append(
                f"{sample.type.value} 压缩包无解压能力（仅支持 zip 一层展开），仅归档级静态分析。"
            )
        else:
            notes.append(f"压缩包类型 {sample.type.value} 未展开，仅归档级静态分析。")
        if static_payload.get("available") is False:
            notes.append(f"静态分析不可用：{static_payload.get('reason', '未知原因')}")
    result.extra["archive"] = archive_info
    existing_notes = [str(note) for note in (result.notes or []) if str(note).strip()]
    result.notes = notes + [note for note in existing_notes if note not in notes]
    result.extra["source_path"] = str(target)
    return result


def _scan_archive(
    target: Path,
    sample: Sample,
    static_payload: dict[str, Any],
    *,
    cfg: Config,
    policy: str | None,
    include_upstream: bool,
) -> ScanResult:
    """zip 安全展开 -> 逐条目静态分析 -> 聚合判定（最严重条目 + max 分数）。"""
    with tempfile.TemporaryDirectory(prefix="tianti_zip_") as tmp:
        workdir = Path(tmp)
        extract_info = _extract_zip_entries(target, workdir)
        expanded_entries: list[tuple[dict[str, Any], ScanResult]] = []
        for entry in extract_info.get("entries") or []:
            extracted = Path(entry.get("path") or "")
            if not extracted.exists():
                continue
            try:
                entry_result = _analyze_archive_entry(
                    extracted,
                    str(entry.get("name") or extracted.name),
                    cfg=cfg,
                    policy=policy,
                    include_upstream=include_upstream,
                )
            except Exception as exc:  # 单条目异常隔离
                extract_info.setdefault("skipped", []).append(
                    {"name": entry.get("name", ""), "reason": f"静态分析异常: {exc}"}
                )
                continue
            meta = _archive_entry_meta(
                str(entry.get("name") or extracted.name),
                entry_result,
                nested=bool(entry.get("nested")),
            )
            meta["size"] = int(entry.get("size") or meta.get("size") or 0)
            expanded_entries.append((meta, entry_result))
        return _build_archive_result(
            target,
            sample,
            static_payload,
            cfg=cfg,
            policy=policy,
            include_upstream=include_upstream,
            expanded=True,
            expanded_entries=expanded_entries,
            extract_info=extract_info,
        )


def _is_trace_file(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(payload, dict) and payload.get("schema") == schema.SCHEMA_ID


# --------------------------------------------------------------------- 静态 / 执行
def _call_static(func: Callable[..., Any], path: Path) -> Any:
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return func(str(path))
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        and parameter.default is parameter.empty
    ]
    if not positional:
        return func()
    first = positional[0]
    if "sample" in first.name.lower():
        return func(Sample.from_path(path))
    return func(str(path))


def run_static(path: Path, *, config: Config | None = None) -> dict[str, Any]:
    """静态预筛（M1 未就绪时返回 available=False，不影响回放链路）。"""
    func, module_name, reasons = _resolve(STATIC_MODULES, STATIC_ENTRIES)
    if func is None:
        return {"available": False, "reason": "静态分析尚未接通（" + _reason_text(reasons) + "）"}
    try:
        raw = _call_static(func, path)
    except Exception as exc:
        return {"available": False, "reason": f"静态分析异常（{module_name}）: {exc}"}
    if isinstance(raw, dict):
        payload = dict(raw)
        payload.setdefault("available", True)
        return payload
    to_dict = getattr(raw, "to_dict", None)
    if callable(to_dict):
        payload = dict(to_dict())
        payload.setdefault("available", True)
        return payload
    return {"available": True, "summary": str(raw)}


def run_backend(
    path: str | Path,
    *,
    policy_name: str | None = None,
    config: Config | None = None,
) -> tuple[Trace, dict[str, Any]]:
    """按策略选择沙箱后端执行样本；全部不可用时抛 SandboxUnavailable。"""
    cfg = config or Config.load()
    target = Path(path)
    if not target.exists():
        raise SampleError(f"样本不存在: {target}", path=str(target))
    if not target.is_file():
        raise SampleError(f"不是普通文件: {target}", path=str(target))
    sample = Sample.from_path(target)
    policy_name = policy_name or cfg.default_policy
    policy = SandboxPolicy.from_config(cfg.policy(policy_name))
    candidates = list(dict.fromkeys((policy.backend, *BACKEND_ORDER)))
    tried: list[str] = []
    for name in candidates:
        module_name = f"tianti.sandbox.{name}"
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            tried.append(f"{name}: 模块未实现")
            continue
        except Exception as exc:
            tried.append(f"{name}: 导入失败（{exc}）")
            continue
        backend = getattr(module, "BACKEND", None)
        if backend is None or not hasattr(backend, "available"):
            tried.append(f"{name}: 未导出 BACKEND.available()")
            continue
        try:
            ok, reason = backend.available()
        except Exception as exc:
            tried.append(f"{name}: 可用性检测异常（{exc}）")
            continue
        if not ok:
            tried.append(f"{name}: {reason}")
            continue
        try:
            trace = backend.run(sample, policy)
        except Exception as exc:
            tried.append(f"{name}: 执行失败（{exc}）")
            continue
        trace.extra["source_path"] = str(target)
        return trace, {
            "backend": name,
            "requested": policy.backend,
            "policy": policy.name,
            "fallback": name != policy.backend,
            "attempts": list(tried),
        }
    raise SandboxUnavailable(
        "沙箱后端不可用: " + "；".join(tried),
        path=str(target),
        requested=policy.backend,
        tried=tried,
    )


def scan_path(
    path: str | Path,
    *,
    policy: str | None = None,
    config: Config | None = None,
    include_upstream: bool = False,
    expand_archives: bool = True,
) -> ScanResult:
    """一条命令完成扫描：trace JSON -> 离线分析；其他文件 -> 静态 + 沙箱 + 分析。"""
    cfg = config or Config.load()
    target = Path(path)
    if not target.exists():
        raise SampleError(f"路径不存在: {target}", path=str(target))
    if target.is_dir():
        raise SampleError(f"scan_path 只接受文件: {target}", path=str(target))

    if target.suffix.lower() == ".json" and _is_trace_file(target):
        trace = schema.load(target)
        result = analyze_trace(
            trace,
            static={"available": False, "reason": "输入为回放 trace，不包含静态预筛阶段"},
            config=cfg,
            include_upstream=include_upstream,
        )
        result.notes.insert(0, "输入为 trace JSON：离线重放分析，未执行样本。")
        result.extra["input"] = "replay"
        result.extra["source_path"] = str(target)
        return result

    static_payload = run_static(target, config=cfg)
    sample = Sample.from_path(target)
    if sample.type == SampleType.ARCHIVE_ZIP and expand_archives:
        return _scan_archive(
            target,
            sample,
            static_payload,
            cfg=cfg,
            policy=policy,
            include_upstream=include_upstream,
        )
    if sample.type in _ARCHIVE_TYPES:
        return _build_archive_result(
            target,
            sample,
            static_payload,
            cfg=cfg,
            policy=policy,
            include_upstream=include_upstream,
            expanded=False,
        )
    if not dynamically_executable(sample):
        trace = _static_only_trace(sample, policy=(policy or cfg.default_policy))
        result = analyze_trace(trace, static=static_payload, config=cfg, include_upstream=include_upstream)
        result.notes.insert(
            0,
            f"样本类型 {sample.type.value} 不支持沙箱动态执行，已完成静态分析"
            "（无行为轨迹，结论仅基于静态信号/文件名/内容特征，置信度相应降低）。",
        )
        result.extra["input"] = "static-only"
        result.extra["backend"] = {
            "backend": "static",
            "requested": policy or cfg.default_policy,
            "fallback": False,
            "attempts": [],
        }
        return result
    trace, backend_info = run_backend(target, policy_name=policy, config=cfg)
    trace.extra.setdefault("source_path", str(target))
    result = analyze_trace(trace, static=static_payload, config=cfg, include_upstream=include_upstream)
    result.extra["input"] = "sandbox"
    result.extra["backend"] = backend_info
    if backend_info.get("fallback"):
        attempts = "；".join(backend_info.get("attempts") or [])
        result.notes.insert(
            0,
            f"沙箱后端 {backend_info.get('requested')} 不可用，已回退 {backend_info.get('backend')}"
            + (f"（{attempts}）" if attempts else ""),
        )
    return result


# --------------------------------------------------------------------- 规则/检测器管理
def _describe_pack(modules: Iterable[str], entries: Iterable[str], directory: Path, label: str) -> dict[str, Any]:
    func, module_name, reasons = _resolve(modules, entries)
    if func is not None:
        try:
            raw = _call_with_context(
                func,
                {
                    "path": directory,
                    "rules_dir": directory,
                    "detectors_dir": directory,
                    "pack_dir": directory,
                    "path_dir": directory,
                },
            )
            if raw is None:
                raw = []
            items = _as_items(raw, "rules", "detectors", "items", "specs")
            names: list[str] = []
            namespaces: list[str] = []
            errors: list[str] = []
            unsupported: list[str] = []
            for item in items:
                meta = getattr(item, "meta", None) or getattr(item, "spec", None) or item
                if isinstance(meta, dict):
                    names.append(str(meta.get("name") or meta.get("id") or ""))
                    namespaces.append(str(meta.get("namespace") or meta.get("tactic") or ""))
                else:
                    names.append(str(getattr(meta, "name", "") or getattr(meta, "id", "")))
                    namespaces.append(str(getattr(meta, "namespace", "") or getattr(meta, "tactic", "")))
            source = getattr(raw, "errors", None)
            if source:
                errors.extend(str(item) for item in source)
            source = getattr(raw, "unsupported", None)
            if source:
                unsupported.extend(str(item) for item in source)
            return {
                "available": True,
                "engine": module_name,
                "count": len(items),
                "rules" if label == "规则" else "detectors": names,
                "namespaces": namespaces,
                "errors": errors,
                "unsupported": unsupported,
            }
        except Exception as exc:
            reasons.append(f"加载异常: {exc}")
    files: list[str] = []
    if directory.exists():
        for pattern in ("*.yml", "*.yaml"):
            files.extend(str(path.relative_to(directory)) for path in sorted(directory.rglob(pattern)))
    return {
        "available": False,
        "engine": module_name or None,
        "count": len(files),
        "files": files,
        "reason": f"{label}引擎尚未接通（" + _reason_text(reasons) + "）",
    }


def describe_rules(config: Config | None = None, *, include_upstream: bool = False) -> dict[str, Any]:
    """规则包摘要；include_upstream=True 时把 rules/upstream 一并加载统计。"""
    cfg = config or Config.load()
    directory = cfg.paths.rules
    files: list[str] = []
    if directory.exists():
        for pattern in ("*.yml", "*.yaml"):
            files.extend(str(path.relative_to(directory)) for path in sorted(directory.rglob(pattern)))
    upstream_dir = directory / "upstream"
    upstream_files: list[str] = []
    if upstream_dir.is_dir():
        for pattern in ("*.yml", "*.yaml"):
            upstream_files.extend(
                str(path.relative_to(upstream_dir)) for path in sorted(upstream_dir.rglob(pattern))
            )
    upstream = {
        "requested": bool(include_upstream),
        "available": upstream_dir.is_dir() and bool(upstream_files),
        "path": str(upstream_dir),
        "files": len(upstream_files),
        "reason": "",
    }
    if include_upstream and not upstream["available"]:
        upstream["reason"] = "rules/upstream 尚未就绪（等待 rules 完成上游规则导入）"
    try:
        from ..rules.packs import load_rulepack
    except Exception as exc:
        return {
            "available": False,
            "engine": None,
            "count": len(files) + len(upstream_files),
            "files": files,
            "upstream": upstream,
            "reason": f"规则引擎尚未接通（{exc}）",
        }
    subdirs = [directory / "capability", directory / "attack"]
    targets: list[Path] = [path for path in subdirs if path.is_dir()]
    if not targets and directory.is_dir():
        targets = [directory]
    if include_upstream and upstream["available"]:
        targets.append(upstream_dir)
    if not targets:
        return {
            "available": False,
            "engine": "tianti.rules.packs",
            "count": len(files) + len(upstream_files),
            "files": files,
            "upstream": upstream,
            "reason": f"规则目录为空或不存在: {directory}",
        }
    try:
        loaded = load_rulepack(targets)
    except Exception as exc:
        return {
            "available": False,
            "engine": "tianti.rules.packs",
            "count": len(files) + len(upstream_files),
            "files": files,
            "upstream": upstream,
            "reason": f"规则包加载失败: {exc}",
        }
    rules = loaded.rules
    warnings = list(loaded.lint.warnings)
    if upstream["requested"] and not upstream["available"]:
        warnings.append(upstream["reason"])
    return {
        "available": True,
        "engine": "tianti.rules.packs",
        "count": len(rules),
        "files_count": len(loaded.files),
        "files": files,
        "upstream": upstream,
        "rules": [rule.name for rule in rules],
        "namespaces": [rule.meta.namespace for rule in rules],
        "errors": list(loaded.lint.errors),
        "warnings": warnings,
        "unsupported": list(loaded.unsupported),
    }


def describe_detectors(config: Config | None = None) -> dict[str, Any]:
    cfg = config or Config.load()
    return _describe_pack(
        ("tianti.detect.detectors", "tianti.detect.registry", "tianti.detect.engine"),
        ("load_detectors", "list_detectors", "load_all", "load"),
        cfg.paths.detectors,
        "检测器",
    )


def validate_rules(
    config: Config | None = None,
    *,
    include_upstream: bool = False,
) -> tuple[bool, dict[str, Any]]:
    info = describe_rules(config, include_upstream=include_upstream)
    if not info.get("available"):
        return False, info
    if include_upstream and not (info.get("upstream") or {}).get("available"):
        return False, info
    return not info.get("errors"), info
