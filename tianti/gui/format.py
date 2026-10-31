"""GUI 与 CLI 共用的纯格式化逻辑（不依赖 tkinter，便于单测）。

输入统一是 tianti.report.ScanResult；所有函数必须无副作用、可重复调用。
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable

from ..report import ScanResult

VERDICT_LABELS = {"clean": "干净", "suspicious": "可疑", "malicious": "恶意"}
VERDICT_ICONS = {"clean": "[OK]", "suspicious": "[!]", "malicious": "[X]"}
SEVERITY_LABELS = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}


def verdict_label(verdict: str) -> str:
    return VERDICT_LABELS.get(verdict, verdict or "未知")


def verdict_icon(verdict: str) -> str:
    return VERDICT_ICONS.get(verdict, "[?]")


def score_text(result: ScanResult) -> str:
    return f"{float(result.verdict.score):.2f}"


def confidence_text(result: ScanResult) -> str:
    return f"{float(result.verdict.confidence) * 100:.0f}%"


def sample_lines(result: ScanResult) -> list[str]:
    sample = dict(result.sample or {})
    trace = dict(result.trace or {})
    engine = dict(trace.get("engine") or {})
    sandbox = dict(trace.get("sandbox") or {})
    summary = dict(trace.get("summary") or {})
    lines = [
        f"样本名称 : {sample.get('name', 'unknown')}",
        f"类型     : {sample.get('type', 'unknown')}",
        f"大小     : {_human_size(sample.get('size'))}",
        f"SHA256   : {sample.get('sha256', '')}",
        f"判定     : {verdict_icon(result.verdict_name)} {verdict_label(result.verdict_name)}"
        f"  score={score_text(result)}  confidence={confidence_text(result)}",
        f"Tactics  : {', '.join(result.verdict.tactics) or '-'}",
        f"Techniques: {', '.join(result.verdict.techniques) or '-'}",
        f"规则命中 : {len(result.matches)}    危险行为: {len(result.hits)}",
        f"沙箱后端 : {engine.get('backend', '-')}    策略: {engine.get('policy', '-')}",
        f"终止方式 : {sandbox.get('terminated_by', '-')}",
        f"事件统计 : 进程 {summary.get('processes', 0)} / 文件写 {summary.get('file_writes', 0)}"
        f" / 注册表写 {summary.get('reg_sets', 0)} / 外联 {summary.get('net_connects', 0)}",
        f"轨迹裁剪 : {'是' if summary.get('truncated') else '否'}",
    ]
    backend = dict((result.extra or {}).get("backend") or {})
    if backend:
        lines.append(
            f"后端详情 : 请求 {backend.get('requested', '-')} -> 实际 {backend.get('backend', '-')}"
            + ("（回退）" if backend.get("fallback") else "")
        )
    return lines


def verdict_lines(result: ScanResult) -> list[str]:
    items = list(result.verdict.items or [])
    if not items:
        return ["（没有评分明细）"]
    lines: list[str] = []
    for item in items:
        marker = "（已抑制）" if getattr(item, "suppressed", False) else ""
        lines.append(
            f"{item.score:>8.2f}  {item.kind:<10}  {item.ref}{marker}"
            + (f"  # {item.detail}" if item.detail else "")
        )
    return lines


def capability_rows(result: ScanResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for match in result.matches:
        rows.append(
            {
                "name": match.name,
                "namespace": match.namespace,
                "scope": match.scope,
                "attck": "; ".join(match.attack),
                "techniques": ", ".join(sorted(_techniques(match.attack))),
                "evidence": ", ".join(sorted({eid for ids in match.evidence.values() for eid in ids})),
                "evidence_count": sum(len(ids) for ids in match.evidence.values()),
                "confidence": match.confidence,
                "source": match.source_path,
            }
        )
    rows.sort(key=lambda row: (row["namespace"], row["name"]))
    return rows


def detector_rows(result: ScanResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for hit in result.hits:
        rows.append(
            {
                "id": hit.detector_id,
                "name": hit.name,
                "severity": hit.severity,
                "severity_label": SEVERITY_LABELS.get(hit.severity, hit.severity),
                "score": float(hit.score),
                "tactic": hit.tactic,
                "technique": hit.technique,
                "evidence": ", ".join(hit.evidence),
                "evidence_count": len(hit.evidence),
                "detail": hit.detail,
                "suppressed": bool(hit.suppressed),
            }
        )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(key=lambda row: (order.get(row["severity"], 9), -row["score"], row["id"]))
    return rows


def event_rows(result: ScanResult, *, limit: int = 3000) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in result.events[:limit]:
        rows.append(
            {
                "id": str(event.get("id", "")),
                "ts": float(event.get("ts", 0.0)),
                "kind": f"{event.get('category', '?')}/{event.get('action', '?')}",
                "pid": event.get("pid", ""),
                "image": str(event.get("image") or ""),
                "target": str(event.get("target") or ""),
                "source": str(event.get("source") or ""),
                "confidence": str(event.get("confidence") or ""),
            }
        )
    return rows


def event_line(row: dict[str, Any]) -> str:
    pid = row.get("pid")
    pid_text = f" pid={pid}" if pid not in (None, "") else ""
    return (
        f"{row['ts']:>9.3f}s  {row['id']:<7} {row['kind']:<22}{pid_text}  "
        f"{row['target'] or row['image']}    [{row['source']}/{row['confidence']}]"
    )


def static_signal_rows(result: ScanResult) -> list[dict[str, Any]]:
    static = dict(result.static or {})
    signals = static.get("signals") or []
    rows: list[dict[str, Any]] = []
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        rows.append(
            {
                "id": str(signal.get("id", "")),
                "severity": str(signal.get("severity", "")),
                "score": float(signal.get("score") or 0.0),
                "detail": str(signal.get("detail", "")),
            }
        )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(key=lambda row: (order.get(row["severity"], 9), -row["score"]))
    return rows


def archive_rows(result: ScanResult) -> list[dict[str, Any]]:
    """压缩包条目列表（来自 pipeline 的 extra.archive.entries）。"""
    extra = dict(result.extra or {})
    archive = dict(extra.get("archive") or {})
    rows: list[dict[str, Any]] = []
    for entry in archive.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        rows.append(
            {
                "name": str(entry.get("name", "")),
                "type": str(entry.get("type", "")),
                "size": int(entry.get("size") or 0),
                "verdict": str(entry.get("verdict", "")),
                "verdict_label": verdict_label(str(entry.get("verdict", ""))),
                "score": float(entry.get("score") or 0.0),
                "sha256": str(entry.get("sha256", "")),
                "signals": len(entry.get("signals") or []),
                "nested": bool(entry.get("nested")),
            }
        )
    return rows


def archive_summary_lines(result: ScanResult, *, limit: int = 50) -> list[str]:
    """GUI 摘要里的【压缩包内容】表格文本（最多 limit 条）。"""
    extra = dict(result.extra or {})
    archive = dict(extra.get("archive") or {})
    if not archive:
        return []
    if archive.get("malformed"):
        return [
            "",
            f"【压缩包内容】解析失败：{archive.get('error') or '不是有效 ZIP'}",
            "  该文件扩展名/类型为 zip，但内容不是有效 ZIP（可能损坏、截断、加密或改名）",
            "  已回退为原始数据静态分析（字符串 / 熵 / 内嵌载荷）",
        ]
    rows = archive_rows(result)
    discovered = int(archive.get("discovered") or len(rows))
    truncated = bool(archive.get("truncated"))
    lines = [
        "",
        f"【压缩包内容】共 {discovered} 个文件，已静态分析 {len(rows)} 个"
        + ("（已触发上限，结果截断）" if truncated else ""),
        f"  {'名称':<44}{'类型':<16}{'大小':>10}  {'判定':<4}{'分数':>7}",
    ]
    for row in rows[:limit]:
        lines.append(
            f"  {row['name'][:44]:<44}{row['type'][:16]:<16}{_human_size(row['size']):>10}  "
            f"{row['verdict_label']:<4}{row['score']:>8.2f}"
        )
    if len(rows) > limit:
        lines.append(f"  ...（仅显示前 {limit} 条，共 {len(rows)} 条）")
    skipped = archive.get("skipped") or []
    if skipped:
        lines.append(f"  跳过 {len(skipped)} 个条目（路径穿越/符号链接/目录/加密/超限等）")
    if archive.get("expanded") is False:
        lines.append(f"  未展开：{archive.get('format', '压缩包')} 仅归档级静态分析")
    return lines


def summary_text(result: ScanResult) -> str:
    parts: list[str] = ["【样本】", *sample_lines(result), "", "【评分明细】", *verdict_lines(result)]
    signals = static_signal_rows(result)
    if signals:
        parts.extend(["", f"【静态信号】共 {len(signals)} 条"])
        for row in signals[:40]:
            parts.append(f"  {row['severity']:<8} {row['id']}  {row['detail']}")
    parts.extend(archive_summary_lines(result))
    notes = [str(note) for note in (result.notes or []) if str(note).strip()]
    if notes:
        parts.extend(["", "【备注】", *[f"  - {note}" for note in notes]])
    return "\n".join(parts)


def notes_text(result: ScanResult) -> str:
    notes = [f"- {note}" for note in (result.notes or []) if str(note).strip()]
    extra = dict(result.extra or {})
    analysis = dict(extra.get("analysis") or {})
    if analysis:
        notes.append("")
        notes.append("【分析开关】")
        notes.append(f"  规则可用: {analysis.get('rules_available')}")
        notes.append(f"  检测器可用: {analysis.get('detectors_available')}")
        notes.append(f"  评分来源: {analysis.get('scoring')}")
        notes.append(f"  含上游规则: {analysis.get('include_upstream')}")
    return "\n".join(notes) if notes else "（无备注）"


def json_text(result: ScanResult, *, limit_chars: int = 400_000) -> str:
    text = json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
    if len(text) > limit_chars:
        return text[:limit_chars] + "\n...（已截断）"
    return text


def _human_size(value: Any) -> str:
    try:
        size = int(value or 0)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} GB"


def _techniques(entries: Iterable[str]) -> set[str]:
    import re

    found: set[str] = set()
    for entry in entries:
        found.update(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(entry)))
    return found


# --------------------------------------------------------------------- 批量汇总
def matrix_rows(results: Iterable[ScanResult]) -> list[dict[str, Any]]:
    """多文件结果矩阵：一行一个样本，按分数降序。"""
    rows: list[dict[str, Any]] = []
    for result in results:
        tactics = sorted(set(result.verdict.tactics))
        techniques = sorted(set(result.verdict.techniques))
        input_kind = str((result.extra or {}).get("input") or "-")
        backend = str(((result.extra or {}).get("backend") or {}).get("backend") or "-")
        rows.append(
            {
                "name": result.sample_name,
                "verdict": result.verdict_name,
                "verdict_label": verdict_label(result.verdict_name),
                "score": float(result.verdict.score),
                "confidence": float(result.verdict.confidence),
                "matches": len(result.matches),
                "hits": len(result.hits),
                "tactics": ", ".join(tactics) or "-",
                "techniques": ", ".join(techniques) or "-",
                "input": input_kind,
                "backend": backend,
            }
        )
    rows.sort(key=lambda row: (-row["score"], row["name"]))
    return rows


def summary_stats(
    results: Iterable[ScanResult], *, errors: int = 0, elapsed_s: float = 0.0, active_error_files: int = 0
) -> dict[str, Any]:
    items = list(results)
    counts = {"clean": 0, "suspicious": 0, "malicious": 0}
    for result in items:
        counts[result.verdict_name] = counts.get(result.verdict_name, 0) + 1
    scores = [float(result.verdict.score) for result in items]
    tactics = sorted({tactic for result in items for tactic in result.verdict.tactics})
    techniques = sorted({technique for result in items for technique in result.verdict.techniques})
    return {
        "total": len(items),
        "clean": counts["clean"],
        "suspicious": counts["suspicious"],
        "malicious": counts["malicious"],
        "errors": int(errors),
        "avg_score": (sum(scores) / len(scores)) if scores else 0.0,
        "max_score": max(scores) if scores else 0.0,
        "matches": sum(len(result.matches) for result in items),
        "hits": sum(len(result.hits) for result in items),
        "tactics": tactics,
        "techniques": techniques,
        "elapsed_s": float(elapsed_s),
    }


def stats_line(stats: dict[str, Any]) -> str:
    line = (
        f"共 {stats['total']} 个结果：恶意 {stats['malicious']} / 可疑 {stats['suspicious']} / 干净 {stats['clean']}"
        f"    平均分 {stats['avg_score']:.1f}  最高分 {stats['max_score']:.1f}"
        f"    能力命中 {stats['matches']}  危险行为 {stats['hits']}"
    )
    extras: list[str] = []
    if stats.get("elapsed_s"):
        extras.append(f"耗时 {stats['elapsed_s']:.1f}s")
    if stats.get("errors"):
        extras.append(f"失败 {stats['errors']} 个文件")
    if extras:
        line += "    " + "  ".join(extras)
    if stats.get("tactics"):
        line += "\n覆盖战术: " + ", ".join(stats["tactics"])
    return line


def matrix_csv(rows: Iterable[dict[str, Any]]) -> str:
    """把矩阵行导出为 CSV 文本（UTF-8 BOM 由调用方决定是否加）。"""
    fields = ["name", "verdict", "score", "confidence", "matches", "hits", "tactics", "techniques", "input", "backend"]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()
