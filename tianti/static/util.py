"""静态分析通用工具：熵计算、信号构造与校验、文本解码。"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

# 信号严重度，与 tianti.detect.base.SEVERITIES 保持一致
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# 默认静态评分权重（供 detect/scoring 直接消费；signal 可显式覆盖）
SEVERITY_SCORE = {"low": 2.0, "medium": 5.0, "high": 10.0, "critical": 20.0}

# 信号命名：category.signal，两个小写段（如 pe.entropy_high）
_SIGNAL_ID_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")


class StaticError(Exception):
    """静态分析内部错误（不暴露给上层崩溃，analyze 内部兜底）。"""


def signal(
    signal_id: str,
    severity: str,
    detail: str,
    *,
    score: float | None = None,
) -> dict[str, Any]:
    """构造一个静态信号；命名/严重度非法时抛 ValueError（开发期尽早暴露）。

    额外带 score 字段（按严重度给出默认权重），detect/scoring 可直接消费；
    已知无害测试文件（EICAR）显式传 score=0 避免被当成真实威胁计分。
    """
    if not _SIGNAL_ID_RE.match(signal_id):
        raise ValueError(f"非法信号 id（应为 category.signal）: {signal_id}")
    if severity not in SEVERITIES:
        raise ValueError(f"非法严重度: {severity}")
    value = SEVERITY_SCORE[severity] if score is None else float(score)
    return {"id": signal_id, "severity": severity, "detail": detail, "score": value}


def merge_signals(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """按 id 去重合并信号，保留最高严重度与最高 score，detail 拼接（最多 4 段）。"""
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for group in groups:
        for item in group or []:
            sid = str(item.get("id", ""))
            if not sid:
                continue
            sev = str(item.get("severity", "low"))
            detail = str(item.get("detail", ""))
            try:
                score = float(item.get("score", 0.0) or 0.0)
            except (TypeError, ValueError):
                score = 0.0
            if sid not in merged:
                merged[sid] = {"id": sid, "severity": sev, "detail": detail, "score": score}
                order.append(sid)
                continue
            current = merged[sid]
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(current["severity"], 0):
                current["severity"] = sev
            current["score"] = max(float(current.get("score", 0.0)), score)
            if detail and detail not in current["detail"]:
                parts = [p for p in current["detail"].split("；") if p]
                if len(parts) < 4:
                    parts.append(detail)
                    current["detail"] = "；".join(parts)
    return [merged[sid] for sid in order]


def max_severity(signals: list[dict[str, str]]) -> str:
    value = "low"
    for item in signals or []:
        if SEVERITY_RANK.get(str(item.get("severity", "")), 0) > SEVERITY_RANK[value]:
            value = str(item.get("severity"))
    return value


# 熵只统计前 64 KiB：静态预筛的加壳/加密启发不需要全文件精度，
# 但纯 Python 统计大文件会破坏 <100ms/样本的预算。
ENTROPY_SAMPLE_BYTES = 64 * 1024


def shannon_entropy(data: bytes, *, limit: int = ENTROPY_SAMPLE_BYTES) -> float:
    """字节香农熵（0..8）；大文件只统计前 limit 字节。"""
    if not data:
        return 0.0
    sample = data[:limit] if len(data) > limit else data
    counts = Counter(sample)
    total = len(sample)
    result = 0.0
    for count in counts.values():
        p = count / total
        result -= p * math.log2(p)
    return round(result, 4)


def decode_text(data: bytes) -> tuple[str, str]:
    """尽力把脚本字节解码为文本，返回 (text, encoding)。"""
    if not data:
        return "", "empty"
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            return data.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            pass
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace"), "latin-1"


def read_cstring(data: bytes, offset: int, *, max_len: int = 512) -> str:
    """读取 ASCII 零结尾字符串；越界返回空串。"""
    if offset is None or offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end < 0:
        end = min(len(data), offset + max_len)
    return data[offset:end].decode("latin-1", errors="replace")
