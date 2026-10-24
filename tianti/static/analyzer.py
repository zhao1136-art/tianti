"""兼容入口：delivery 的 tianti.api.pipeline 探测 tianti.static.analyzer 的 analyze/scan/analyze_path。

真正的实现都在 .base；本模块只做 re-export，保持接口稳定。
"""

from __future__ import annotations

from typing import Any

from .base import StaticReport, analyze, analyze_bytes, analyze_path


def scan(sample: Any, data: bytes | None = None) -> StaticReport:
    """与 analyze 等价的别名（pipeline 的入口探测列表之一）。"""
    return analyze(sample, data)


__all__ = ["StaticReport", "analyze", "analyze_bytes", "analyze_path", "scan"]
