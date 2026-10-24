"""静态预筛（PE 解析、脚本/归档识别、熵、签名、加壳启发）。"""

from __future__ import annotations

from .base import StaticReport, analyze, analyze_bytes, analyze_path
from .office import CFBInfo, analyze_office, parse_cfb
from .pe import PEInfo, parse_pe

__all__ = [
    "StaticReport",
    "analyze",
    "analyze_bytes",
    "analyze_path",
    "PEInfo",
    "parse_pe",
    "CFBInfo",
    "analyze_office",
    "parse_cfb",
]
