"""报告渲染（JSON / 单文件 HTML / ATT&CK 矩阵）。"""

from .base import RESULT_SCHEMA, ScanResult, load, save
from .html import render_html, save_html
from .jsonr import JSONR_SCHEMA, default_result_path, dumps, load_result, loads, save_result
from .mitre import TACTICS, build_matrix, tactic_for_technique, tactic_name, technique_name

__all__ = [
    "RESULT_SCHEMA",
    "ScanResult",
    "JSONR_SCHEMA",
    "build_matrix",
    "default_result_path",
    "dumps",
    "load",
    "load_result",
    "loads",
    "render_html",
    "save",
    "save_html",
    "save_result",
    "tactic_for_technique",
    "tactic_name",
    "technique_name",
]
