"""ScanResult 的 JSON 落盘与读取（JSONR = 结果 JSON 序列化）。

报告/API 统一使用 tianti.result/1；落盘用 UTF-8、ensure_ascii=False，
保证中文文件名与路径可读。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .base import RESULT_SCHEMA, ScanResult

JSONR_SCHEMA = RESULT_SCHEMA
_RESULT_SUFFIX = ".json"
_UNSAFE_NAME_RE = re.compile(r"[^0-9A-Za-z._-]+")


def dumps(result: ScanResult, *, indent: int = 2) -> str:
    """把 ScanResult 序列化为 JSON 文本。"""
    return result.dumps(indent=indent)


def loads(text: str) -> ScanResult:
    """从 JSON 文本反序列化；结构不合法抛出 ReportError。"""
    try:
        payload: Any = json.loads(text)
    except ValueError as exc:
        from ..core.errors import ReportError

        raise ReportError(f"结果 JSON 解析失败: {exc}") from exc
    return ScanResult.from_dict(payload)


def save(result: ScanResult, path: str | Path, *, indent: int = 2) -> Path:
    """把结果写入 path（自动创建父目录），返回实际路径。"""
    return result.save(path, indent=indent)


def load(path: str | Path) -> ScanResult:
    """从 path 读取结果（自动校验 schema）。"""
    return ScanResult.load(path)


# 语义化别名，便于 CLI/API 调用
save_result = save
load_result = load


def safe_stem(name: str) -> str:
    """把任意样本名/path 片段转成安全文件名主干（无路径分隔符与通配符）。"""
    stem = Path(str(name or "sample")).name
    if stem.lower().endswith(_RESULT_SUFFIX):
        stem = stem[: -len(_RESULT_SUFFIX)]
    return _UNSAFE_NAME_RE.sub("_", stem).strip("._-") or "sample"


def result_filename(sample_name: str, *, suffix: str = "result") -> str:
    """生成安全的默认结果文件名（保留可读字符，去掉路径分隔符）。"""
    return f"{safe_stem(sample_name)}.{suffix}{_RESULT_SUFFIX}"


def default_result_path(out_dir: str | Path, sample_name: str) -> Path:
    """在输出目录下为样本生成默认结果路径。"""
    return Path(out_dir) / result_filename(sample_name)
