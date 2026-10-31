"""压缩包静态清单分析（zip 用 stdlib zipfile；rar/7z 只识别不展开）。

安全约束：
- 只读中央目录元数据，不解压条目内容，天然规避大多数 zip 炸弹；
- 仍对「声明」的条目数 / 总解压量 / 压缩比设阈值并出信号，供评分与报告提示；
- 限制清单条数与循环次数，避免恶意中央目录放大 CPU/内存。
"""

from __future__ import annotations

import io
import posixpath
import zipfile
from typing import Any

from .util import merge_signals, signal

MAX_ENTRIES = 500
MAX_MANIFEST = 200
MAX_TOTAL_UNCOMPRESSED = 64 * 1024 * 1024
MAX_RATIO = 100.0
MAX_ENTRY_RATIO = 1000.0

EXEC_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".pif", ".msi", ".drv"}
SCRIPT_EXTENSIONS = {
    ".ps1",
    ".psm1",
    ".psd1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".bat",
    ".cmd",
    ".hta",
    ".py",
}
SUSPICIOUS_EXTENSIONS = {".lnk", ".url", ".hta", ".reg", ".job", ".application"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".cab", ".gz", ".tar", ".iso", ".img", ".bz2", ".xz"}


def detect_format(data: bytes, name: str = "", sample_type: str = "") -> str:
    head = data[:8]
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06" or head[:4] == b"PK\x07\x08":
        return "zip"
    if head[:4] == b"Rar!":
        return "rar"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if "zip" in sample_type or suffix == "zip":
        return "zip"
    if "rar" in sample_type or suffix == "rar":
        return "rar"
    if "7z" in sample_type or suffix == "7z":
        return "7z"
    return ""


def _basename(name: str) -> str:
    return posixpath.basename(name.replace("\\", "/"))


def _extension(name: str) -> str:
    base = _basename(name)
    if "." not in base:
        return ""
    return "." + base.rsplit(".", 1)[-1].lower()


def _is_path_traversal(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        return True
    if len(normalized) >= 2 and normalized[1] == ":":
        return True
    return any(part == ".." for part in normalized.split("/"))


def _double_extension(name: str) -> bool:
    base = _basename(name).lower()
    risky = EXEC_EXTENSIONS | SCRIPT_EXTENSIONS
    parts = base.split(".")
    if len(parts) < 3:
        return False
    trailer = "." + parts[-1]
    for middle in parts[1:-1]:
        if "." + middle in (".pdf", ".doc", ".docx", ".xls", ".jpg", ".png", ".txt", ".rtf", ".csv"):
            return trailer in risky
    return False


def _empty_result(fmt: str, error: str) -> dict[str, Any]:
    return {
        "format": fmt,
        "valid": False,
        "supported": fmt in ("zip", "rar", "7z"),
        "error": error,
        "entry_count": 0,
        "total_uncompressed": 0,
        "total_compressed": 0,
        "ratio": 0.0,
        "entries": [],
        "truncated": False,
        "embedded_executables": [],
        "embedded_scripts": [],
        "signals": [
            signal(
                "archive.malformed",
                "medium",
                f"压缩包不是有效格式（{error}），已回退为原始数据静态分析（字符串/熵/内嵌载荷）",
            )
        ],
    }


def analyze_archive(data: bytes, *, name: str = "", sample_type: str = "") -> dict[str, Any]:
    """解析压缩包清单并出信号；不展开内容。"""
    fmt = detect_format(data, name, sample_type)
    if fmt in ("rar", "7z"):
        return {
            "format": fmt,
            "valid": True,
            "supported": False,
            "error": "",
            "entry_count": 0,
            "total_uncompressed": 0,
            "total_compressed": 0,
            "ratio": 0.0,
            "entries": [],
            "truncated": False,
            "embedded_executables": [],
            "embedded_scripts": [],
            "signals": [
                signal("archive.unsupported_format", "low", f"{fmt} 压缩包仅识别格式，不展开内容（M1 范围）")
            ],
        }
    if fmt != "zip":
        return _empty_result(fmt or "unknown", "未知压缩格式或魔术字节不匹配")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            return _analyze_zip_infos(infos)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
        return _empty_result("zip", f"{type(exc).__name__}: {exc}")


def _analyze_zip_infos(infos: list[zipfile.ZipInfo]) -> dict[str, Any]:
    signals: list[dict[str, str]] = []
    entries: list[dict[str, Any]] = []
    total_uncompressed = 0
    total_compressed = 0
    encrypted_entries = 0
    traversal_entries: list[str] = []
    embedded_executables: list[str] = []
    embedded_scripts: list[str] = []
    suspicious_extensions: list[str] = []
    nested_archives: list[str] = []
    has_macro = False
    double_extension_entries: list[str] = []
    entry_ratio_bombs: list[str] = []

    for info in infos:
        size = int(info.file_size or 0)
        compressed = int(info.compress_size or 0)
        total_uncompressed += size
        total_compressed += compressed
        filename = info.filename or ""
        basename = _basename(filename)
        ext = _extension(filename)
        encrypted = bool(info.flag_bits & 0x1)
        if encrypted:
            encrypted_entries += 1
        if _is_path_traversal(filename):
            traversal_entries.append(filename)
        if ext in EXEC_EXTENSIONS and not filename.endswith("/"):
            embedded_executables.append(filename)
        if ext in SCRIPT_EXTENSIONS:
            embedded_scripts.append(filename)
        if ext in SUSPICIOUS_EXTENSIONS:
            suspicious_extensions.append(filename)
        if ext in ARCHIVE_EXTENSIONS:
            nested_archives.append(filename)
        if basename.lower() == "vbaproject.bin":
            has_macro = True
        if _double_extension(filename):
            double_extension_entries.append(filename)
        if size > 10 * 1024 * 1024 and compressed > 0 and size / compressed > MAX_ENTRY_RATIO:
            entry_ratio_bombs.append(filename)
        if len(entries) < MAX_MANIFEST:
            entries.append(
                {
                    "name": filename[:300],
                    "size": size,
                    "compressed_size": compressed,
                    "is_dir": filename.endswith("/"),
                    "encrypted": encrypted,
                    "ext": ext,
                }
            )

    ratio = round(total_uncompressed / max(total_compressed, 1), 2)
    truncated = len(infos) > MAX_ENTRIES

    if not infos:
        signals.append(signal("archive.empty", "low", "空压缩包（无条目）"))
    if truncated:
        signals.append(
            signal("archive.entry_limit", "high", f"条目数 {len(infos)} 超过上限 {MAX_ENTRIES}（仅分析前 {MAX_MANIFEST} 条）")
        )
    if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
        signals.append(
            signal(
                "archive.total_size_bomb",
                "high",
                f"声明解压总量 {total_uncompressed} 字节，超过上限 {MAX_TOTAL_UNCOMPRESSED}",
            )
        )
    if ratio > MAX_RATIO and total_uncompressed > 1024 * 1024:
        signals.append(
            signal("archive.ratio_bomb", "high", f"压缩比 {ratio:.1f}（解压 {total_uncompressed} / 压缩 {total_compressed}），疑似 zip 炸弹")
        )
    if entry_ratio_bombs:
        signals.append(
            signal(
                "archive.entry_ratio_bomb",
                "medium",
                f"{len(entry_ratio_bombs)} 个条目单条压缩比 > {MAX_ENTRY_RATIO:.0f}：{', '.join(entry_ratio_bombs[:3])}",
            )
        )
    if traversal_entries:
        signals.append(
            signal(
                "archive.path_traversal",
                "high",
                f"{len(traversal_entries)} 个条目含路径穿越：{', '.join(traversal_entries[:3])}",
            )
        )
    if encrypted_entries:
        signals.append(signal("archive.encrypted", "medium", f"{encrypted_entries} 个加密条目（内容不可静态检视）"))
    if embedded_executables:
        signals.append(
            signal(
                "archive.embedded_executable",
                "high",
                f"压缩包含 {len(embedded_executables)} 个可执行条目：{', '.join(embedded_executables[:5])}",
            )
        )
    if embedded_scripts:
        signals.append(
            signal(
                "archive.embedded_script",
                "medium",
                f"压缩包含 {len(embedded_scripts)} 个脚本条目：{', '.join(embedded_scripts[:5])}",
            )
        )
    if suspicious_extensions:
        signals.append(
            signal(
                "archive.suspicious_extension",
                "medium",
                f"可疑扩展名条目：{', '.join(suspicious_extensions[:5])}",
            )
        )
    if nested_archives:
        signals.append(
            signal("archive.nested", "low", f"嵌套压缩包：{', '.join(nested_archives[:5])}")
        )
    if has_macro:
        signals.append(signal("archive.macro_container", "high", "包含 VBA 宏容器（vbaProject.bin）"))
    if double_extension_entries:
        signals.append(
            signal(
                "archive.double_extension",
                "medium",
                f"双扩展名伪装：{', '.join(double_extension_entries[:5])}",
            )
        )

    return {
        "format": "zip",
        "valid": True,
        "supported": True,
        "error": "",
        "entry_count": len(infos),
        "total_uncompressed": total_uncompressed,
        "total_compressed": total_compressed,
        "ratio": ratio,
        "entries": entries,
        "truncated": truncated,
        "embedded_executables": embedded_executables[:MAX_MANIFEST],
        "embedded_scripts": embedded_scripts[:MAX_MANIFEST],
        "signals": merge_signals(signals),
    }
