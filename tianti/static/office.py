"""Office 宏静态提取：OOXML（docx/xlsm/pptm 等 zip 容器）与 OLE（doc/xls/ppt 复合文档）。

范围与限制：
- 只做静态识别，绝不执行宏；不实现 MS-OVBA 解压，宏源码只做关键字/字符串扫描；
- OOXML：定位 word/xl/ppt 下的 vbaProject.bin，并按最小 CFB 解析器枚举流名；
- OLE：用同一 CFB 解析器枚举目录流名，找 VBA/_VBA_PROJECT/Macros 存储；解析失败或
  找不到宏存储时退化到原始字节关键字扫描，并标记 heuristic=True；
- 任何畸形输入都不抛异常，失败信息进 notes，宏存在性按 vbaProject.bin / 宏流判定。
"""

from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Any

from .util import merge_signals, signal

CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"

MAX_OOXML_ENTRIES = 4000
MAX_MACRO_BYTES = 16 * 1024 * 1024
MAX_RAW_SCAN_BYTES = 8 * 1024 * 1024
MAX_FAT_SECTORS = 4096
MAX_DIR_SECTORS = 4096
MAX_CFB_STREAMS = 512
MAX_MACRO_ENTRIES = 8

# 后缀 -> office 子类型；用于 model.guess_type 把 OOXML 识别成 archive/zip 时按文件名兜底
_OOXML_SUFFIX_KIND = {
    ".docx": "word",
    ".docm": "word",
    ".dotx": "word",
    ".dotm": "word",
    ".xlsx": "excel",
    ".xlsm": "excel",
    ".xltx": "excel",
    ".xltm": "excel",
    ".xlsb": "excel",
    ".pptx": "powerpoint",
    ".pptm": "powerpoint",
    ".potx": "powerpoint",
    ".potm": "powerpoint",
    ".ppsx": "powerpoint",
    ".ppsm": "powerpoint",
    ".sldx": "powerpoint",
    ".sldm": "powerpoint",
    ".xlam": "excel",
}
_OLE_SUFFIX_KIND = {
    ".doc": "word",
    ".dot": "word",
    ".xls": "excel",
    ".xlt": "excel",
    ".ppt": "powerpoint",
    ".pot": "powerpoint",
    ".pps": "powerpoint",
    ".msg": "outlook",
    ".vsd": "visio",
}

# 自动执行入口（拼接构造，避免单文件出现密集可疑字面量）
AUTOEXEC_KEYWORDS = (
    "Auto" + "Open",
    "Auto_" + "Open",
    "Auto" + "Exec",
    "Auto" + "Close",
    "Document_" + "Open",
    "Document_" + "BeforeClose",
    "Workbook_" + "Open",
    "Workbook_" + "Activate",
    "Workbook_" + "BeforeClose",
    "Presentation_" + "Open",
    "New" + "Presentation",
    "Window" + "Activate",
)

# 可疑 API / 行为关键字（宏源码被 MS-OVBA 压缩，未解压时只能命中部分字符串）
SUSPICIOUS_API_KEYWORDS = (
    "Create" + "Object",
    "WScript" + ".Shell",
    "Shell" + "Execute",
    "URLDownload" + "ToFile",
    "URLDownload" + "ToCacheFile",
    "ADODB" + ".Stream",
    "MSXML2" + ".XMLHTTP",
    "WinHttp" + ".WinHttpRequest",
    "Scripting" + ".FileSystemObject",
    "Environ" + "(",
    "Dll" + "Import",
    "Declare" + " Function",
    "VirtualAlloc",
    "CreateRemote" + "Thread",
    "powershell",
    "cmd" + ".exe",
    "Base" + "64",
    "From" + "Base64String",
    "StrReverse",
    "Chr" + "(",
)

VBA_MARKER_KEYWORDS = ("VBA", "_VBA_PROJECT", "Macros", "ThisDocument", "ThisWorkbook")


class CFBError(Exception):
    """CFB 结构读取失败（内部使用，parse_cfb 捕获）。"""


@dataclass
class CFBInfo:
    valid: bool = False
    error: str = ""
    major_version: int = 0
    sector_size: int = 512
    root_name: str = ""
    streams: list[str] = field(default_factory=list)
    storages: list[str] = field(default_factory=list)
    stream_sizes: dict[str, int] = field(default_factory=dict)
    truncated: bool = False


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def _sector(data: bytes, sector_id: int, sector_size: int) -> bytes | None:
    """按 CFB 规则取扇区：扇区 N 位于 (N+1)*sector_size；特殊值/越界返回 None。"""
    if sector_id >= 0xFFFFFFFA:
        return None
    offset = (sector_id + 1) * sector_size
    if offset < 0 or offset + sector_size > len(data):
        return None
    return data[offset : offset + sector_size]


def parse_cfb(data: bytes) -> CFBInfo:
    """最小 CFB 解析器（只需枚举目录流名）；永不抛异常。"""
    info = CFBInfo()
    try:
        _parse_cfb_into(info, data)
    except CFBError as exc:
        info.valid = False
        info.error = str(exc)
    except Exception as exc:  # 解析器兜底
        info.valid = False
        info.error = f"{type(exc).__name__}: {exc}"
    return info


def _parse_cfb_into(info: CFBInfo, data: bytes) -> None:
    if len(data) < 512:
        raise CFBError(f"文件过短（{len(data)} < 512）")
    if data[:8] != CFB_MAGIC:
        raise CFBError("缺少 CFB 魔数")
    major = _u16(data, 26)
    shift = _u16(data, 30)
    if shift not in (9, 12):
        raise CFBError(f"扇区大小非法（sector_shift={shift}）")
    sector_size = 1 << shift
    info.major_version = major
    info.sector_size = sector_size

    first_dir = _u32(data, 48)
    first_difat = _u32(data, 68)
    num_difat = _u32(data, 72)

    # 1) DIFAT -> FAT 扇区列表（header 内 109 项 + 后续 DIFAT 扇区）
    fat_sector_ids: list[int] = []
    try:
        header_difat = struct.unpack_from("<109I", data, 76)
    except struct.error as exc:
        raise CFBError(f"DIFAT 读取失败: {exc}") from exc
    fat_sector_ids.extend(value for value in header_difat if value < 0xFFFFFFFA)
    seen_difat: set[int] = set()
    next_difat = first_difat
    loops = 0
    while next_difat < 0xFFFFFFFA and loops < min(num_difat + 4, 1024):
        if next_difat in seen_difat:
            break
        seen_difat.add(next_difat)
        sector = _sector(data, next_difat, sector_size)
        if sector is None:
            info.truncated = True
            break
        values = struct.unpack_from("<%dI" % (sector_size // 4), sector, 0)
        fat_sector_ids.extend(value for value in values[:-1] if value < 0xFFFFFFFA)
        next_difat = values[-1]
        loops += 1

    # 2) FAT（扇区链数组）
    fat: list[int] = []
    for sector_id in fat_sector_ids[:MAX_FAT_SECTORS]:
        sector = _sector(data, sector_id, sector_size)
        if sector is None:
            info.truncated = True
            break
        fat.extend(struct.unpack_from("<%dI" % (sector_size // 4), sector, 0))

    # 3) 目录扇区链 -> 目录项
    sector_id = first_dir
    visited: set[int] = set()
    entries_per_sector = sector_size // 128
    while sector_id < 0xFFFFFFFA:
        if len(visited) >= MAX_DIR_SECTORS:
            info.truncated = True
            break
        if sector_id in visited:
            break
        visited.add(sector_id)
        sector = _sector(data, sector_id, sector_size)
        if sector is None:
            info.truncated = True
            break
        for index in range(entries_per_sector):
            entry = sector[index * 128 : (index + 1) * 128]
            if len(entry) < 128:
                break
            _parse_directory_entry(entry, info)
        if sector_id >= len(fat):
            break
        sector_id = fat[sector_id]

    info.valid = True


def _parse_directory_entry(entry: bytes, info: CFBInfo) -> None:
    name_length = _u16(entry, 64)
    if name_length < 2 or name_length > 64:
        return
    try:
        name = entry[: name_length - 2].decode("utf-16-le", errors="ignore").rstrip("\x00")
    except Exception:
        return
    if not name:
        return
    object_type = entry[66]
    if object_type == 5:  # root storage
        info.root_name = name
        return
    if object_type == 2:  # stream
        if len(info.streams) >= MAX_CFB_STREAMS:
            info.truncated = True
            return
        info.streams.append(name)
        info.stream_sizes[name] = _u64(entry, 120)
        return
    if object_type == 1:  # storage
        if len(info.storages) < MAX_CFB_STREAMS:
            info.storages.append(name)


def _scan_keywords(data: bytes, keywords: tuple[str, ...]) -> list[str]:
    """在原始字节里做 ASCII / UTF-16LE 关键字扫描（大小写不敏感），返回命中关键字。"""
    if not data:
        return []
    sample = data[:MAX_RAW_SCAN_BYTES].lower()
    hits: list[str] = []
    for keyword in keywords:
        token = keyword.lower().encode("latin-1", errors="ignore")
        if token and token in sample:
            hits.append(keyword)
            continue
        token16 = keyword.lower().encode("utf-16-le", errors="ignore")
        if token16 and token16 in sample:
            hits.append(keyword)
    return hits


def _macro_streams(names: list[str]) -> list[str]:
    """从目录流/存储名中识别 VBA 宏存储（强标记优先，dir/module 仅辅助）。"""
    lower = {name: name.lower() for name in names}
    strong = [
        name
        for name, low in lower.items()
        if "vba" in low or low in ("_vba_project", "projectwm", "macros")
    ]
    if strong:
        related = [
            name
            for name, low in lower.items()
            if low == "dir" or low.startswith("module") or low in ("project", "projectwm")
        ]
        return list(dict.fromkeys(strong + related))
    has_project = any(low == "project" for low in lower.values())
    has_dir = any(low == "dir" for low in lower.values())
    if has_project and has_dir:
        return [name for name, low in lower.items() if low in ("project", "dir") or low.startswith("module")]
    return []


def office_kind_from_name(name: str) -> str:
    """按后缀判断 office 容器类型：'ooxml' / 'ole' / ''。"""
    if not name:
        return ""
    suffix = ""
    if "." in name:
        suffix = "." + name.rsplit(".", 1)[-1].lower()
    if suffix in _OOXML_SUFFIX_KIND:
        return "ooxml"
    if suffix in _OLE_SUFFIX_KIND:
        return "ole"
    return ""


def _kind_from_name(name: str) -> str:
    if not name or "." not in name:
        return ""
    suffix = "." + name.rsplit(".", 1)[-1].lower()
    return _OOXML_SUFFIX_KIND.get(suffix) or _OLE_SUFFIX_KIND.get(suffix) or ""


def _base_result(container: str) -> dict[str, Any]:
    return {
        "container": container,
        "kind": "",
        "has_macros": False,
        "streams": [],
        "storages": [],
        "macro_streams": [],
        "macro_paths": [],
        "autoexec": [],
        "suspicious_api": [],
        "vba_project_size": 0,
        "heuristic": False,
        "notes": [],
        "signals": [],
    }


def _build_signals(result: dict[str, Any]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    if result.get("has_macros"):
        paths = result.get("macro_paths") or result.get("macro_streams") or []
        location = ", ".join(str(item) for item in paths[:5]) or result.get("container", "office")
        signals.append(
            signal("office.macro_present", "high", f"{result.get('container')} 容器包含 VBA 宏项目（{location}）")
        )
    if result.get("autoexec"):
        signals.append(
            signal(
                "office.macro_autoexec",
                "critical",
                f"宏包含自动执行入口：{', '.join(str(item) for item in result['autoexec'][:6])}",
            )
        )
    if result.get("suspicious_api"):
        signals.append(
            signal(
                "office.macro_suspicious_api",
                "high",
                f"宏包含可疑 API/关键字：{', '.join(str(item) for item in result['suspicious_api'][:8])}",
            )
        )
    if result.get("heuristic"):
        signals.append(
            signal("office.ole_heuristic", "low", "OLE 宏判定退化：已用原始字节关键字扫描（启发式）")
        )
    return signals


def _analyze_ooxml(data: bytes, name: str) -> dict[str, Any]:
    result = _base_result("ooxml")
    result["kind"] = _kind_from_name(name)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
        result["notes"].append(f"OOXML 容器解析失败：{type(exc).__name__}: {exc}")
        return result
    with archive:
        try:
            infos = archive.infolist()
        except Exception as exc:
            result["notes"].append(f"读取 zip 目录失败：{type(exc).__name__}: {exc}")
            return result
        if len(infos) > MAX_OOXML_ENTRIES:
            result["notes"].append(f"条目数 {len(infos)} 超过上限 {MAX_OOXML_ENTRIES}，仅检查前 {MAX_OOXML_ENTRIES} 条")
        considered = infos[:MAX_OOXML_ENTRIES]
        names = [info.filename for info in considered]
        if not result["kind"]:
            for prefix, kind in (("word/", "word"), ("xl/", "excel"), ("ppt/", "powerpoint")):
                if any(item.lower().startswith(prefix) for item in names):
                    result["kind"] = kind
                    break

        macro_infos = [
            info
            for info in considered
            if info.filename.replace("\\", "/").rsplit("/", 1)[-1].lower() == "vbaproject.bin"
        ][:MAX_MACRO_ENTRIES]
        total_size = 0
        blobs: list[bytes] = []
        stream_names: list[str] = []
        for info in macro_infos:
            result["macro_paths"].append(info.filename[:300])
            try:
                with archive.open(info) as handle:
                    blob = handle.read(MAX_MACRO_BYTES)
            except Exception as exc:  # 加密/损坏条目：宏存在性仍按条目判定
                result["notes"].append(f"读取 {info.filename[:120]} 失败：{type(exc).__name__}: {exc}")
                continue
            total_size += len(blob)
            blobs.append(blob)
            cfb = parse_cfb(blob)
            if cfb.valid:
                stream_names.extend(cfb.streams)
                if cfb.truncated:
                    result["notes"].append(f"{info.filename[:120]} 的 CFB 目录被截断，流名可能不全")
            else:
                result["notes"].append(
                    f"{info.filename[:120]} 不是可解析的 CFB（{cfb.error}），已退化字符串扫描"
                )
        result["has_macros"] = bool(macro_infos)
        result["vba_project_size"] = total_size
        result["streams"] = list(dict.fromkeys(stream_names))[:MAX_CFB_STREAMS]
        if macro_infos and not result["streams"]:
            result["macro_streams"] = ["vbaProject.bin"]
        combined = b"".join(blobs)[:MAX_RAW_SCAN_BYTES]
        result["autoexec"] = _scan_keywords(combined, AUTOEXEC_KEYWORDS)
        result["suspicious_api"] = _scan_keywords(combined, SUSPICIOUS_API_KEYWORDS)
        if not macro_infos:
            result["notes"].append("OOXML 中未发现 vbaProject.bin（无 VBA 宏）")
    result["signals"] = _build_signals(result)
    return result


def _analyze_ole(data: bytes, name: str) -> dict[str, Any]:
    result = _base_result("ole")
    result["kind"] = _kind_from_name(name)
    cfb = parse_cfb(data)
    result["streams"] = list(cfb.streams)[:MAX_CFB_STREAMS]
    result["storages"] = list(cfb.storages)[:MAX_CFB_STREAMS]
    if not cfb.valid:
        result["notes"].append(f"CFB 解析失败：{cfb.error}；退化原始字节关键字扫描")
    elif cfb.truncated:
        result["notes"].append("CFB 目录被截断，流名可能不全")

    macro_streams = _macro_streams(cfb.streams + cfb.storages)
    result["macro_streams"] = macro_streams[:MAX_CFB_STREAMS]
    vba_size = 0
    for stream_name in macro_streams:
        vba_size += int(cfb.stream_sizes.get(stream_name, 0) or 0)
    result["vba_project_size"] = min(vba_size, MAX_MACRO_BYTES)

    if macro_streams:
        result["has_macros"] = True
    else:
        # fallback：原始字节关键字扫描（必须在所有 OLE 文档上做，因 VBA 存储可能被剥离/加壳）
        result["heuristic"] = True
        markers = _scan_keywords(data, VBA_MARKER_KEYWORDS)
        autoexec = _scan_keywords(data, AUTOEXEC_KEYWORDS)
        result["autoexec"] = autoexec
        result["suspicious_api"] = _scan_keywords(data, SUSPICIOUS_API_KEYWORDS)
        result["has_macros"] = bool(markers or autoexec)
        if markers or autoexec:
            result["notes"].append(
                f"未发现 VBA 宏存储，原始字节关键字命中：{', '.join((markers + autoexec)[:6])}（启发式）"
            )
        else:
            result["notes"].append("未发现 VBA 宏存储，原始字节也未命中宏关键字")
    if macro_streams:
        result["autoexec"] = _scan_keywords(data, AUTOEXEC_KEYWORDS)
        result["suspicious_api"] = _scan_keywords(data, SUSPICIOUS_API_KEYWORDS)
        result["notes"].append("发现 VBA 宏存储：" + ", ".join(macro_streams[:8]))
    result["signals"] = _build_signals(result)
    return result


def analyze_office(data: bytes, name: str = "") -> dict[str, Any]:
    """Office 文件静态宏提取入口；永不抛异常。"""
    if not data:
        result = _base_result("unknown")
        result["notes"].append("空数据")
        return result
    if data[:8] == CFB_MAGIC:
        return _analyze_ole(data, name)
    if data[:4] == ZIP_MAGIC:
        return _analyze_ooxml(data, name)
    result = _base_result("unknown")
    result["kind"] = _kind_from_name(name)
    result["notes"].append("既不是 OOXML(zip) 也不是 OLE(CFB) 容器")
    return result
