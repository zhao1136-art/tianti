"""纯标准库 PE32/PE64 解析：头、节区、导入/导出、签名目录、overlay、校验和与启发信号。

设计原则：
- 绝不抛异常出模块：任何畸形/截断输入都降级为 valid=False + pe.malformed 信号；
- 所有读取都做边界检查，限制循环次数，避免恶意文件造成 CPU/内存放大；
- 输出为纯 dict，可直接 JSON 序列化（供 StaticReport.to_dict 与报告消费）。
"""

from __future__ import annotations

import array
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .util import merge_signals, shannon_entropy, signal

MACHINE_NAMES = {
    0x14C: "i386",
    0x8664: "amd64",
    0x1C0: "arm",
    0x1C4: "armnt",
    0xAA64: "arm64",
    0x200: "ia64",
    0x0: "unknown",
}

SUBSYSTEM_NAMES = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    5: "os2_cui",
    7: "posix_cui",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
    13: "efi_rom",
    14: "xbox",
    16: "windows_boot_application",
}

# 加壳/保护器常见节名特征（对节名做小写归一后做子串匹配）
PACKER_SECTION_TOKENS = (
    "upx",
    "aspack",
    "mpress",
    "themida",
    "winlicense",
    "vmp",
    "enigma",
    "petite",
    "nsp",
    "pec",
    "kkrunchy",
    "boom",
    "taz",
    "perplex",
    "sforce",
    "packed",
    "adata",
    "packman",
    "y0da",
    "obsidium",
    "armadillo",
)

# 文件头/节区中的加壳器字符串特征
PACKER_STRING_HINTS = (
    b"UPX!",
    b"UPX0",
    b"ASPack",
    b"MPRESS",
    b"Themida",
    b"WinLicense",
    b".enigma",
    b"VMProtect",
    b"Enigma protector",
    b"PECompact",
    b"Armadillo",
)

# 导入函数组合（全部小写），用于异常导入启发
IMPORT_COMBOS: tuple[tuple[str, str, tuple[str, ...], bool], ...] = (
    # (signal_id, detail, functions, require_all)
    (
        "pe.import_injection",
        "进程注入类 API 组合（内存分配+写入+远程执行）",
        ("virtualallocex", "writeprocessmemory", "createremotethread"),
        True,
    ),
    (
        "pe.import_process_hollow",
        "进程镂空类 API 组合（卸载映像+写入+上下文替换）",
        ("ntunmapviewofsection", "virtualallocex", "setthreadcontext"),
        True,
    ),
    (
        "pe.import_credential",
        "凭据访问类 API（MiniDumpWriteDump / CryptUnprotectData 等）",
        ("minidumpwritedump", "cryptunprotectdata", "lsaenumeratelogonsessions", "samqueryinformationuser"),
        False,
    ),
    (
        "pe.import_download",
        "下载类 API（URLDownloadToFile / WinHttp / InternetReadFile）",
        ("urldownloadtofilea", "urldownloadtofilew", "internetopenurl", "winhttpopen", "httpsendrequest"),
        False,
    ),
    (
        "pe.import_crypto",
        "加密类 API（CryptEncrypt / BCryptEncrypt）",
        ("cryptencrypt", "bcryptencrypt", "cryptgenkey"),
        False,
    ),
    (
        "pe.import_keylog",
        "键盘记录类 API（SetWindowsHookEx / GetAsyncKeyState）",
        ("setwindowshookexa", "setwindowshookexw", "getasynckeystate"),
        False,
    ),
    (
        "pe.import_antidebug",
        "反调试类 API（IsDebuggerPresent / CheckRemoteDebuggerPresent）",
        ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"),
        False,
    ),
    (
        "pe.import_network",
        "网络通信类 API（WSAStartup / socket / connect）",
        ("wsastartup", "socket", "connect", "wsaconnect"),
        False,
    ),
)

COMBO_SEVERITY = {
    "pe.import_injection": "high",
    "pe.import_process_hollow": "high",
    "pe.import_credential": "medium",
    "pe.import_download": "medium",
    "pe.import_crypto": "medium",
    "pe.import_keylog": "high",
    "pe.import_antidebug": "low",
    "pe.import_network": "low",
}

MAX_DLLS = 64
MAX_FUNCS_PER_DLL = 1024
MAX_TOTAL_IMPORTS = 8000
MAX_EXPORTS = 4096
MAX_SECTION_ENTROPY_BYTES = 16 * 1024
MAX_PACKER_SCAN_BYTES = 4 * 1024 * 1024


class PEError(Exception):
    """PE 结构读取失败（内部使用，parse_pe 会捕获）。"""


def _e(data: bytes, off: int, size: int) -> bytes:
    if off < 0 or size < 0 or off + size > len(data):
        raise PEError(f"读取越界 off={off} size={size} len={len(data)}")
    return data[off : off + size]


def _u8(data: bytes, off: int) -> int:
    return _e(data, off, 1)[0]


def _u16(data: bytes, off: int) -> int:
    return struct.unpack("<H", _e(data, off, 2))[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack("<I", _e(data, off, 4))[0]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack("<Q", _e(data, off, 8))[0]


def _u16_or(data: bytes, off: int, default: int = 0) -> int:
    try:
        return _u16(data, off)
    except PEError:
        return default


def _u32_or(data: bytes, off: int, default: int = 0) -> int:
    try:
        return _u32(data, off)
    except PEError:
        return default


def compute_checksum(data: bytes, checksum_offset: int) -> int:
    """按 PE 规范计算校验和（校验和字段本身按 0 计，最后加文件长度）。

    使用 array('H') 求和（快 15 倍以上），避免大文件逐字节 Python 循环。
    """
    length = len(data)
    tail = 0
    even = data
    if length % 2:
        tail = data[-1]
        even = data[:-1]
    words = array.array("H", even)
    if sys.byteorder != "little":
        words.byteswap()
    total = sum(words)
    if 0 <= checksum_offset and checksum_offset // 2 + 1 < len(words):
        index = checksum_offset // 2
        total -= words[index] + words[index + 1]
    total += tail
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + length) & 0xFFFFFFFF


@dataclass
class PEInfo:
    """PE 解析结果（to_dict 可直接 JSON 序列化）。"""

    valid: bool = False
    error: str = ""
    is_pe32_plus: bool = False
    machine: int = 0
    machine_name: str = ""
    timestamp: int = 0
    timestamp_iso: str = ""
    characteristics: int = 0
    is_dll: bool = False
    is_executable: bool = False
    subsystem: int = 0
    subsystem_name: str = ""
    image_base: int = 0
    entrypoint_rva: int = 0
    entrypoint_section: str = ""
    section_alignment: int = 0
    file_alignment: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    checksum: int = 0
    checksum_computed: int | None = None
    checksum_ok: bool | None = None
    num_sections: int = 0
    sections: list[dict[str, Any]] = field(default_factory=list)
    imports: list[dict[str, Any]] = field(default_factory=list)
    import_count: int = 0
    exports: list[str] = field(default_factory=list)
    export_count: int = 0
    has_resources: bool = False
    has_signature: bool = False
    security_directory: dict[str, int] = field(default_factory=dict)
    has_relocations: bool = False
    has_tls: bool = False
    has_debug: bool = False
    overlay_size: int = 0
    overlay_ratio: float = 0.0
    packer_indicators: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    signals: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "error": self.error,
            "is_pe32_plus": self.is_pe32_plus,
            "machine": self.machine,
            "machine_name": self.machine_name,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "characteristics": self.characteristics,
            "is_dll": self.is_dll,
            "is_executable": self.is_executable,
            "subsystem": self.subsystem,
            "subsystem_name": self.subsystem_name,
            "image_base": self.image_base,
            "entrypoint_rva": self.entrypoint_rva,
            "entrypoint_section": self.entrypoint_section,
            "section_alignment": self.section_alignment,
            "file_alignment": self.file_alignment,
            "size_of_image": self.size_of_image,
            "size_of_headers": self.size_of_headers,
            "checksum": self.checksum,
            "checksum_computed": self.checksum_computed,
            "checksum_ok": self.checksum_ok,
            "num_sections": self.num_sections,
            "sections": [dict(sec) for sec in self.sections],
            "imports": [
                {"dll": imp["dll"], "functions": list(imp["functions"]), "count": imp["count"]}
                for imp in self.imports
            ],
            "import_count": self.import_count,
            "exports": list(self.exports),
            "export_count": self.export_count,
            "has_resources": self.has_resources,
            "has_signature": self.has_signature,
            "security_directory": dict(self.security_directory),
            "has_relocations": self.has_relocations,
            "has_tls": self.has_tls,
            "has_debug": self.has_debug,
            "overlay_size": self.overlay_size,
            "overlay_ratio": self.overlay_ratio,
            "packer_indicators": list(self.packer_indicators),
            "warnings": list(self.warnings),
            "signals": [dict(sig) for sig in self.signals],
        }


def _timestamp_iso(ts: int) -> str:
    if ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return ""


def _section_flags(characteristics: int) -> list[str]:
    flags: list[str] = []
    if characteristics & 0x40000000:
        flags.append("read")
    if characteristics & 0x80000000:
        flags.append("write")
    if characteristics & 0x20000000:
        flags.append("execute")
    if characteristics & 0x00000020:
        flags.append("code")
    if characteristics & 0x00000040:
        flags.append("initialized_data")
    if characteristics & 0x00000080:
        flags.append("uninitialized_data")
    if characteristics & 0x02000000:
        flags.append("discardable")
    return flags


def _clean_section_name(raw: bytes) -> str:
    name = raw.split(b"\x00", 1)[0].decode("latin-1", errors="replace")
    return name.strip()


def _parse_imports(
    data: bytes,
    import_rva: int,
    sections: list[dict[str, Any]],
    size_of_headers: int,
    *,
    is_pe32_plus: bool,
) -> tuple[list[dict[str, Any]], int]:
    if not import_rva:
        return [], 0
    offset = rva_to_offset(import_rva, sections, size_of_headers, len(data))
    if offset is None:
        return [], 0
    imports: list[dict[str, Any]] = []
    total = 0
    try:
        for index in range(MAX_DLLS):
            base = offset + index * 20
            if base + 20 > len(data):
                break
            original_first_thunk = _u32(data, base)
            name_rva = _u32(data, base + 12)
            first_thunk = _u32(data, base + 16)
            if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break
            dll_off = rva_to_offset(name_rva, sections, size_of_headers, len(data))
            dll_name = ""
            if dll_off is not None:
                end = data.find(b"\x00", dll_off, min(len(data), dll_off + 260))
                if end < 0:
                    end = min(len(data), dll_off + 260)
                dll_name = data[dll_off:end].decode("latin-1", errors="replace")
            thunk_rva = original_first_thunk or first_thunk
            thunk_off = rva_to_offset(thunk_rva, sections, size_of_headers, len(data))
            functions: list[str] = []
            if thunk_off is not None:
                step = 8 if is_pe32_plus else 4
                for func_index in range(MAX_FUNCS_PER_DLL):
                    entry_off = thunk_off + func_index * step
                    try:
                        value = _u64(data, entry_off) if step == 8 else _u32(data, entry_off)
                    except PEError:
                        break
                    if value == 0:
                        break
                    if value & (1 << (step * 8 - 1)):
                        functions.append(f"ordinal:{value & 0xFFFF}")
                    else:
                        name_off = rva_to_offset(value, sections, size_of_headers, len(data))
                        if name_off is None or name_off + 2 > len(data):
                            break
                        end = data.find(b"\x00", name_off + 2, min(len(data), name_off + 2 + 512))
                        if end < 0:
                            end = min(len(data), name_off + 2 + 512)
                        func_name = data[name_off + 2 : end].decode("latin-1", errors="replace")
                        if func_name:
                            functions.append(func_name)
                    total += 1
                    if total >= MAX_TOTAL_IMPORTS:
                        break
            imports.append({"dll": dll_name, "functions": functions, "count": len(functions)})
            if total >= MAX_TOTAL_IMPORTS:
                break
    except PEError:
        pass
    return imports, total


def _parse_exports(
    data: bytes,
    export_rva: int,
    sections: list[dict[str, Any]],
    size_of_headers: int,
) -> list[str]:
    if not export_rva:
        return []
    offset = rva_to_offset(export_rva, sections, size_of_headers, len(data))
    if offset is None or offset + 40 > len(data):
        return []
    number_of_names = _u32_or(data, offset + 24, 0)
    address_of_names = _u32_or(data, offset + 32, 0)
    if not number_of_names or not address_of_names:
        return []
    names_off = rva_to_offset(address_of_names, sections, size_of_headers, len(data))
    if names_off is None:
        return []
    exports: list[str] = []
    limit = min(number_of_names, MAX_EXPORTS)
    for index in range(limit):
        entry_off = names_off + index * 4
        if entry_off + 4 > len(data):
            break
        name_rva = _u32_or(data, entry_off, 0)
        name_off = rva_to_offset(name_rva, sections, size_of_headers, len(data))
        if name_off is None or name_off >= len(data):
            continue
        end = data.find(b"\x00", name_off, min(len(data), name_off + 512))
        if end < 0:
            end = min(len(data), name_off + 512)
        name = data[name_off:end].decode("latin-1", errors="replace")
        if name:
            exports.append(name)
    return exports


def rva_to_offset(
    rva: int,
    sections: list[dict[str, Any]],
    size_of_headers: int,
    data_len: int,
) -> int | None:
    """RVA -> 文件偏移；无法映射返回 None。"""
    if rva < 0:
        return None
    if rva < size_of_headers:
        return rva if rva < data_len else None
    for sec in sections:
        va = int(sec["virtual_address"])
        raw_size = int(sec["raw_size"])
        raw_ptr = int(sec["pointer_raw"])
        virtual_size = int(sec["virtual_size"])
        span = max(virtual_size, raw_size)
        if va <= rva < va + span:
            delta = rva - va
            if delta >= raw_size:
                return None
            off = raw_ptr + delta
            return off if off < data_len else None
    return None


def _import_function_set(imports: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for imp in imports:
        for func in imp.get("functions", []):
            if func and not func.startswith("ordinal:"):
                names.add(func.lower())
    return names


def _import_signals(imports: list[dict[str, Any]]) -> list[dict[str, str]]:
    functions = _import_function_set(imports)
    if not functions:
        return []
    out: list[dict[str, str]] = []
    for signal_id, detail, needed, require_all in IMPORT_COMBOS:
        hits = [name for name in needed if name in functions]
        if not hits:
            continue
        matched = len(hits) == len(needed) if require_all else True
        if not matched:
            continue
        out.append(signal(signal_id, COMBO_SEVERITY[signal_id], f"{detail}：{', '.join(sorted(hits))}"))
    return out


def parse_pe(data: bytes, *, truncated: bool = False) -> PEInfo:
    """解析 PE 数据；永不抛异常。truncated 表示 data 只是文件前缀（跳过校验和）。"""
    info = PEInfo()
    if not data:
        info.error = "空数据"
        info.signals = [signal("pe.malformed", "medium", "空数据，无法解析 PE")]
        return info
    try:
        _parse_pe_into(info, data, truncated=truncated)
    except PEError as exc:
        info.valid = False
        info.error = str(exc)
        info.signals = merge_signals(info.signals, [signal("pe.malformed", "medium", f"PE 解析失败：{exc}")])
    except Exception as exc:  # 兜底：任何解析器缺陷都不得让静态分析崩溃
        info.valid = False
        info.error = f"{type(exc).__name__}: {exc}"
        info.signals = merge_signals(info.signals, [signal("pe.malformed", "medium", f"PE 解析异常：{info.error}")])
    return info


def _parse_pe_into(info: PEInfo, data: bytes, *, truncated: bool) -> None:
    if len(data) < 0x40:
        raise PEError("DOS 头被截断")
    if data[:2] != b"MZ":
        raise PEError("缺少 MZ 签名")
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew <= 0 or e_lfanew > len(data) - 24:
        raise PEError(f"e_lfanew 非法/越界：0x{e_lfanew:x}")
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise PEError("缺少 PE 签名")
    coff = e_lfanew + 4
    machine = _u16(data, coff)
    num_sections = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    size_optional = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)
    if size_optional < 96:
        raise PEError(f"可选头过小：{size_optional}")
    optional = coff + 20
    if optional + size_optional > len(data):
        raise PEError("可选头被截断")
    magic = _u16(data, optional)
    if magic not in (0x10B, 0x20B):
        raise PEError(f"未知可选头 magic：0x{magic:x}")
    is_plus = magic == 0x20B
    info.valid = True
    info.is_pe32_plus = is_plus
    info.machine = machine
    info.machine_name = MACHINE_NAMES.get(machine, f"0x{machine:x}")
    info.timestamp = timestamp
    info.timestamp_iso = _timestamp_iso(timestamp)
    info.characteristics = characteristics
    info.is_dll = bool(characteristics & 0x2000)
    info.is_executable = bool(characteristics & 0x0002)
    info.entrypoint_rva = _u32(data, optional + 16)
    info.image_base = _u64(data, optional + 24) if is_plus else _u32(data, optional + 28)
    info.section_alignment = _u32(data, optional + 32)
    info.file_alignment = _u32(data, optional + 36)
    info.size_of_image = _u32(data, optional + 56)
    info.size_of_headers = _u32(data, optional + 60)
    checksum_offset = optional + 64
    info.checksum = _u32(data, checksum_offset)
    info.subsystem = _u16(data, optional + 68)
    info.subsystem_name = SUBSYSTEM_NAMES.get(info.subsystem, f"0x{info.subsystem:x}")
    info.num_sections = num_sections

    num_dirs = _u32(data, optional + (108 if is_plus else 92))
    dirs_offset = optional + (112 if is_plus else 96)
    dirs_count = min(num_dirs, 16)
    if dirs_offset + dirs_count * 8 > optional + size_optional:
        dirs_count = max(0, (optional + size_optional - dirs_offset) // 8)

    def directory(index: int) -> tuple[int, int]:
        if index >= dirs_count:
            return 0, 0
        entry = dirs_offset + index * 8
        if entry + 8 > len(data):
            return 0, 0
        return _u32_or(data, entry, 0), _u32_or(data, entry + 4, 0)

    export_rva, export_size = directory(0)
    import_rva, import_size = directory(1)
    resource_rva, resource_size = directory(2)
    reloc_rva, reloc_size = directory(5)
    tls_rva, tls_size = directory(9)
    debug_rva, debug_size = directory(6)
    security_offset, security_size = directory(4)
    info.has_resources = resource_size > 0 and resource_rva > 0
    info.has_signature = security_size > 0
    info.security_directory = {"offset": security_offset, "size": security_size}
    info.has_relocations = reloc_size > 0 and reloc_rva > 0
    info.has_tls = tls_size > 0 and tls_rva > 0
    info.has_debug = debug_size > 0 and debug_rva > 0

    # 节区表
    section_table = optional + size_optional
    section_data_end = 0
    for index in range(num_sections):
        base = section_table + index * 40
        if base + 40 > len(data):
            info.warnings.append(f"节区表在索引 {index} 处被截断")
            info.signals = merge_signals(info.signals, [signal("pe.malformed", "medium", "节区表被截断")])
            break
        name = _clean_section_name(data[base : base + 8])
        virtual_size = _u32(data, base + 8)
        virtual_address = _u32(data, base + 12)
        raw_size = _u32(data, base + 16)
        pointer_raw = _u32(data, base + 20)
        section_characteristics = _u32(data, base + 36)
        entropy = 0.0
        if raw_size and pointer_raw < len(data):
            available = min(raw_size, len(data) - pointer_raw, MAX_SECTION_ENTROPY_BYTES)
            if available > 0:
                entropy = shannon_entropy(data[pointer_raw : pointer_raw + available])
        if raw_size:
            section_data_end = max(section_data_end, pointer_raw + raw_size)
        info.sections.append(
            {
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "pointer_raw": pointer_raw,
                "characteristics": section_characteristics,
                "flags": _section_flags(section_characteristics),
                "entropy": entropy,
            }
        )

    # 节区启发
    section_signals: list[dict[str, str]] = []
    suspicious_names: list[str] = []
    for sec in info.sections:
        name = str(sec["name"])
        norm = name.lower().strip(". _-")
        if any(token in norm for token in PACKER_SECTION_TOKENS):
            suspicious_names.append(name)
        if sec["entropy"] >= 7.2 and sec["raw_size"] >= 256:
            section_signals.append(
                signal("pe.entropy_high", "medium", f"节区 {name or '(未命名)'} 熵 {sec['entropy']:.2f}（疑似加壳/加密）")
            )
        flags = sec["flags"]
        if "write" in flags and "execute" in flags:
            section_signals.append(
                signal("pe.rwx_section", "high", f"节区 {name or '(未命名)'} 可写可执行（W+X）")
            )
        if "execute" in flags and "initialized_data" in flags and sec["raw_size"] == 0:
            info.warnings.append(f"节区 {name} 标记可执行但无文件数据")
    if suspicious_names:
        section_signals.append(
            signal("pe.suspicious_section", "high", f"可疑/加壳节名：{', '.join(suspicious_names[:6])}")
        )

    # 入口点所在节
    for sec in info.sections:
        va = int(sec["virtual_address"])
        span = max(int(sec["virtual_size"]), int(sec["raw_size"]))
        if va <= info.entrypoint_rva < va + span:
            info.entrypoint_section = str(sec["name"])
            break
    if info.sections and not info.entrypoint_section:
        section_signals.append(
            signal("pe.entrypoint_outside", "medium", f"入口点 RVA 0x{info.entrypoint_rva:x} 不在任何节区内")
        )

    # 导入 / 导出
    if import_rva:
        info.imports, info.import_count = _parse_imports(
            data, import_rva, info.sections, info.size_of_headers, is_pe32_plus=is_plus
        )
        if not info.imports:
            info.warnings.append("导入目录存在但无法解析")
    info.exports = _parse_exports(data, export_rva, info.sections, info.size_of_headers)
    info.export_count = len(info.exports)

    # checksum（仅在完整文件上有意义）
    if not truncated:
        try:
            computed = compute_checksum(data, checksum_offset)
            info.checksum_computed = computed
            info.checksum_ok = computed == info.checksum
        except Exception:
            info.checksum_ok = None

    # overlay
    covered = max(section_data_end, info.size_of_headers)
    if len(data) > covered:
        info.overlay_size = len(data) - covered
        info.overlay_ratio = round(info.overlay_size / len(data), 4)

    # 加壳器字符串特征
    head = data[:MAX_PACKER_SCAN_BYTES]
    for hint in PACKER_STRING_HINTS:
        if hint in head:
            info.packer_indicators.append(hint.decode("latin-1", errors="replace"))
    if info.packer_indicators:
        section_signals.append(
            signal("pe.packer_indicator", "high", f"命中加壳器特征：{', '.join(info.packer_indicators[:5])}")
        )

    # 其它启发
    if info.timestamp == 0:
        section_signals.append(signal("pe.zero_timestamp", "low", "PE 时间戳为 0（常见于加壳/伪造样本）"))
    if info.overlay_size > 0 and (info.overlay_size > 1024 * 1024 or info.overlay_ratio > 0.10):
        section_signals.append(
            signal("pe.overlay", "medium", f"overlay {info.overlay_size} 字节（占 {info.overlay_ratio:.1%}）")
        )
    elif info.overlay_size > 0:
        section_signals.append(signal("pe.overlay", "low", f"overlay {info.overlay_size} 字节"))
    if info.checksum_ok is False:
        section_signals.append(
            signal("pe.checksum_invalid", "low", f"校验和不匹配（头内 0x{info.checksum:08x}，计算 0x{(info.checksum_computed or 0):08x}）")
        )
    if not info.has_signature:
        section_signals.append(signal("pe.unsigned", "low", "无 Authenticode 签名目录（IMAGE_DIRECTORY_ENTRY_SECURITY 为空）"))
    if not info.imports:
        section_signals.append(signal("pe.no_imports", "medium", "无导入表（疑似加壳或资源型 PE）"))
    info.signals = merge_signals(
        info.signals,
        section_signals,
        _import_signals(info.imports),
    )
