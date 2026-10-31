"""静态预筛入口：StaticReport + analyze(sample, data=None)。

analyze 接受 Sample / 路径(str|Path) / bytes，按类型分派到
pe / scripts / archive / office / strings 子分析器，汇总为可 JSON 序列化的 StaticReport。
Office 类型额外产出 office 字段（OOXML/OLE 宏提取）。绝不执行样本内容。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Any

from ..core.errors import SampleError
from ..core.hashing import hash_bytes, hash_file
from ..core.model import Sample, SampleType
from . import archive, known, office, pe, scripts, strings
from .util import merge_signals, shannon_entropy, signal

MAX_ANALYZE_BYTES = 16 * 1024 * 1024
MAX_REPORT_STRINGS = 500
MAX_REPORT_IMPORTS = 2000

SCRIPT_TYPES = (
    SampleType.SCRIPT_POWERSHELL,
    SampleType.SCRIPT_VBS,
    SampleType.SCRIPT_JS,
    SampleType.SCRIPT_BATCH,
)
ARCHIVE_TYPES = (SampleType.ARCHIVE_ZIP, SampleType.ARCHIVE_RAR, SampleType.ARCHIVE_7Z)
OFFICE_TYPES = (SampleType.OFFICE_DOC, SampleType.OFFICE_XLS, SampleType.OFFICE_PPT)
PE_TYPES = (SampleType.PE32, SampleType.PE64)


@dataclass
class StaticReport:
    """一次静态预筛的结果。signals 元素为 {id, severity, detail}，可直接 JSON 序列化。"""

    sample: dict[str, Any] = field(default_factory=dict)
    hashes: dict[str, Any] = field(default_factory=dict)
    size: int = 0
    type: str = SampleType.UNKNOWN.value
    entropy: float = 0.0
    pe: dict[str, Any] | None = None
    imports: list[str] = field(default_factory=list)
    sections: list[dict[str, Any]] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)
    string_stats: dict[str, Any] = field(default_factory=dict)
    signals: list[dict[str, Any]] = field(default_factory=list)
    ioc_hits: list[dict[str, str]] = field(default_factory=list)
    archive: dict[str, Any] | None = None
    script: dict[str, Any] | None = None
    office: dict[str, Any] | None = None
    known_test_file: str = ""
    truncated: bool = False
    elapsed_ms: float = 0.0

    @property
    def signal_ids(self) -> list[str]:
        return [str(item.get("id", "")) for item in self.signals]

    @property
    def top_severity(self) -> str:
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        value = "low"
        for item in self.signals:
            if rank.get(str(item.get("severity", "")), 0) > rank[value]:
                value = str(item.get("severity"))
        return value

    def has_signal(self, signal_id: str) -> bool:
        return any(item.get("id") == signal_id for item in self.signals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample": dict(self.sample),
            "hashes": dict(self.hashes),
            "size": int(self.size),
            "type": self.type,
            "entropy": round(float(self.entropy), 4),
            "pe": self.pe,
            "imports": list(self.imports),
            "sections": [dict(sec) for sec in self.sections],
            "strings": list(self.strings),
            "suspicious_strings": list(self.suspicious_strings),
            "string_stats": dict(self.string_stats),
            "signals": [dict(item) for item in self.signals],
            "signal_count": len(self.signals),
            "max_severity": self.top_severity,
            "ioc_hits": [dict(item) for item in self.ioc_hits],
            "archive": self.archive,
            "script": self.script,
            "office": self.office,
            "known_test_file": self.known_test_file,
            "truncated": bool(self.truncated),
            "elapsed_ms": round(float(self.elapsed_ms), 3),
        }


def _resolve_input(sample: Sample | str | Path | bytes | bytearray | memoryview, data: bytes | None) -> tuple[Sample, bytes, bool]:
    """统一输入：返回 (Sample, 分析用字节, 是否因上限截断)。"""
    if isinstance(sample, (bytes, bytearray, memoryview)):
        raw = bytes(sample)
        truncated = len(raw) > MAX_ANALYZE_BYTES
        if truncated:
            raw = raw[:MAX_ANALYZE_BYTES]
        return Sample.from_bytes(raw, "sample.bin"), raw, truncated

    if isinstance(sample, Sample):
        if data is not None:
            raw = bytes(data)
            truncated = len(raw) > MAX_ANALYZE_BYTES
            return sample, raw[:MAX_ANALYZE_BYTES] if truncated else raw, truncated
        if not sample.path:
            raise SampleError("Sample 没有 path 且未提供 data，无法静态分析", name=sample.name)
        return _read_path(sample.path, sample, data)

    if isinstance(sample, (str, Path)):
        path = Path(sample)
        if not path.exists():
            raise SampleError(f"样本不存在: {path}", path=str(path))
        if not path.is_file():
            raise SampleError(f"不是文件: {path}", path=str(path))
        return _read_path(path, None, data)

    raise SampleError(f"不支持的输入类型: {type(sample).__name__}")


def _read_path(path: str | Path, sample: Sample | None, data: bytes | None) -> tuple[Sample, bytes, bool]:
    p = Path(path)
    sample = sample or Sample.from_path(p)
    if data is not None:
        raw = bytes(data)
        truncated = len(raw) > MAX_ANALYZE_BYTES
        return sample, raw[:MAX_ANALYZE_BYTES] if truncated else raw, truncated
    try:
        with p.open("rb") as fh:
            raw = fh.read(MAX_ANALYZE_BYTES + 1)
    except OSError as exc:
        raise SampleError(f"读取样本失败: {p}: {exc}", path=str(p)) from exc
    truncated = len(raw) > MAX_ANALYZE_BYTES
    if truncated:
        raw = raw[:MAX_ANALYZE_BYTES]
    return sample, raw, truncated


def _report_hashes(sample: Sample, raw: bytes, truncated: bool) -> dict[str, Any]:
    if sample.sha256 and sample.size >= 0:
        return {
            "sha256": sample.sha256,
            "sha1": sample.sha1,
            "md5": sample.md5,
            "size": int(sample.size),
        }
    if truncated and sample.path:
        return dict(hash_file(sample.path))
    info = hash_bytes(raw)
    return {"sha256": info["sha256"], "sha1": info["sha1"], "md5": info["md5"], "size": info["size"]}


def analyze(sample: Sample | str | Path | bytes | bytearray | memoryview, data: bytes | None = None) -> StaticReport:
    """静态分析入口：路径 / bytes / Sample；永不执行样本。"""
    started = perf_counter()
    resolved, raw, truncated = _resolve_input(sample, data)
    report = StaticReport(truncated=truncated)
    try:
        hashes = _report_hashes(resolved, raw, truncated)
        report.hashes = hashes
        report.size = int(hashes.get("size") or resolved.size or len(raw))
        report.type = resolved.type.value
        report.sample = {
            "name": resolved.name,
            "sha256": str(hashes.get("sha256", "")),
            "size": report.size,
            "type": report.type,
            "origin": resolved.origin,
        }
        if not raw:
            report.signals = [signal("sample.empty", "low", "空文件（0 字节），无内容可分析")]
            return report

        signals_all: list[dict[str, str]] = []
        string_result = None

        # 1) 已知测试文件（EICAR 等公开无害串），只识别不执行
        known_hit = known.check_known_test_file(raw)
        if known_hit:
            report.known_test_file = str(known_hit["name"])
            signals_all.append(known_hit["signal"])

        # 2) 类型分派
        sample_type = resolved.type
        is_pe_by_magic = raw[:2] == b"MZ"
        office_name_kind = office.office_kind_from_name(resolved.name)
        is_office_input = sample_type in OFFICE_TYPES or (
            office_name_kind != ""
            and (raw[:4] == b"PK\x03\x04" or raw[:8] == office.CFB_MAGIC)
        )
        archive_failed = False
        if sample_type in PE_TYPES or is_pe_by_magic:
            try:
                info = pe.parse_pe(raw, truncated=truncated)
                report.pe = info.to_dict()
                report.sections = info.sections
                report.imports = _flatten_imports(info.imports)
                signals_all.extend(info.signals)
            except Exception as exc:  # 兜底，PE 解析器自身也应有兜底
                signals_all.append(signal("static.analysis_error", "low", f"PE 解析异常：{type(exc).__name__}: {exc}"))
        elif sample_type in SCRIPT_TYPES:
            try:
                script_result = scripts.analyze_script(raw, name=resolved.name, sample_type=sample_type.value)
                report.script = script_result
                signals_all.extend(script_result["signals"])
            except Exception as exc:
                signals_all.append(signal("static.analysis_error", "low", f"脚本分析异常：{type(exc).__name__}: {exc}"))
        elif is_office_input:
            try:
                office_result = office.analyze_office(raw, resolved.name)
                report.office = office_result
                signals_all.extend(office_result.get("signals") or [])
                # OOXML 同时复用压缩包清单检查（路径穿越/内嵌可执行等），宏信号由 office 层统一给出
                if raw[:4] == b"PK\x03\x04":
                    try:
                        archive_result = archive.analyze_archive(raw, name=resolved.name, sample_type="zip")
                        report.archive = archive_result
                        signals_all.extend(
                            item for item in archive_result["signals"] if item.get("id") != "archive.macro_container"
                        )
                    except Exception as exc:
                        signals_all.append(
                            signal("static.analysis_error", "low", f"Office 压缩容器分析异常：{type(exc).__name__}: {exc}")
                        )
            except Exception as exc:
                signals_all.append(signal("static.analysis_error", "low", f"Office 宏分析异常：{type(exc).__name__}: {exc}"))
        elif sample_type in ARCHIVE_TYPES:
            try:
                archive_result = archive.analyze_archive(raw, name=resolved.name, sample_type=sample_type.value)
                report.archive = archive_result
                signals_all.extend(archive_result["signals"])
                archive_failed = not bool(archive_result.get("valid", True))
                if archive_failed:
                    # 不是有效压缩包（损坏/改名/截断）：按原始数据做内嵌载荷检查
                    signals_all.extend(_embedded_payload_signals(raw))
            except Exception as exc:
                archive_failed = True
                signals_all.append(signal("static.analysis_error", "low", f"压缩包分析异常：{type(exc).__name__}: {exc}"))
                signals_all.extend(_embedded_payload_signals(raw))

        elif sample_type in (SampleType.DATA, SampleType.UNKNOWN):
            try:
                signals_all.extend(_embedded_payload_signals(raw))
            except Exception as exc:
                signals_all.append(signal("static.analysis_error", "low", f"内嵌载荷检查异常：{type(exc).__name__}: {exc}"))

        # 3) 字符串 / IoC（压缩包/Office 容器内容不解压，跳过）
        is_archive_like = (sample_type in ARCHIVE_TYPES or is_office_input) and not archive_failed
        if not is_archive_like:
            try:
                string_result = strings.analyze_strings(raw)
                report.strings = string_result.strings[:MAX_REPORT_STRINGS]
                report.suspicious_strings = string_result.suspicious
                report.string_stats = {
                    "total": len(string_result.strings),
                    "ascii_count": string_result.ascii_count,
                    "utf16le_count": string_result.utf16_count,
                    "truncated": string_result.truncated,
                }
                report.ioc_hits = string_result.ioc_hits
                signals_all.extend(string_result.signals)
            except Exception as exc:
                signals_all.append(signal("static.analysis_error", "low", f"字符串分析异常：{type(exc).__name__}: {exc}"))

        # 4) 整体熵（压缩包本身高熵属正常，不重复报）
        try:
            report.entropy = shannon_entropy(raw)
            if not is_archive_like and report.entropy >= 7.5:
                signals_all.append(
                    signal("sample.entropy_high", "medium", f"整体熵 {report.entropy:.2f}（疑似加密/压缩载荷）")
                )
        except Exception:
            pass

        report.signals = merge_signals(signals_all)
        return report
    finally:
        report.elapsed_ms = (perf_counter() - started) * 1000.0


def _embedded_payload_signals(data: bytes, *, window: int = 4 * 1024 * 1024) -> list[dict[str, str]]:
    """数据文件（.dat/.bin/未知类型）里找内嵌可执行/压缩包/宏/脚本标记。"""
    out: list[dict[str, str]] = []
    head = data[:window]
    if not head:
        return out
    # 内嵌 PE：找 MZ 且 e_lfanew 指向 "PE\0\0"
    offset = head.find(b"MZ")
    while offset != -1:
        if offset + 0x40 <= len(head):
            e_lfanew = int.from_bytes(head[offset + 0x3C : offset + 0x40], "little")
            pe_at = offset + e_lfanew
            if 0 < e_lfanew < 0x1000 and pe_at + 4 <= len(head) and head[pe_at : pe_at + 4] == b"PE\x00\x00":
                out.append(
                    signal(
                        "data.embedded_pe",
                        "high",
                        f"偏移 0x{offset:x} 发现内嵌 PE 可执行体（疑似打包/载荷投递）",
                    )
                )
                break
        offset = head.find(b"MZ", offset + 1)
    if head.find(b"PK\x03\x04") > 0:
        out.append(signal("data.embedded_zip", "medium", "发现内嵌 ZIP 数据（可能为释放的载荷/文档）"))
    if b"vbaProject.bin" in head:
        out.append(signal("data.embedded_macro", "high", "发现内嵌 Office 宏项目（vbaProject.bin）"))
    lowered = head.lower()
    for marker, label in (
        (b"powershell", "PowerShell"),
        (b"wscript.shell", "WScript.Shell"),
        (b"cmd.exe /c", "cmd 命令"),
        (b"autoopen", "Office AutoOpen"),
        (b"createobject", "CreateObject"),
    ):
        if marker in lowered:
            out.append(signal("data.script_marker", "medium", f"发现 {label} 脚本标记"))
            break
    return out


def _flatten_imports(imports: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for imp in imports:
        dll = str(imp.get("dll") or "").strip()
        for func in imp.get("functions", []):
            if len(out) >= MAX_REPORT_IMPORTS:
                return out
            out.append(f"{dll}!{func}" if dll else str(func))
    return out


def analyze_bytes(data: bytes, name: str = "sample.bin") -> StaticReport:
    """便捷入口：分析内存字节。"""
    sample = Sample.from_bytes(data, name)
    return analyze(sample, data)


def analyze_path(path: str | Path) -> StaticReport:
    """便捷入口：分析文件路径。"""
    return analyze(path)
