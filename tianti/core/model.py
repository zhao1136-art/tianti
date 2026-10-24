"""样本模型与类型识别（不执行样本，只读头部）。"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .hashing import hash_bytes, hash_file

SNIFF_LIMIT = 64 * 1024


class SampleType(str, enum.Enum):
    PE32 = "pe32"
    PE64 = "pe64"
    SCRIPT_POWERSHELL = "script/powershell"
    SCRIPT_VBS = "script/vbs"
    SCRIPT_JS = "script/js"
    SCRIPT_BATCH = "script/batch"
    ARCHIVE_ZIP = "archive/zip"
    ARCHIVE_RAR = "archive/rar"
    ARCHIVE_7Z = "archive/7z"
    OFFICE_DOC = "office/doc"
    OFFICE_XLS = "office/xls"
    OFFICE_PPT = "office/ppt"
    TEXT = "text"
    UNKNOWN = "unknown"

    @property
    def is_executable(self) -> bool:
        return self in (SampleType.PE32, SampleType.PE64)

    @property
    def is_script(self) -> bool:
        return self.value.startswith("script/")

    @property
    def is_archive(self) -> bool:
        return self.value.startswith("archive/")


_SUFFIX_TYPES: dict[str, SampleType] = {
    ".ps1": SampleType.SCRIPT_POWERSHELL,
    ".psm1": SampleType.SCRIPT_POWERSHELL,
    ".psd1": SampleType.SCRIPT_POWERSHELL,
    ".vbs": SampleType.SCRIPT_VBS,
    ".vbe": SampleType.SCRIPT_VBS,
    ".js": SampleType.SCRIPT_JS,
    ".jse": SampleType.SCRIPT_JS,
    ".bat": SampleType.SCRIPT_BATCH,
    ".cmd": SampleType.SCRIPT_BATCH,
    ".zip": SampleType.ARCHIVE_ZIP,
    ".rar": SampleType.ARCHIVE_RAR,
    ".7z": SampleType.ARCHIVE_7Z,
    ".doc": SampleType.OFFICE_DOC,
    ".docx": SampleType.OFFICE_DOC,
    ".xls": SampleType.OFFICE_XLS,
    ".xlsx": SampleType.OFFICE_XLS,
    ".ppt": SampleType.OFFICE_PPT,
    ".pptx": SampleType.OFFICE_PPT,
    ".txt": SampleType.TEXT,
    ".md": SampleType.TEXT,
    ".json": SampleType.TEXT,
    ".xml": SampleType.TEXT,
    ".html": SampleType.TEXT,
    ".htm": SampleType.TEXT,
    ".csv": SampleType.TEXT,
    ".log": SampleType.TEXT,
    ".ini": SampleType.TEXT,
    ".yaml": SampleType.TEXT,
    ".yml": SampleType.TEXT,
}


def _pe_kind(head: bytes) -> SampleType | None:
    """从 MZ 头判断 PE32 / PE64，失败返回 None。"""
    if len(head) < 0x40:
        return None
    try:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
    except ValueError:
        return None
    if e_lfanew <= 0 or e_lfanew + 6 > len(head):
        return None
    if head[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    machine = int.from_bytes(head[e_lfanew + 4 : e_lfanew + 6], "little")
    if machine == 0x8664:
        return SampleType.PE64
    if machine == 0x14C:
        return SampleType.PE32
    return None


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return False
    # 先按 UTF-8 严格解码：中文/日文等文本按字节可打印率会被误判，UTF-8 判定更准
    try:
        decoded = data[:8192].decode("utf-8")
    except UnicodeDecodeError:
        pass
    else:
        if not any(ord(ch) < 32 and ch not in "\t\n\r" for ch in decoded):
            return True
    sample = data[:8192]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) > 0.90


def guess_type(name: str, head: bytes = b"") -> SampleType:
    """按魔术字节 -> 后缀 -> 文本判定的顺序猜测类型。"""
    if head[:2] == b"MZ":
        kind = _pe_kind(head)
        if kind is not None:
            return kind
    if head[:4] == b"PK\x03\x04":
        return SampleType.ARCHIVE_ZIP
    if head[:4] == b"Rar!":
        return SampleType.ARCHIVE_RAR
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return SampleType.ARCHIVE_7Z
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return SampleType.OFFICE_DOC
    suffix = Path(name).suffix.lower()
    if suffix in _SUFFIX_TYPES:
        return _SUFFIX_TYPES[suffix]
    if _looks_text(head):
        return SampleType.TEXT
    return SampleType.UNKNOWN


@dataclass
class Sample:
    """被检样本的元信息（不含内容，内容按需从 store 读取）。"""

    name: str
    sha256: str = ""
    size: int = 0
    type: SampleType = SampleType.UNKNOWN
    sha1: str = ""
    md5: str = ""
    path: str | None = None
    origin: str = "file"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
            "type": self.type.value,
        }
        if self.sha1:
            out["sha1"] = self.sha1
        if self.md5:
            out["md5"] = self.md5
        if self.path:
            out["path"] = self.path
        out["origin"] = self.origin
        if self.extra:
            out["extra"] = self.extra
        return out

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Sample":
        return cls(
            name=str(payload.get("name", "")),
            sha256=str(payload.get("sha256", "")),
            size=int(payload.get("size", 0) or 0),
            type=SampleType(str(payload.get("type", SampleType.UNKNOWN.value))),
            sha1=str(payload.get("sha1", "")),
            md5=str(payload.get("md5", "")),
            path=payload.get("path"),
            origin=str(payload.get("origin", "file")),
            extra=dict(payload.get("extra") or {}),
        )

    @classmethod
    def from_path(cls, path: str | Path, *, origin: str = "file") -> "Sample":
        p = Path(path)
        info = hash_file(p)
        with p.open("rb") as fh:
            head = fh.read(SNIFF_LIMIT)
        return cls(
            name=p.name,
            sha256=str(info["sha256"]),
            size=int(info["size"]),
            type=guess_type(p.name, head),
            sha1=str(info["sha1"]),
            md5=str(info["md5"]),
            path=str(p),
            origin=origin,
        )

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        name: str,
        *,
        origin: str = "api",
        sample_type: SampleType | None = None,
    ) -> "Sample":
        info = hash_bytes(data)
        return cls(
            name=name,
            sha256=str(info["sha256"]),
            size=int(info["size"]),
            type=sample_type or guess_type(name, data[:SNIFF_LIMIT]),
            sha1=str(info["sha1"]),
            md5=str(info["md5"]),
            origin=origin,
        )
