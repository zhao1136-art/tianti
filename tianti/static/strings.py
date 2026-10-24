"""字符串提取与可疑字符串/IoC 扫描（ASCII + UTF-16LE，纯标准库）。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .util import signal

MIN_STRING_LEN = 4
MAX_STRINGS = 500
MAX_SCAN_BYTES = 4 * 1024 * 1024
MAX_SUSPICIOUS = 100
MAX_IOCS = 100
MAX_EXAMPLE_LEN = 160

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

_URL_RE = re.compile(r"(?:https?|ftp|hxxps?)://[^\s\"'<>]{4,}", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|ru|cn|top|xyz|info|biz|io|cc|tk|su|onion|site|online|club|shop|pw)\b",
    re.IGNORECASE,
)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
_REGISTRY_RE = re.compile(
    r"(?:HKCU|HKLM|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s\"'<>]{2,200}", re.IGNORECASE
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_ENCODED_RE = re.compile(r"(?:^|[\s\"'])[-/](?:enc|encodedcommand)\b", re.IGNORECASE)
_HEX_ADDR_RE = re.compile(r"\b0x[0-9a-f]{8,16}\b", re.IGNORECASE)

# 关键词组：(signal_id, severity, 描述, 关键词[全部小写])
_KEYWORD_GROUPS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    (
        "strings.persistence",
        "medium",
        "持久化关键词",
        (
            r"currentversion\run",
            r"currentversion\runonce",
            r"currentversion\runservices",
            "\\startup\\",
            "schtasks /create",
            "register-scheduledtask",
            "new-service",
            "sc create",
            "winlogon",
            "userinit",
            "active setup",
        ),
    ),
    (
        "strings.defense_evasion",
        "high",
        "防御规避关键词",
        (
            "vssadmin delete shadows",
            "wbadmin delete",
            "bcdedit /set",
            "wevtutil cl",
            "clear-eventlog",
            "set-mppreference",
            "disablerealtimemonitoring",
            "add-mppreference",
            "netsh advfirewall",
            "sc stop windefend",
            "amsiutils",
            "amsiinitfailed",
            "set-executionpolicy bypass",
            "executionpolicy bypass",
            "disable-windowsdefender",
        ),
    ),
    (
        "strings.command_exec",
        "medium",
        "命令执行/系统工具关键词",
        (
            "cmd.exe /c",
            "cmd /c",
            "powershell.exe -",
            "powershell -",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "regsvr32",
            "certutil -",
            "bitsadmin",
        ),
    ),
    (
        "strings.download",
        "medium",
        "下载/远程加载关键词",
        (
            "downloadstring",
            "downloadfile",
            "invoke-webrequest",
            "net.webclient",
            "start-bitstransfer",
            "urlmon",
            "winhttp",
            "httpclient",
        ),
    ),
    (
        "strings.credential_access",
        "high",
        "凭据访问关键词",
        (
            "mimikatz",
            "sekurlsa",
            "lsass",
            "procdump",
            "comsvcs.dll",
            "minidump",
            "lsaenumeratelogonsessions",
            "cryptunprotectdata",
        ),
    ),
    (
        "strings.ransom_note",
        "medium",
        "勒索提示/加密扩展名关键词",
        (
            "your files have been encrypted",
            "all your files",
            "decrypt",
            "readme_for_decrypt",
            ".locked",
            ".encrypted",
            "bitcoin",
        ),
    ),
    (
        "strings.temp_staging",
        "low",
        "临时/公共目录暂存路径",
        ("%temp%", r"appdata\local\temp", "\\temp\\", r"c:\users\public"),
    ),
)


@dataclass
class StringsResult:
    strings: list[str] = field(default_factory=list)
    ascii_count: int = 0
    utf16_count: int = 0
    suspicious: list[str] = field(default_factory=list)
    signals: list[dict[str, str]] = field(default_factory=list)
    ioc_hits: list[dict[str, str]] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "strings": list(self.strings),
            "ascii_count": self.ascii_count,
            "utf16_count": self.utf16_count,
            "suspicious": list(self.suspicious),
            "signals": [dict(sig) for sig in self.signals],
            "ioc_hits": [dict(ioc) for ioc in self.ioc_hits],
            "truncated": self.truncated,
        }


def extract_ascii_strings(data: bytes, *, min_len: int = MIN_STRING_LEN, limit: int = MAX_STRINGS) -> list[str]:
    if len(data) > MAX_SCAN_BYTES:
        data = data[:MAX_SCAN_BYTES]
    pattern = _ASCII_RE if min_len <= 4 else re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    out: list[str] = []
    for match in pattern.finditer(data):
        out.append(match.group(0).decode("latin-1"))
        if len(out) >= limit:
            break
    return out


def extract_utf16le_strings(data: bytes, *, min_len: int = MIN_STRING_LEN, limit: int = MAX_STRINGS) -> list[str]:
    if len(data) > MAX_SCAN_BYTES:
        data = data[:MAX_SCAN_BYTES]
    pattern = _UTF16_RE if min_len <= 4 else re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    out: list[str] = []
    for match in pattern.finditer(data):
        raw = match.group(0)
        out.append(raw[::2].decode("latin-1"))
        if len(out) >= limit:
            break
    return out


def _likely_utf16_text(data: bytes) -> bool:
    """UTF-16LE 文本的奇数位几乎全为 0；二进制数据上跑 UTF-16 正则很贵，先做廉价探测。"""
    sample = data[:65536]
    if not sample:
        return False
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    odd = sample[1::2]
    if not odd:
        return False
    return odd.count(b"\x00") / len(odd) >= 0.5


def extract_strings(data: bytes, *, limit: int = MAX_STRINGS) -> StringsResult:
    """提取 ASCII 与 UTF-16LE 字符串，去重并上限截断。"""
    ascii_strings = extract_ascii_strings(data, limit=limit)
    utf16_strings = extract_utf16le_strings(data, limit=limit) if _likely_utf16_text(data) else []
    seen: set[str] = set()
    merged: list[str] = []
    for value in ascii_strings + utf16_strings:
        if value in seen:
            continue
        seen.add(value)
        merged.append(value)
        if len(merged) >= limit:
            break
    return StringsResult(
        strings=merged,
        ascii_count=len(ascii_strings),
        utf16_count=len(utf16_strings),
        truncated=len(merged) >= limit,
    )


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return False
    return all(0 <= octet <= 255 for octet in octets) and not all(o == 0 for o in octets)


def _short(value: str) -> str:
    text = value.strip()
    return text if len(text) <= MAX_EXAMPLE_LEN else text[: MAX_EXAMPLE_LEN - 3] + "..."


def _ioc_priority(kind: str) -> int:
    return {"url": 0, "ip": 1, "domain": 2, "email": 3, "registry": 4, "base64": 5, "hex": 6}.get(kind, 9)


def scan_strings(strings: list[str]) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    """扫描字符串，返回 (signals, ioc_hits, suspicious 字符串列表)。"""
    aggregated: dict[str, dict[str, Any]] = {}
    iocs: dict[tuple[str, str], dict[str, str]] = {}
    suspicious: list[str] = []
    suspicious_seen: set[str] = set()

    def add_signal(signal_id: str, severity: str, detail: str, example: str) -> None:
        entry = aggregated.get(signal_id)
        if entry is None:
            entry = {"severity": severity, "detail": detail, "count": 0, "examples": []}
            aggregated[signal_id] = entry
        entry["count"] += 1
        if len(entry["examples"]) < 3:
            entry["examples"].append(_short(example))

    def add_ioc(kind: str, value: str, severity: str = "low") -> None:
        key = (kind, value)
        if key in iocs or len(iocs) >= MAX_IOCS:
            return
        iocs[key] = {
            "kind": kind,
            "value": value if len(value) <= 300 else value[:297] + "...",
            "severity": severity,
            "detail": f"静态字符串中发现 {kind}",
        }

    for raw in strings:
        text = raw.strip()
        if not text:
            continue

        matched = False
        for match in _URL_RE.finditer(text):
            add_ioc("url", match.group(0))
            add_signal("strings.url", "low", "嵌入 URL", match.group(0))
            matched = True
        for match in _IP_RE.finditer(text):
            if _valid_ipv4(match.group(0)):
                add_ioc("ip", match.group(0))
                add_signal("strings.ip_address", "low", "嵌入 IP 地址", match.group(0))
                matched = True
        for match in _DOMAIN_RE.finditer(text):
            value = match.group(0)
            # 过滤常见文件名/版本号样式（xxx.dll 之类已不在 TLD 列表）
            add_ioc("domain", value)
            add_signal("strings.domain", "low", "嵌入域名", value)
            matched = True
        for match in _EMAIL_RE.finditer(text):
            add_ioc("email", match.group(0))
            matched = True
        for match in _REGISTRY_RE.finditer(text):
            add_ioc("registry", match.group(0))
            matched = True
        for match in _BASE64_RE.finditer(text):
            add_ioc("base64", match.group(0)[:120])
            add_signal("strings.base64_blob", "medium", "长 Base64 块（可能隐藏载荷）", match.group(0))
            matched = True
        if _ENCODED_RE.search(text) or "frombase64string" in text.lower():
            add_signal("strings.encoded_command", "high", "疑似编码命令（-enc / FromBase64String）", text)
            matched = True
        if _HEX_ADDR_RE.search(text):
            add_ioc("hex", _HEX_ADDR_RE.search(text).group(0))  # type: ignore[union-attr]
            matched = True

        low = text.lower()
        for signal_id, severity, detail, keywords in _KEYWORD_GROUPS:
            for keyword in keywords:
                if keyword in low:
                    add_signal(signal_id, severity, detail, text)
                    matched = True
                    break

        if matched:
            key = _short(text).lower()
            if key not in suspicious_seen and len(suspicious) < MAX_SUSPICIOUS:
                suspicious_seen.add(key)
                suspicious.append(_short(text))

    signals: list[dict[str, str]] = []
    for signal_id, entry in aggregated.items():
        examples = " | ".join(entry["examples"])
        signals.append(
            signal(
                signal_id,
                entry["severity"],
                f"{entry['detail']}（{entry['count']} 处，示例：{examples}）",
            )
        )
    ioc_list = sorted(iocs.values(), key=lambda item: (_ioc_priority(item["kind"]), item["value"]))
    return signals, ioc_list, suspicious


def analyze_strings(data: bytes) -> StringsResult:
    result = extract_strings(data)
    signals, iocs, suspicious = scan_strings(result.strings)
    result.signals = signals
    result.ioc_hits = iocs
    result.suspicious = suspicious
    return result
