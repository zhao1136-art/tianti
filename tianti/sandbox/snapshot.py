"""工作目录文件快照 diff + 关键注册表子树前后导出 diff（纯标准库）。

文件：walk + sha256 流式哈希；注册表：reg export 临时 .reg 文本解析。
用于降级观测路径（source=snapshot:，confidence=medium）。
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

CHUNK = 1024 * 1024
MAX_FILE_BYTES = 500 * 1024 * 1024

DEFAULT_REG_SUBTREES: tuple[str, ...] = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
)
OPTIONAL_REG_SUBTREES: tuple[str, ...] = (
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
)

_ROOT_ALIASES = {
    "HKEY_CURRENT_USER": "HKCU",
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKEY_USERS": "HKU",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKEY_CURRENT_CONFIG": "HKCC",
}
_REG_KEY_RE = re.compile(r"^\[(.+)\]$")
_REG_VALUE_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"=(.*)$')


# ---------------------------------------------------------------------------
# 文件快照
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FileState:
    rel_path: str
    size: int
    sha256: str
    entropy: float


@dataclass(frozen=True)
class FileChange:
    change: str  # created / modified / deleted
    rel_path: str
    abs_path: str
    size: int = 0
    sha256: str = ""
    old_size: int = 0
    old_sha256: str = ""
    entropy: float = 0.0


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def file_entropy(path: str | Path, *, limit: int = 1024 * 1024) -> float:
    """样本文件前 N 字节的 Shannon 熵（0..8）。读取失败返回 0。"""
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(limit)
    except OSError:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def snapshot_tree(root: str | Path, *, max_files: int = 5000, hash_limit: int = MAX_FILE_BYTES) -> dict[str, FileState]:
    """记录目录树内全部普通文件状态（相对路径统一用 / 分隔）。"""
    base = Path(root)
    states: dict[str, FileState] = {}
    if not base.is_dir():
        return states
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for name in sorted(filenames):
            absolute = Path(dirpath) / name
            try:
                if not absolute.is_file() or absolute.is_symlink():
                    continue
                stat = absolute.stat()
                if stat.st_size > hash_limit:
                    continue
                rel = str(absolute.relative_to(base)).replace(os.sep, "/")
                states[rel] = FileState(
                    rel_path=rel,
                    size=int(stat.st_size),
                    sha256=sha256_file(absolute),
                    entropy=file_entropy(absolute),
                )
            except OSError:
                continue
            if len(states) >= max_files:
                return states
    return states


def diff_files(before: dict[str, FileState], after: dict[str, FileState], *, root: str | Path = "") -> list[FileChange]:
    """比较两个快照，返回 created/modified/deleted 变化（确定性排序）。"""
    base = Path(root) if str(root) else Path()
    changes: list[FileChange] = []
    for rel in sorted(after):
        new = after[rel]
        old = before.get(rel)
        absolute = str(base / rel) if str(root) else rel
        if old is None:
            changes.append(
                FileChange(
                    change="created",
                    rel_path=rel,
                    abs_path=absolute,
                    size=new.size,
                    sha256=new.sha256,
                    entropy=new.entropy,
                )
            )
        elif old.sha256 != new.sha256 or old.size != new.size:
            changes.append(
                FileChange(
                    change="modified",
                    rel_path=rel,
                    abs_path=absolute,
                    size=new.size,
                    sha256=new.sha256,
                    old_size=old.size,
                    old_sha256=old.sha256,
                    entropy=new.entropy,
                )
            )
    for rel in sorted(before):
        if rel not in after:
            old = before[rel]
            changes.append(
                FileChange(
                    change="deleted",
                    rel_path=rel,
                    abs_path=str(base / rel) if str(root) else rel,
                    old_size=old.size,
                    old_sha256=old.sha256,
                )
            )
    return changes


# ---------------------------------------------------------------------------
# 注册表快照
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RegistryChange:
    change: str  # created / modified / deleted
    key: str
    name: str
    data: str = ""
    old_data: str = ""

    @property
    def target(self) -> str:
        return self.key if self.name == "@" else f"{self.key}\\{self.name}"


def normalize_key(key: str) -> str:
    cleaned = key.strip()
    for long_name, short in _ROOT_ALIASES.items():
        if cleaned.upper().startswith(long_name):
            return short + cleaned[len(long_name) :]
    return cleaned


def parse_reg_export(text: str) -> dict[str, dict[str, str]]:
    """解析 reg export 生成的 .reg 文本 -> {key: {value_name: raw_data}}。"""
    result: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        key_match = _REG_KEY_RE.match(stripped)
        if key_match:
            current = normalize_key(key_match.group(1))
            result.setdefault(current, {})
            continue
        if current is None:
            continue
        if stripped.startswith("@="):
            result[current]["@"] = stripped[2:]
            continue
        value_match = _REG_VALUE_RE.match(stripped)
        if value_match:
            result[current][value_match.group(1)] = value_match.group(2)
    return result


def export_registry(
    subtrees: Iterable[str] = DEFAULT_REG_SUBTREES,
    *,
    timeout_s: float = 20.0,
) -> tuple[dict[str, dict[str, str]], list[str]]:
    """导出关键注册表子树；返回 (状态, 错误列表)。错误不致命。"""
    states: dict[str, dict[str, str]] = {}
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="tianti_reg_") as tmp:
        for index, subtree in enumerate(subtrees):
            target = Path(tmp) / f"sub_{index}.reg"
            try:
                completed = subprocess.run(
                    ["reg", "export", subtree, str(target), "/y"],
                    capture_output=True,
                    text=True, errors="replace",
                    timeout=timeout_s,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(f"reg export {subtree}: {exc}")
                continue
            if completed.returncode != 0 or not target.exists():
                detail = (completed.stderr or completed.stdout or "").strip()[:160]
                errors.append(f"reg export {subtree}: rc={completed.returncode} {detail}")
                continue
            try:
                text = target.read_text(encoding="utf-16")
            except UnicodeError:
                try:
                    text = target.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    errors.append(f"reg export {subtree}: read {exc}")
                    continue
            except OSError as exc:
                errors.append(f"reg export {subtree}: read {exc}")
                continue
            for key, values in parse_reg_export(text).items():
                states[key] = values
    return states, errors


def diff_registry(
    before: dict[str, dict[str, str]],
    after: dict[str, dict[str, str]],
) -> list[RegistryChange]:
    changes: list[RegistryChange] = []
    for key in sorted(set(before) | set(after)):
        old_values = before.get(key, {})
        new_values = after.get(key, {})
        for name in sorted(new_values):
            if name not in old_values:
                changes.append(RegistryChange("created", key, name, new_values[name]))
            elif old_values[name] != new_values[name]:
                changes.append(RegistryChange("modified", key, name, new_values[name], old_values[name]))
        for name in sorted(old_values):
            if name not in new_values:
                changes.append(RegistryChange("deleted", key, name, old_data=old_values[name]))
    return changes


def rollback_created_values(changes: Iterable[RegistryChange], *, timeout_s: float = 15.0) -> tuple[list[str], list[str]]:
    """回滚沙箱内“新建”的注册表值（仅值，不删键），best-effort。

    返回 (成功回滚的 target 列表, 错误列表)。
    """
    rolled: list[str] = []
    errors: list[str] = []
    for change in changes:
        if change.change != "created" or change.name in ("@", ""):
            continue
        try:
            completed = subprocess.run(
                ["reg", "delete", change.key, "/v", change.name, "/f"],
                capture_output=True,
                text=True, errors="replace",
                timeout=timeout_s,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"rollback {change.target}: {exc}")
            continue
        if completed.returncode == 0:
            rolled.append(change.target)
        else:
            errors.append(f"rollback {change.target}: rc={completed.returncode}")
    return rolled, errors
