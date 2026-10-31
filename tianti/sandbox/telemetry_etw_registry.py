"""定向注册表 ETW：logman 只开 Microsoft-Windows-Kernel-Registry，tracerpt 解析。

与 telemetry_etw.GeneralProfile（wpr 全量，~97s）不同，本模块只采注册表 provider：
本机实测 start ~65ms、stop ~50ms、tracerpt ~2s（XML ~14MB），可默认随深扫启用。
产出 registry:set / registry:delete 事件，含 ValueName、Status/denied，能看见
低完整性被拒绝的写尝试（快照 net-diff 看不到）。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

from .telemetry_etw import EtwEvent, _event_data, _iter_events, _local, _parse_time, _system_field, is_admin

LOGNAM = shutil.which("logman")
TRACERPT = shutil.which("tracerpt")
REGISTRY_GUID = "{70EB4F03-C1DE-4F73-A051-33D13D5413BD}"
SESSION_PREFIX = "TiantiReg"

# Kernel-Registry 事件 id 映射（本机实测）
CREATE_KEY_IDS = {0, 2}
SET_VALUE_IDS = {5}
DELETE_VALUE_IDS = {6}
DELETE_KEY_IDS = {11}
QUERY_VALUE_IDS = {7}
_INTERESTING = (
    "currentversion\\run",
    "currentversion\\runonce",
    "winlogon",
    "windows defender",
    "lsass",
    "\\sam\\",
    "\\security\\",
    "\\config\\system",
    "lsa\\secrets",
    "vbox",
    "vmware",
    "virtualbox",
    "qemu",
    "\\startup\\",
)


def _interesting(target: str) -> bool:
    lowered = (target or "").lower()
    return any(token in lowered for token in _INTERESTING)


def available() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "仅支持 Windows"
    if not LOGNAM:
        return False, "logman.exe 不可用"
    if not TRACERPT:
        return False, "tracerpt.exe 不可用"
    if not is_admin():
        return False, "需要管理员权限"
    return True, "logman + tracerpt 可用（Kernel-Registry 定向采集）"


def _normalize_key(relative: str) -> str:
    """把 ETW 的 \\Registry\\Machine\\... 归一化为 HKLM/HKCU 形式。"""
    text = (relative or "").replace("/", "\\")
    lower = text.lower()
    if lower.startswith("\\registry\\machine"):
        return "HKLM" + text[len("\\registry\\machine") :]
    if lower.startswith("\\registry\\user"):
        rest = text[len("\\registry\\user") :].lstrip("\\")
        parts = rest.split("\\", 1)
        tail = parts[1] if len(parts) > 1 else ""
        return "HKCU" + ("\\" + tail if tail else "")
    return text


def _resolve_relative(base: str, relative: str, handle_path: dict[str, str]) -> str:
    """把 ETW RelativeName 解析成完整/可读路径（可能是相对父 key 的路径）。"""
    text = (relative or "").replace("/", "\\")
    if text.lower().startswith("\\registry\\"):
        return _normalize_key(text)
    parent = handle_path.get((base or "").strip())
    if parent:
        return parent.rstrip("\\") + "\\" + text
    return text


def _status_denied(status: str) -> bool:
    value = (status or "").strip().lower()
    return value not in ("", "0", "0x0", "0x00000000")


def _pid(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


class RegistryEtwSession:
    """一次注册表定向采集；调用方负责 try/except 降级。"""

    def __init__(self, workdir: str | Path, *, session_suffix: str = "") -> None:
        self.workdir = Path(workdir)
        self.name = f"{SESSION_PREFIX}-{(session_suffix or os.urandom(4).hex())[:12]}"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.providers_file = self.workdir / f"{self.name}.txt"
        self.etl_path = self.workdir / f"{self.name}.etl"
        self.xml_path = self.workdir / f"{self.name}.xml"
        self.running = False
        self.error = ""

    def start(self) -> None:
        if not LOGNAM or not TRACERPT:
            raise RuntimeError("logman/tracerpt 不可用")
        self.providers_file.write_text(
            f"{REGISTRY_GUID} 0xffffffffffffffff 5\n", encoding="ascii"
        )
        command = [
            LOGNAM, "create", "trace", self.name,
            "-pf", str(self.providers_file),
            "-o", str(self.etl_path),
            "-bs", "256",   # 每缓冲 256KB
            "-nb", "64",    # 64 个缓冲，降低高负载下丢事件概率
            "-ft", "1",     # 1s 刷新
            "-ets",
        ]
        proc = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode != 0:
            raise RuntimeError(
                ((proc.stdout or "") + (proc.stderr or "")).strip()[:300] or "logman create trace 失败"
            )
        self.running = True

    def stop(
        self,
        *,
        t0: datetime | None = None,
        allowed_pids: set[int] | None = None,
        limit: int = 5000,
    ) -> tuple[list[EtwEvent], dict[str, Any]]:
        meta: dict[str, Any] = {"enabled": True, "ok": False, "events": 0, "denied": 0, "session": self.name}
        if self.running:
            stop = subprocess.run(
                [LOGNAM, "stop", self.name, "-ets"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.running = False
            if stop.returncode != 0:
                meta["error"] = ((stop.stdout or "") + (stop.stderr or "")).strip()[:300]
                return [], meta
        if not self.etl_path.is_file() or self.etl_path.stat().st_size == 0:
            meta["error"] = "未生成 ETL"
            return [], meta
        parse = subprocess.run(
            [TRACERPT, str(self.etl_path), "-of", "XML", "-o", str(self.xml_path)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if parse.returncode != 0 or not self.xml_path.is_file():
            meta["error"] = ((parse.stdout or "") + (parse.stderr or "")).strip()[:300] or "tracerpt 失败"
            return [], meta
        try:
            root = ET.parse(self.xml_path).getroot()
        except (ET.ParseError, OSError) as exc:
            meta["error"] = f"XML 解析失败: {exc}"
            return [], meta

        events: list[EtwEvent] = []
        handle_path: dict[str, str] = {}
        seen: set[tuple[str, str, int | None]] = set()
        total = 0
        for element in _iter_events(root):
            fields = _system_field(element)
            if "kernel-registry" not in (fields.get("provider_Name") or "").lower():
                continue
            total += 1
            data = _event_data(element)
            try:
                event_id = int(fields.get("EventID") or -1)
            except ValueError:
                continue
            pid = _pid(fields.get("execution_ProcessID"))
            if allowed_pids is not None and pid not in allowed_pids:
                continue
            handle = (data.get("KeyObject") or "").strip()
            base = (data.get("BaseObject") or "").strip()
            relative = (data.get("RelativeName") or "").strip()
            status = (data.get("Status") or "").strip()
            denied = _status_denied(status)
            parsed_time = _parse_time(fields.get("time_SystemTime") or "")
            ts = 0.0
            if parsed_time is not None and t0 is not None:
                ts = max(0.0, (parsed_time - t0).total_seconds())

            if relative:
                full = _resolve_relative(base, relative, handle_path)
                if handle:
                    handle_path[handle] = full
                # 低完整性/权限被拒绝的写尝试：RegOpenKey/CreateKey 返回 ACCESS_DENIED
                if (
                    event_id in (1, 2)
                    and status.upper().startswith("0XC0000022")
                    and full
                    and _interesting(full)
                ):
                    target = full.rstrip("\\") + "\\"
                    dedupe = ("set", target.lower(), pid)
                    if dedupe in seen:
                        continue
                    seen.add(dedupe)
                    events.append(
                        EtwEvent(
                            ts,
                            "registry",
                            "set",
                            "etw:registry",
                            confidence="high",
                            pid=pid,
                            target=target,
                            args={
                                "etw_event_id": event_id,
                                "status": status,
                                "denied": True,
                                "attempt": "open_key",
                            },
                        )
                    )
                    if len(events) >= limit:
                        break
                continue

            value_name = (data.get("ValueName") or "").strip()
            if event_id == QUERY_VALUE_IDS:
                if not value_name:
                    continue
                key_path = handle_path.get(handle)
                if not key_path:
                    continue
                query_target = key_path.rstrip("\\") + "\\" + value_name
                if not _interesting(query_target):
                    continue
                dedupe = ("query", query_target.lower(), pid)
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                events.append(
                    EtwEvent(
                        ts,
                        "registry",
                        "query",
                        "etw:registry",
                        confidence="high",
                        pid=pid,
                        target=query_target,
                        args={"etw_event_id": event_id, "status": status, "denied": denied},
                    )
                )
                continue
            if event_id not in SET_VALUE_IDS and event_id not in DELETE_VALUE_IDS:
                continue
            if not value_name:
                continue
            key_path = handle_path.get(handle)
            if not key_path or not key_path.lower().startswith(("hklm", "hkcu")):
                continue
            target = key_path.rstrip("\\") + "\\" + value_name
            action = "set" if event_id in SET_VALUE_IDS else "delete"
            dedupe = (action, target.lower(), pid)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            events.append(
                EtwEvent(
                    ts,
                    "registry",
                    action,
                    "etw:registry",
                    confidence="high",
                    pid=pid,
                    target=target,
                    args={
                        "etw_event_id": event_id,
                        "status": status,
                        "denied": denied,
                        "value_name": value_name,
                    },
                )
            )
            if len(events) >= limit:
                break
        meta.update(
            {
                "ok": True,
                "events": len(events),
                "denied": sum(1 for event in events if event.args.get("denied")),
                "total_registry_events": total,
                "xml_bytes": self.xml_path.stat().st_size if self.xml_path.is_file() else 0,
            }
        )
        return events, meta
