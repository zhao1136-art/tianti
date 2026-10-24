"""best-effort ETW 采集：wpr -start / -stop + tracerpt 导出 XML + 解析。

重要：本机实测 GeneralProfile 单样本 wpr stop 约 24s、tracerpt 约 73s、
XML 约 450MB，远超 deep 策略 20s 的预算，因此 **默认关闭**。
ContainmentBackend(use_etw=True) 可显式开启；任何失败都必须优雅降级，
原因写入 trace.extra["etw"]，绝不因为 ETW 失败而让沙箱失败。
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

WPR = shutil.which("wpr")
TRACERPT = shutil.which("tracerpt")
shell32 = ctypes.WinDLL("shell32")
shell32.IsUserAnAdmin.argtypes = []
shell32.IsUserAnAdmin.restype = ctypes.c_bool

KERNEL_PROCESS_GUIDS = {
    "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716",
    "9e814aad-3204-11d2-9a82-006008a86939",
}
KERNEL_FILE_GUIDS = {"edd08927-9cc4-4e65-b970-c2560fb5c289"}
KERNEL_REGISTRY_GUIDS = {"70eb4f03-c1de-4f73-a051-33d13d5413bd"}
KERNEL_NETWORK_GUIDS = {"7dd42a49-5329-4832-8dfd-43d979153a88"}
DNS_CLIENT_GUIDS = {"1c95126e-7eea-49a9-a3fe-a378b03ddb4d"}
TCPIP_GUIDS = {"2f07e2ee-15db-40f1-90ef-9d7ba282188a"}


class EtwUnavailable(RuntimeError):
    """ETW 不可用或采集中断（调用方必须降级，不得使沙箱失败）。"""


@dataclass
class EtwEvent:
    ts: float
    category: str
    action: str
    source: str
    confidence: str = "medium"
    pid: int | None = None
    tid: int | None = None
    ppid: int | None = None
    image: str | None = None
    target: str | None = None
    args: dict[str, Any] = field(default_factory=dict)


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def available() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "仅支持 Windows"
    if not WPR:
        return False, "wpr.exe 不可用"
    if not TRACERPT:
        return False, "tracerpt.exe 不可用"
    if not is_admin():
        return False, "需要管理员权限"
    return True, "wpr + tracerpt 可用（admin）；注意 GeneralProfile 采集开销大"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _iter_events(root: ET.Element) -> Iterable[ET.Element]:
    for element in root.iter():
        if _local(element.tag) == "Event":
            yield element


def _system_field(event: ET.Element) -> dict[str, str]:
    fields: dict[str, str] = {}
    for system in event:
        if _local(system.tag) != "System":
            continue
        for child in system:
            name = _local(child.tag)
            if name == "Provider":
                for key, value in child.attrib.items():
                    fields[f"provider_{_local(key)}"] = value
            elif name == "Execution":
                for key, value in child.attrib.items():
                    fields[f"execution_{_local(key)}"] = value
            elif name == "TimeCreated":
                for key, value in child.attrib.items():
                    fields[f"time_{_local(key)}"] = value
            elif name in ("EventID", "Opcode", "Task", "Level"):
                fields[name] = (child.text or "").strip()
    return fields


def _event_data(event: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    for element in event:
        if _local(element.tag) != "EventData":
            continue
        for child in element:
            if _local(child.tag) != "Data":
                continue
            name = child.attrib.get("Name") or ""
            data[name] = (child.text or "").strip()
    return data


def _parse_time(value: str) -> datetime | None:
    for parser in (
        lambda v: datetime.fromisoformat(v),
        lambda v: datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%f%z"),
    ):
        try:
            parsed = parser(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue
    return None


def _provider_key(fields: dict[str, str]) -> str:
    guid = (fields.get("provider_Guid") or "").lower().strip("{}")
    name = fields.get("provider_Name") or ""
    return f"{guid}|{name}"


def classify_event(fields: dict[str, str], data: dict[str, str]) -> EtwEvent | None:
    """把一条 ETW 事件映射为 Trace 事件；无法可靠映射时返回 None（计入 unmapped）。"""
    key = _provider_key(fields)
    guid, _, name = key.partition("|")
    name_lower = name.lower()
    try:
        event_id = int(fields.get("EventID") or -1)
    except ValueError:
        event_id = -1
    pid = _int(data.get("ProcessID")) or _int(fields.get("execution_ProcessID"))
    tid = _int(fields.get("execution_ThreadID"))
    ppid = _int(data.get("ParentProcessID")) or _int(data.get("ParentID"))

    if guid in KERNEL_PROCESS_GUIDS or "kernel-process" in name_lower:
        image = data.get("ImageName") or data.get("ImageFileName")
        command_line = data.get("CommandLine")
        if event_id in (1, 3) or (image and event_id not in (2, 4, 6)):
            if event_id in (2, 4, 6):
                return EtwEvent(0.0, "process", "exit", "etw:process", pid=pid, tid=tid, ppid=ppid, image=image)
            target = image
            args = {"command_line": command_line} if command_line else {}
            return EtwEvent(0.0, "process", "create", "etw:process", pid=pid, tid=tid, ppid=ppid, image=image, target=target, args=args)
        if event_id in (3, 5):
            image = data.get("ImageName") or data.get("FileName")
            if image:
                return EtwEvent(0.0, "image", "load", "etw:image", pid=pid, tid=tid, target=image)
        return None

    if guid in KERNEL_FILE_GUIDS or "kernel-file" in name_lower:
        path = data.get("FileName") or data.get("FilePath")
        if not path:
            return None
        action = {12: "create", 13: "write", 14: "delete", 15: "rename"}.get(event_id, "create")
        return EtwEvent(0.0, "file", action, "etw:file", pid=pid, tid=tid, target=path, args={"etw_event_id": event_id})

    if guid in KERNEL_REGISTRY_GUIDS or "kernel-registry" in name_lower:
        key_path = data.get("KeyName") or data.get("KeyPath")
        if not key_path:
            return None
        return EtwEvent(0.0, "registry", "set", "etw:registry", pid=pid, tid=tid, target=key_path, args={"etw_event_id": event_id})

    if guid in KERNEL_NETWORK_GUIDS or guid in TCPIP_GUIDS or "kernel-network" in name_lower or "tcpip" in name_lower:
        remote = data.get("RemoteAddress") or data.get("daddr") or data.get("DestinationAddress")
        port = _int(data.get("RemotePort") or data.get("dport"))
        if not remote:
            return None
        target = f"{remote}:{port}" if port else remote
        return EtwEvent(0.0, "network", "connect", "etw:network", pid=pid, tid=tid, target=target, args={"remote_port": port} if port else {})

    if guid in DNS_CLIENT_GUIDS or "dns-client" in name_lower:
        query = data.get("QueryName") or data.get("Name")
        if not query:
            return None
        return EtwEvent(0.0, "network", "dns", "etw:dns", pid=pid, tid=tid, target=query)

    return None


def _int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def parse_events_xml(
    source: str | Path,
    *,
    t0: datetime | None = None,
    limit: int = 50000,
) -> tuple[list[EtwEvent], dict[str, Any]]:
    """解析 tracerpt 导出的 XML；返回 (事件, 元信息)。解析失败抛 EtwUnavailable。"""
    meta: dict[str, Any] = {"total": 0, "mapped": 0, "unmapped": 0, "by_category": {}}
    try:
        if isinstance(source, Path) or (isinstance(source, str) and "<" not in source):
            tree = ET.parse(str(source))
            root = tree.getroot()
        else:
            root = ET.fromstring(source)
    except (ET.ParseError, OSError) as exc:
        raise EtwUnavailable(f"tracerpt XML 解析失败: {exc}") from exc

    raw: list[tuple[datetime, EtwEvent]] = []
    base_time = t0
    for element in _iter_events(root):
        meta["total"] += 1
        fields = _system_field(element)
        data = _event_data(element)
        moment = _parse_time(fields.get("time_SystemTime", ""))
        if moment is None:
            meta["unmapped"] += 1
            continue
        if base_time is None:
            base_time = moment
        mapped = classify_event(fields, data)
        if mapped is None:
            meta["unmapped"] += 1
            continue
        delta = (moment - base_time).total_seconds()
        mapped.ts = round(max(0.0, delta), 6)
        raw.append((moment, mapped))
        meta["mapped"] += 1
        meta["by_category"][mapped.category] = meta["by_category"].get(mapped.category, 0) + 1
        if meta["mapped"] >= max(1, int(limit)):
            break

    raw.sort(key=lambda item: item[0])
    events: list[EtwEvent] = []
    last_ts = 0.0
    for _, event in raw:
        event.ts = max(event.ts, last_ts)
        last_ts = event.ts
        events.append(event)
    return events, meta


class EtwSession:
    """一次 wpr 采集会话；调用方必须 try/except 并降级。"""

    def __init__(self, workdir: str | Path, *, timeout_s: float = 30.0) -> None:
        self.workdir = Path(workdir)
        self.timeout_s = max(1.0, float(timeout_s))
        self.etl_path = self.workdir / "etw.etl"
        self.xml_path = self.workdir / "etw.xml"
        self.started = False

    def start(self) -> None:
        ok, reason = available()
        if not ok:
            raise EtwUnavailable(reason)
        self.workdir.mkdir(parents=True, exist_ok=True)
        try:
            completed = subprocess.run(
                [WPR, "-start", "GeneralProfile", "-filemode"],
                capture_output=True,
                text=True, errors="replace",
                timeout=self.timeout_s,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise EtwUnavailable(f"wpr -start 失败: {exc}") from exc
        if completed.returncode != 0:
            raise EtwUnavailable(f"wpr -start 失败: {((completed.stdout or '') + (completed.stderr or '')).strip()[:200]}")
        self.started = True

    def stop(self, *, t0: datetime | None = None) -> tuple[list[EtwEvent], dict[str, Any]]:
        if not self.started:
            raise EtwUnavailable("ETW 会话未启动")
        try:
            completed = subprocess.run(
                [WPR, "-stop", str(self.etl_path)],
                capture_output=True,
                text=True, errors="replace",
                timeout=max(60.0, self.timeout_s),
            )
            if completed.returncode != 0 or not self.etl_path.exists():
                raise EtwUnavailable(
                    "wpr -stop 失败: " + ((completed.stdout or "") + (completed.stderr or "")).strip()[:200]
                )
            completed = subprocess.run(
                [TRACERPT, str(self.etl_path), "-of", "XML", "-o", str(self.xml_path), "-y"],
                capture_output=True,
                text=True, errors="replace",
                timeout=300.0,
            )
            if completed.returncode != 0 or not self.xml_path.exists():
                raise EtwUnavailable(
                    "tracerpt 失败: " + ((completed.stdout or "") + (completed.stderr or "")).strip()[:200]
                )
            events, meta = parse_events_xml(self.xml_path, t0=t0, limit=50000)
            self.started = False
            return events, meta
        finally:
            self._cleanup_files()

    def abort(self) -> None:
        if not self.started:
            return
        try:
            subprocess.run(
                [WPR, "-stop", str(self.etl_path)],
                capture_output=True,
                text=True, errors="replace",
                timeout=120.0,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        self.started = False
        self._cleanup_files()

    def _cleanup_files(self) -> None:
        for path in (self.etl_path, self.xml_path):
            try:
                if path and path.exists():
                    path.unlink()
            except OSError:
                pass
