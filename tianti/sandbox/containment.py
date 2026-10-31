"""ContainmentBackend（L1 主后端）：受限执行 + 限时 + 观测 -> Trace。

流程：
  work/<trace_id>/c/ 工作目录 -> 复制样本 -> 受限令牌 + 防火墙按程序阻断
  -> Job Object（内存/CPU/进程数/KILL_ON_JOB_CLOSE）-> 创建挂起进程
  -> AssignProcessToJobObject -> ResumeThread -> 轮询观测（进程树/连接表）
  -> 超时/退出 -> 强杀进程树 -> 文件与注册表快照 diff -> 汇总 Trace

隔离选型（M3 定稿）：受限令牌（DISABLE_MAX_PRIVILEGES）+ 低完整性
（Integrity Level = SECURITY_MANDATORY_LOW_RID，S-1-16-4096）+ Job Object +
按程序防火墙阻断。不采用 AppContainer：已验证方案实现风险最低。
低完整性语义：写入受限（含 C:\\Windows 等中/高完整性位置），读/执行不受限；
工作目录会显式打低完整性标签（icacls /setintegritylevel），样本才能在其中落盘。

防挂死/防残留（M3 硬化）：
- 主等待有 deadline（watchdog.wait_process），超时必杀树；
- 独立守护线程 _HardKillTimer 在 timeout_s+grace 后无条件杀进程树 + TerminateJobObject，
  防止主线程卡在任意 syscall 时残留进程；
- AssignProcessToJobObject 失败即杀树并 fail-closed，不允许进程在 Job 外执行；
- finally 中 TerminateJobObject + kill_tree 双保险，并校验根进程已死。

DLL 动态执行（M3+）：
- .dll 后缀或 IMAGE_FILE_DLL 特征的 PE：解析导出表取第一个函数名导出，用
  rundll32.exe "<copy>",<export> 启动；无函数名导出（或 rundll32 不可用）回退
  regsvr32.exe /s "<copy>"；两者都不可用则 SandboxUnavailable（fail-closed）。
- trace.extra.dll_loader = {launcher, export, export_count, note}。
- 已知限制：按程序防火墙绑定的是启动器（rundll32.exe / regsvr32.exe），不是 DLL 本身。

观测主路径：快照 diff + 进程树/连接表轮询（source=snapshot:/poll:）；
ETW 默认关闭（实测开销超预算，见 telemetry_etw.py），可显式开启，失败优雅降级。
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import threading
import time
from ctypes import wintypes as wt
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .. import __version__
from ..core.config import Config
from ..core.errors import SampleError, SandboxError, SandboxUnavailable
from ..core.model import Sample, SampleType
from ..trace.normalize import EventBuilder, build_trace
from ..trace.schema import Event, SandboxInfo, new_trace_id
from . import isolation, netmon, snapshot, telemetry_etw, watchdog
from .base import BaseSandboxBackend, SandboxPolicy

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
MB = 1024 * 1024
ACTIVE_PROCESS_LIMIT = 16
IMAGE_FILE_DLL = 0x2000
DLL_SAMPLE_LIMIT_BYTES = 64 * MB  # 超过则不解析导出，直接回退 regsvr32


class _LARGE_INTEGER(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", _LARGE_INTEGER),
        ("PerJobUserTimeLimit", _LARGE_INTEGER),
        ("LimitFlags", wt.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wt.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wt.DWORD),
        ("SchedulingClass", wt.DWORD),
    ]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
    _fields_ = [
        ("NumberOfAssignedProcesses", wt.DWORD),
        ("NumberOfProcessIdsInList", wt.DWORD),
        ("ProcessIdList", ctypes.c_size_t * 1),
    ]


k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wt.LPCWSTR]
k32.CreateJobObjectW.restype = wt.HANDLE
k32.SetInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
k32.SetInformationJobObject.restype = wt.BOOL
k32.AssignProcessToJobObject.argtypes = [wt.HANDLE, wt.HANDLE]
k32.AssignProcessToJobObject.restype = wt.BOOL
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.CloseHandle.restype = wt.BOOL
k32.QueryInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
k32.QueryInformationJobObject.restype = wt.BOOL
k32.TerminateJobObject.argtypes = [wt.HANDLE, wt.UINT]
k32.TerminateJobObject.restype = wt.BOOL
k32.ResumeThread.argtypes = [wt.HANDLE]
k32.ResumeThread.restype = wt.DWORD


def _iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class _JobObject:
    """Job Object 限额 + KILL_ON_JOB_CLOSE；创建/配置/分配失败均降级而非致命。"""

    def __init__(self) -> None:
        self.handle = k32.CreateJobObjectW(None, None)
        self.limits: list[str] = []
        self.configured = False
        self.error: str | None = None
        if not self.handle:
            self.error = f"CreateJobObjectW 失败 (winerror={ctypes.get_last_error()})"

    def configure(self, policy: SandboxPolicy) -> bool:
        if not self.handle:
            return False
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        self.limits = ["kill_on_job_close"]
        if policy.cpu_s > 0:
            flags |= JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_JOB_TIME
            ticks = int(policy.cpu_s * 10_000_000)
            info.BasicLimitInformation.PerProcessUserTimeLimit.LowPart = ticks & 0xFFFFFFFF
            info.BasicLimitInformation.PerProcessUserTimeLimit.HighPart = ticks >> 32
            info.BasicLimitInformation.PerJobUserTimeLimit.LowPart = ticks & 0xFFFFFFFF
            info.BasicLimitInformation.PerJobUserTimeLimit.HighPart = ticks >> 32
            self.limits.extend(["cpu_limit", "job_cpu_limit"])
        if policy.mem_mb > 0:
            flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY
            info.ProcessMemoryLimit = int(policy.mem_mb) * MB
            info.JobMemoryLimit = int(policy.mem_mb) * MB
            self.limits.extend(["mem_limit", "job_mem_limit"])
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        info.BasicLimitInformation.ActiveProcessLimit = ACTIVE_PROCESS_LIMIT
        self.limits.append("process_limit")
        info.BasicLimitInformation.LimitFlags = flags
        if not k32.SetInformationJobObject(
            self.handle,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            self.error = f"SetInformationJobObject 失败 (winerror={ctypes.get_last_error()})"
            return False
        self.configured = True
        return True

    def assign(self, process_handle: int) -> tuple[bool, str]:
        if not self.handle or not process_handle:
            return False, "Job/进程句柄无效"
        if not k32.AssignProcessToJobObject(self.handle, process_handle):
            return False, f"AssignProcessToJobObject 失败 (winerror={ctypes.get_last_error()})"
        return True, "ok"

    def pids(self) -> set[int]:
        if not self.handle:
            return set()
        capacity = 4096
        header_size = ctypes.sizeof(_JOBOBJECT_BASIC_PROCESS_ID_LIST)
        buffer = ctypes.create_string_buffer(header_size + capacity * ctypes.sizeof(ctypes.c_size_t))
        returned = wt.DWORD(0)
        if not k32.QueryInformationJobObject(
            self.handle,
            JOB_OBJECT_BASIC_PROCESS_ID_LIST,
            buffer,
            len(buffer),
            ctypes.byref(returned),
        ):
            return set()
        header = ctypes.cast(buffer, ctypes.POINTER(_JOBOBJECT_BASIC_PROCESS_ID_LIST)).contents
        count = int(header.NumberOfProcessIdsInList)
        count = max(0, min(count, capacity))
        if count == 0:
            return set()
        array = (ctypes.c_size_t * count).from_buffer(buffer, ctypes.sizeof(wt.DWORD) * 2)
        return {int(pid) for pid in array if pid}

    def terminate(self, exit_code: int = 1) -> bool:
        """同步终止 Job 内全部进程（防残留的第二道保险）。"""
        if not self.handle:
            return False
        return bool(k32.TerminateJobObject(self.handle, int(exit_code)))

    def close(self) -> None:
        if self.handle:
            k32.CloseHandle(self.handle)
            self.handle = 0


class _ProcessTracker:
    """轮询进程树：Job 内进程 + root 后代；产出 process create/exit（root 由调用方记录）。"""

    def __init__(
        self,
        builder: EventBuilder,
        root_pid: int,
        job: _JobObject | None,
        *,
        known: set[int] | None = None,
    ) -> None:
        self.builder = builder
        self.root_pid = root_pid
        self.job = job
        self.tracked: dict[int, watchdog.ProcessEntry] = {}
        self.exited: set[int] = set()
        self._known = set(known or set())
        self._known.add(root_pid)
        self.polls = 0

    def pids(self) -> set[int]:
        procs = watchdog.list_processes()
        found: set[int] = set()
        if self.root_pid in procs:
            found.add(self.root_pid)
        found.update(watchdog.descendants(self.root_pid, procs))
        if self.job is not None:
            found.update(self.job.pids())
        return found

    def poll(self, procs: dict[int, watchdog.ProcessEntry] | None = None) -> None:
        self.polls += 1
        table = procs if procs is not None else watchdog.list_processes()
        current: set[int] = set()
        if self.root_pid in table:
            current.add(self.root_pid)
        current.update(watchdog.descendants(self.root_pid, table))
        if self.job is not None:
            current.update(self.job.pids())
        for pid in sorted(current):
            if pid in self.tracked or pid in self._known:
                self.tracked.setdefault(pid, table.get(pid) or watchdog.ProcessEntry(pid, 0, ""))
                continue
            entry = table.get(pid) or watchdog.ProcessEntry(pid, 0, "")
            self.tracked[pid] = entry
            self.builder.emit(
                "process",
                "create",
                pid=pid,
                ppid=entry.ppid or None,
                target=entry.name or None,
                args={"discovered": "job" if self.job is not None else "poll"},
                source="poll:process",
                confidence="medium",
            )
        for pid, entry in list(self.tracked.items()):
            if pid == self.root_pid or pid in self.exited:
                continue
            if pid not in table:
                self.exited.add(pid)
                self.builder.emit(
                    "process",
                    "exit",
                    pid=pid,
                    target=entry.name or None,
                    args={"discovered": "poll"},
                    source="poll:process",
                    confidence="medium",
                )

    def survivors(self) -> list[watchdog.ProcessEntry]:
        table = watchdog.list_processes()
        return [entry for pid, entry in self.tracked.items() if pid in table]


def _powershell_path() -> str:
    candidate = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if candidate.is_file():
        return str(candidate)
    found = shutil.which("powershell")
    if found:
        return found
    raise SandboxUnavailable("找不到 powershell.exe，无法执行 PowerShell 模拟样本")


def _cmd_path() -> str:
    candidate = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
    if candidate.is_file():
        return str(candidate)
    return os.environ.get("ComSpec", "cmd.exe")


@dataclass(frozen=True)
class _LaunchSpec:
    """实际启动方式：程序路径 + 命令行 + DLL 加载器信息（非 DLL 为 None）。"""

    program: str
    command_line: str
    dll_loader: dict[str, Any] | None = None


def _system32_tool(name: str) -> str | None:
    candidate = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / name
    if candidate.is_file():
        return str(candidate)
    return shutil.which(name)


def _pe_is_dll(path: Path) -> bool:
    """只读文件头判断 IMAGE_FILE_DLL 特征（用于无 .dll 后缀的 DLL 样本）。"""
    try:
        with path.open("rb") as handle:
            head = handle.read(256 * 1024)
    except OSError:
        return False
    try:
        if len(head) < 0x40 or head[:2] != b"MZ":
            return False
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if e_lfanew <= 0 or e_lfanew + 24 > len(head):
            return False
        if head[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return False
        characteristics = int.from_bytes(head[e_lfanew + 4 + 18 : e_lfanew + 4 + 20], "little")
        return bool(characteristics & IMAGE_FILE_DLL)
    except (ValueError, IndexError):
        return False


def _read_sample_bytes(path: Path) -> tuple[bytes, str]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return b"", f"stat 失败: {exc}"
    if size <= 0:
        return b"", "空文件"
    if size > DLL_SAMPLE_LIMIT_BYTES:
        return b"", f"文件过大（{size} 字节），跳过导出解析"
    try:
        return path.read_bytes(), "ok"
    except OSError as exc:
        return b"", f"读取失败: {exc}"


def _minimal_pe_exports(data: bytes) -> tuple[bool, list[str]]:
    """内置最小 PE 导出表解析（static.pe 不可用/异常时的兜底），绝不抛异常。"""
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False, []
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if e_lfanew <= 0 or e_lfanew + 24 > len(data):
            return False, []
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return False, []
        coff = e_lfanew + 4
        num_sections = int.from_bytes(data[coff + 2 : coff + 4], "little")
        size_optional = int.from_bytes(data[coff + 16 : coff + 18], "little")
        characteristics = int.from_bytes(data[coff + 18 : coff + 20], "little")
        is_dll = bool(characteristics & IMAGE_FILE_DLL)
        optional = coff + 20
        if size_optional < 96 or optional + size_optional > len(data):
            return is_dll, []
        magic = int.from_bytes(data[optional : optional + 2], "little")
        if magic not in (0x10B, 0x20B):
            return is_dll, []
        is_plus = magic == 0x20B
        dirs_count = int.from_bytes(data[optional + (108 if is_plus else 92) : optional + (112 if is_plus else 96)], "little")
        dirs_offset = optional + (112 if is_plus else 96)
        if dirs_count < 1 or dirs_offset + 8 > len(data):
            return is_dll, []
        export_rva = int.from_bytes(data[dirs_offset : dirs_offset + 4], "little")
        if not export_rva:
            return is_dll, []
        section_table = optional + size_optional

        def rva_to_offset(rva: int) -> int:
            for index in range(min(num_sections, 96)):
                base = section_table + index * 40
                if base + 40 > len(data):
                    return 0
                virtual_size = int.from_bytes(data[base + 8 : base + 12], "little")
                virtual_addr = int.from_bytes(data[base + 12 : base + 16], "little")
                raw_size = int.from_bytes(data[base + 16 : base + 20], "little")
                pointer_raw = int.from_bytes(data[base + 20 : base + 24], "little")
                span = max(virtual_size, raw_size)
                if virtual_addr <= rva < virtual_addr + span:
                    delta = rva - virtual_addr
                    if delta < raw_size and pointer_raw + delta < len(data):
                        return pointer_raw + delta
                    return 0
            return 0

        export_offset = rva_to_offset(export_rva)
        if not export_offset or export_offset + 40 > len(data):
            return is_dll, []
        num_names = int.from_bytes(data[export_offset + 24 : export_offset + 28], "little")
        names_rva = int.from_bytes(data[export_offset + 32 : export_offset + 36], "little")
        names_offset = rva_to_offset(names_rva)
        if not names_offset:
            return is_dll, []
        exports: list[str] = []
        for index in range(min(num_names, 512)):
            entry = names_offset + index * 4
            if entry + 4 > len(data):
                break
            name_offset = rva_to_offset(int.from_bytes(data[entry : entry + 4], "little"))
            if not name_offset or name_offset >= len(data):
                continue
            end = data.find(b"\x00", name_offset, min(len(data), name_offset + 256))
            if end < 0:
                continue
            name = data[name_offset:end].decode("ascii", "replace")
            if name:
                exports.append(name)
            if len(exports) >= 64:
                break
        return is_dll, exports
    except (ValueError, IndexError):
        return False, []


def _named_dll_exports(path: Path) -> tuple[list[str], str]:
    """解析 DLL 的名字导出表（优先 lazy import tianti.static.pe，失败回退最小解析）。

    返回 (导出名列表, 解析来源说明)。列表顺序即 PE 导出名表顺序，调用方取第一个。
    """
    data, note = _read_sample_bytes(path)
    if not data:
        return [], note
    try:
        from ..static import pe as static_pe  # lazy：避免 L1 常态依赖静态层
    except Exception as exc:  # noqa: BLE001 - 静态层不可用必须降级
        static_pe = None
        static_error = f"static.pe 不可用: {exc}"
    else:
        static_error = ""
    if static_pe is not None:
        try:
            info = static_pe.parse_pe(data)
            if info.valid or info.is_dll:
                return [str(name) for name in (info.exports or [])], "static.pe"
            static_error = info.error or "static.pe 判定 PE 无效"
        except Exception as exc:  # noqa: BLE001
            static_error = f"static.pe 解析异常: {exc}"
    _is_dll, exports = _minimal_pe_exports(data)
    return exports, f"内置最小解析（{static_error}）"


def _build_dll_command(sample_copy: Path) -> _LaunchSpec:
    """DLL 动态执行：rundll32 优先，regsvr32 兜底，均不可用则 fail-closed。"""
    rundll32 = _system32_tool("rundll32.exe")
    regsvr32 = _system32_tool("regsvr32.exe")
    exports, parse_note = _named_dll_exports(sample_copy)
    firewall_note = "按程序防火墙绑定启动器 exe，不绑定 DLL 文件"
    if exports and rundll32:
        export = exports[0]
        return _LaunchSpec(
            str(rundll32),
            f'"{rundll32}" "{sample_copy}",{export}',
            {
                "launcher": "rundll32",
                "export": export,
                "export_count": int(len(exports)),
                "note": f"取第一个函数名导出（{parse_note}）；{firewall_note}",
            },
        )
    if regsvr32:
        reason = "无函数名导出" if not exports else "rundll32.exe 不可用"
        return _LaunchSpec(
            str(regsvr32),
            f'"{regsvr32}" /s "{sample_copy}"',
            {
                "launcher": "regsvr32",
                "export": None,
                "export_count": int(len(exports)),
                "note": f"{reason}，回退 regsvr32 /s（{parse_note}）；{firewall_note}",
            },
        )
    raise SandboxUnavailable(
        f"DLL 无法动态执行：rundll32.exe/regsvr32.exe 均不可用（导出解析: {parse_note}）",
        sample=str(sample_copy),
        export_count=len(exports),
    )


def _build_command(sample: Sample, sample_copy: Path) -> _LaunchSpec:
    """返回实际启动方式。DLL 走 rundll32/regsvr32，其余按脚本/PE 直启。"""
    suffix = sample_copy.suffix.lower()
    sample_type = sample.type
    if suffix == ".dll" or (
        sample_type in (SampleType.PE32, SampleType.PE64) and _pe_is_dll(sample_copy)
    ):
        return _build_dll_command(sample_copy)
    if sample_type in (SampleType.PE32, SampleType.PE64):
        return _LaunchSpec(str(sample_copy), f'"{sample_copy}"')
    if sample_type is SampleType.SCRIPT_POWERSHELL or suffix in (".ps1", ".psm1"):
        powershell = _powershell_path()
        command = (
            f'"{powershell}" -NoProfile -NonInteractive -ExecutionPolicy Bypass '
            f'-WindowStyle Hidden -File "{sample_copy}"'
        )
        return _LaunchSpec(powershell, command)
    if sample_type is SampleType.SCRIPT_BATCH or suffix in (".bat", ".cmd"):
        cmd = _cmd_path()
        return _LaunchSpec(cmd, f'"{cmd}" /c "{sample_copy}"')
    if sample_type is SampleType.SCRIPT_JS or suffix == ".js":
        cscript = _system32_tool("cscript.exe") or "cscript.exe"
        return _LaunchSpec(cscript, f'"{cscript}" //nologo //B "{sample_copy}"')
    if sample_type is SampleType.SCRIPT_VBS or suffix == ".vbs":
        cscript = _system32_tool("cscript.exe") or "cscript.exe"
        return _LaunchSpec(cscript, f'"{cscript}" //nologo //B "{sample_copy}"')
    raise SandboxUnavailable(
        f"containment 不执行该样本类型: {sample_type.value}（仅支持 PE / DLL / PowerShell / BAT / JS / VBS）",
        sample_type=sample_type.value,
    )


def _set_tree_low_integrity(path: Path, *, recursive: bool = True) -> tuple[bool, str]:
    """给工作目录/样本打低完整性标签（icacls /setintegritylevel），失败返回原因。

    低完整性进程只能向低完整性位置写入；若不标记工作目录，样本将无法落盘
    （读/执行仍然允许）。这是 integrity:low 生效的必要配套步骤。
    """
    icacls = shutil.which("icacls")
    if not icacls:
        return False, "icacls.exe 不可用"
    args = [icacls, str(path), "/setintegritylevel", "(OI)(CI)L" if recursive else "L"]
    try:
        completed = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"icacls 失败: {exc}"
    if completed.returncode != 0:
        detail = ((completed.stdout or "") + (completed.stderr or "")).strip()[:200]
        return False, f"icacls rc={completed.returncode}: {detail}"
    return True, "low"


class _HardKillTimer:
    """独立守护线程：到 deadline 后无条件杀树 + 终止 Job，防止主线程卡死导致残留。"""

    def __init__(self, root_pid: int, job: _JobObject | None, *, deadline_s: float) -> None:
        self.root_pid = int(root_pid)
        self.job = job
        self.deadline_s = max(0.5, float(deadline_s))
        self.fired = False
        self.killed: list[int] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="tianti-hardkill", daemon=True)

    def _run(self) -> None:
        if self._stop.wait(self.deadline_s):
            return
        self.fired = True
        try:
            if self.job is not None:
                self.job.terminate()
        except Exception:  # noqa: BLE001 - 兜底清理绝不抛
            pass
        try:
            self.killed = watchdog.kill_tree(self.root_pid)
        except Exception:  # noqa: BLE001
            pass

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1.5)


class ContainmentBackend(BaseSandboxBackend):
    """本机可用的真实隔离执行后端（不是虚拟机隔离，边界见 docs/THREAT_MODEL.md）。"""

    name = "containment"

    def __init__(
        self,
        *,
        use_etw: bool | None = None,
        cleanup_workdir: bool = True,
        keep_workdir: bool = False,
    ) -> None:
        self.use_etw = bool(use_etw)
        self.cleanup_workdir = bool(cleanup_workdir)
        self.keep_workdir = bool(keep_workdir)

    # -- 可用性 -------------------------------------------------------
    def available(self) -> tuple[bool, str]:
        if os.name != "nt":
            return False, "containment 仅支持 Windows"
        if not isolation.is_admin():
            return False, "需要管理员权限（防火墙阻断 fail-closed）；当前不是管理员"
        if not shutil.which("netsh"):
            return False, "netsh 不可用，无法启用网络阻断（fail-closed）"
        if not shutil.which("icacls"):
            return False, "icacls 不可用，无法为工作目录设置低完整性标签"
        return True, (
            "containment：受限令牌 + 低完整性(integrity:low) + Job Object + "
            "防火墙按程序阻断 + 快照/连接表观测 + DLL(rundll32/regsvr32)"
        )

    # -- 主流程 -------------------------------------------------------
    def run(
        self,
        sample: Sample,
        policy: SandboxPolicy,
        *,
        on_event: Callable[[Event], None] | None = None,
    ) -> Trace:
        if os.name != "nt":
            raise SandboxUnavailable("containment 仅支持 Windows", backend="containment")
        available, reason = self.available()
        if not available:
            raise SandboxUnavailable(reason, backend="containment")
        if not sample.path or not Path(sample.path).is_file():
            raise SampleError(f"样本路径不可执行或不存在: {sample.path}", path=str(sample.path))
        if str(policy.network).lower() == "blocked" and not isolation.is_admin():
            raise SandboxError("network=blocked 且无管理员权限：fail-closed，不执行样本")

        trace_id = new_trace_id()
        t_begin = time.perf_counter()
        timings: dict[str, float] = {}

        def _mark(name: str) -> None:
            timings[name] = round(time.perf_counter() - t_begin, 3)

        work_root = Path(policy.workdir_root).resolve() if policy.workdir_root else Config.default().paths.work
        work = work_root / trace_id / "c"
        work.mkdir(parents=True, exist_ok=True)
        # 放在 work 内部，确保 snapshot_tree(work) 能看到样本写出的临时文件
        temp_dir = work / "_tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        source = Path(sample.path).resolve()
        sample_copy = work / source.name
        shutil.copy2(source, sample_copy)
        _mark("workspace")

        builder = EventBuilder(max_events=policy.max_events, source="poll:process", on_event=on_event)
        notes: list[str] = []
        extra: dict[str, Any] = {}
        iso = isolation.Isolation(trace_id=trace_id, network=policy.network, use_firewall=True)
        net = netmon.NetMonitor()
        job: _JobObject | None = None
        launch: isolation.LaunchResult | None = None
        etw_session: telemetry_etw.EtwSession | None = None
        started_at = _iso_now()
        terminated_by = "error"
        exit_code: int | None = None
        killed: list[int] = []
        tracker: _ProcessTracker | None = None
        launch_utc: datetime | None = None
        fatal: BaseException | None = None
        before_files: dict[str, snapshot.FileState] = {}
        after_files: dict[str, snapshot.FileState] = {}
        before_reg: dict[str, dict[str, str]] = {}
        after_reg: dict[str, dict[str, str]] = {}
        reg_errors: list[str] = []
        reg_cleanup_errors: list[str] = []
        rolled_back: list[str] = []
        workdir_integrity: dict[str, Any] | None = None
        hard_kill: _HardKillTimer | None = None
        root_pid = 0

        program = ""
        command_line = ""
        launch_spec: _LaunchSpec | None = None
        try:
            launch_spec = _build_command(sample, sample_copy)
            program = launch_spec.program
            command_line = launch_spec.command_line
            iso.prepare(program)  # 防火墙失败 -> SandboxError（fail-closed）
            if "integrity:low" in iso.items:
                # 低完整性进程只能写低完整性位置：必须给工作目录 + 样本打标签
                dir_ok, dir_detail = _set_tree_low_integrity(work)
                if not dir_ok:
                    raise SandboxError(
                        f"工作目录低完整性标记失败（fail-closed，不执行样本）: {dir_detail}",
                        reason="workdir_integrity_failed",
                    )
                file_ok, file_detail = _set_tree_low_integrity(sample_copy, recursive=False)
                temp_ok, temp_detail = _set_tree_low_integrity(temp_dir)
                workdir_integrity = {
                    "label": "low",
                    "dir": dir_detail,
                    "sample": file_detail if file_ok else f"failed: {file_detail}",
                    "temp": temp_detail if temp_ok else f"failed: {temp_detail}",
                }
                notes.append("低完整性（integrity:low）：写入受限（含系统目录），读/执行不受限")
            job = _JobObject()
            if job.handle and not job.configure(policy):
                notes.append(job.error or "Job Object 配置失败")
            if not job.handle:
                notes.append(job.error or "Job Object 创建失败")
            _mark("isolation")

            try:
                before_files = snapshot.snapshot_tree(work)
            except OSError as exc:
                notes.append(f"文件快照失败: {exc}")
            if policy.registry_snapshot:
                try:
                    before_reg, reg_errors = snapshot.export_registry(snapshot.DEFAULT_REG_SUBTREES)
                except Exception as exc:  # 注册表快照失败不致命
                    notes.append(f"注册表快照失败: {exc}")
            else:
                notes.append("注册表快照已按策略跳过（registry_snapshot=false，提升扫描速度）")
            _mark("snapshots_before")

            if self.use_etw:
                try:
                    etw_session = telemetry_etw.EtwSession(work_root / trace_id, timeout_s=30.0)
                    etw_session.start()
                except Exception as exc:
                    extra["etw"] = {"enabled": True, "ok": False, "error": str(exc)[:400]}
                    etw_session = None

            builder.start()
            # TEMP/TMP 重定向到 work/_tmp：样本写临时文件也会被快照观测到
            launch_env = {"TEMP": str(temp_dir), "TMP": str(temp_dir)}
            launch = iso.launch(command_line, cwd=str(work), env=launch_env)
            notes.append("TEMP/TMP 已重定向到 work/_tmp（样本写临时文件可被快照观测）")
            launch_utc = datetime.now(timezone.utc)
            root_pid = launch.pid
            if job is not None and job.handle:
                assigned, assign_reason = job.assign(launch.process_handle)
                if not assigned:
                    # 进程已在 Job 外：立即杀树并 fail-closed，绝不允许“无人看管”的执行
                    try:
                        watchdog.kill_tree(root_pid)
                    finally:
                        notes.append(f"{assign_reason}；已杀树并中止（fail-closed）")
                    raise SandboxError(
                        f"AssignProcessToJobObject 失败（fail-closed，已杀树中止）: {assign_reason}",
                        reason="job_assign_failed",
                    )
            if launch.thread_handle and not k32.ResumeThread(launch.thread_handle):
                notes.append(f"ResumeThread 失败 (winerror={ctypes.get_last_error()})")
            # 独立守护线程：主等待之外的最后一道超时保险
            hard_kill = _HardKillTimer(root_pid, job, deadline_s=float(policy.timeout_s) + 5.0)
            hard_kill.start()
            _mark("launch")

            root_entry = watchdog.list_processes().get(root_pid)
            root_name = root_entry.name if root_entry else Path(program).name
            builder.emit(
                "process",
                "create",
                pid=root_pid,
                ppid=os.getpid(),
                image=program,
                target=program,
                args={
                    "command_line": command_line,
                    "restricted_token": launch.restricted_token,
                    "job_object": bool(job and job.handle),
                    "workdir": str(work),
                },
                source="poll:process",
                confidence="high",
            )
            tracker = _ProcessTracker(builder, root_pid, job, known={root_pid})

            def on_tick(elapsed: float) -> None:
                tracker.poll()  # type: ignore[union-attr]
                for conn in net.poll(tracker.pids()):  # type: ignore[union-attr]
                    builder.emit(
                        "network",
                        "connect",
                        pid=conn.pid,
                        target=conn.target,
                        args=conn.to_args(),
                        source="poll:network",
                        confidence="medium",
                    )

            result = watchdog.wait_process(launch.process_handle, policy.timeout_s, poll_s=0.2, on_tick=on_tick)
            terminated_by = "timeout" if result.reason == "timeout" else "exited"
            exit_code = result.exit_code
            _mark("execute")

            # 收尾前的最后一次连接表采样（短命外联尽量抓到）
            for conn in net.poll(tracker.pids()):
                builder.emit(
                    "network",
                    "connect",
                    pid=conn.pid,
                    target=conn.target,
                    args=conn.to_args(),
                    source="poll:network",
                    confidence="medium",
                )
            # 无论正常退出还是超时，都强杀整棵进程树，保证不残留
            killed = watchdog.kill_tree(root_pid)
            tracker.poll()
            builder.emit(
                "process",
                "exit",
                pid=root_pid,
                image=program,
                target=program,
                args={"exit_code": exit_code, "terminated": terminated_by == "timeout"},
                source="poll:process",
                confidence="high",
            )
            _mark("terminate")
        except BaseException as exc:  # noqa: BLE001 - 所有异常都要先清理再抛出
            fatal = exc
        finally:
            # 0) 先停硬杀定时器，避免清理完成后再误杀
            if hard_kill is not None:
                try:
                    hard_kill.stop()
                except Exception:  # noqa: BLE001
                    pass
            # 1) 关 ETW（先停采集，避免写入已删除目录）
            if etw_session is not None:
                try:
                    etw_events, etw_meta = etw_session.stop(t0=launch_utc)
                    for item in etw_events:
                        builder.emit(
                            item.category,
                            item.action,
                            ts=item.ts,
                            pid=item.pid,
                            tid=item.tid,
                            ppid=item.ppid,
                            image=item.image,
                            target=item.target,
                            args=dict(item.args),
                            source=item.source,
                            confidence=item.confidence,
                        )
                    extra["etw"] = {"enabled": True, "ok": True, **etw_meta}
                except BaseException as exc:  # noqa: BLE001
                    extra["etw"] = {"enabled": True, "ok": False, "error": str(exc)[:400]}
                    try:
                        etw_session.abort()
                    except Exception:
                        pass
            else:
                if "etw" not in extra:
                    try:
                        etw_ok, etw_reason = telemetry_etw.available()
                    except Exception as exc:  # noqa: BLE001
                        etw_ok, etw_reason = False, str(exc)
                    extra["etw"] = {
                        "enabled": False,
                        "available": bool(etw_ok),
                        "reason": "默认关闭：实测 wpr GeneralProfile 单样本 stop+tracerpt 约 97s、XML 450MB，超预算；"
                        "可用 ContainmentBackend(use_etw=True) 显式开启",
                    }
                    if not etw_ok:
                        extra["etw"]["available_reason"] = etw_reason
            # 2) 确保进程树已终止（无论正常/超时/异常）
            root_pid = launch.pid if launch is not None else 0
            if root_pid:
                try:
                    killed = sorted(set(killed) | set(watchdog.kill_tree(root_pid)))
                except Exception as exc:  # noqa: BLE001
                    notes.append(f"进程树清理失败: {exc}")
            # 3) TerminateJobObject + 关闭句柄（KILL_ON_JOB_CLOSE 双保险）
            if job is not None:
                try:
                    job.terminate()
                except Exception:  # noqa: BLE001
                    pass
            if launch is not None:
                for handle in (launch.thread_handle, launch.process_handle):
                    if handle:
                        try:
                            k32.CloseHandle(handle)
                        except Exception:
                            pass
            if job is not None:
                job.close()
            # 3.1) 返回前确认根进程已死（不残留）
            if root_pid:
                deadline = time.monotonic() + 2.0
                while watchdog.is_alive(root_pid) and time.monotonic() < deadline:
                    watchdog.kill_pid(root_pid)
                    time.sleep(0.05)
                if watchdog.is_alive(root_pid):
                    notes.append(f"根进程 {root_pid} 在清理后仍存活（残留告警）")
                    try:
                        watchdog.kill_tree(root_pid)
                    except Exception:  # noqa: BLE001
                        pass
            # 4) 清理防火墙规则
            try:
                iso_cleanup = iso.cleanup()
            except Exception as exc:  # noqa: BLE001
                iso_cleanup = {"rules_removed": [], "errors": [str(exc)]}
                notes.append(f"防火墙清理失败: {exc}")
            extra["isolation_cleanup"] = iso_cleanup
            # 5) 文件/注册表快照 diff（只在执行过的情况下）
            if launch is not None:
                try:
                    after_files = snapshot.snapshot_tree(work)
                except OSError as exc:
                    notes.append(f"执行后文件快照失败: {exc}")
                if policy.registry_snapshot:
                    try:
                        after_reg, after_errors = snapshot.export_registry(snapshot.DEFAULT_REG_SUBTREES)
                        reg_errors.extend(after_errors)
                    except Exception as exc:  # noqa: BLE001
                        notes.append(f"执行后注册表快照失败: {exc}")
                _mark("cleanup")

        if fatal is not None:
            if self.cleanup_workdir and not self.keep_workdir:
                try:
                    shutil.rmtree(work_root / trace_id, ignore_errors=True)
                except OSError:
                    pass
            if isinstance(fatal, (SandboxError, SampleError, SandboxUnavailable)):
                raise fatal
            raise SandboxError(f"containment 执行异常: {fatal}", reason="containment_exception") from fatal

        timings["total"] = round(time.perf_counter() - t_begin, 3)
        extra["timings"] = timings

        # ------------------------------------------------------------------
        # 观测后处理：文件 diff / 注册表 diff / 事件落地 / Trace 汇总
        # ------------------------------------------------------------------
        try:
            changes = snapshot.diff_files(before_files, after_files, root=work)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"文件 diff 失败: {exc}")
            changes = []
        dropped_files: list[str] = []
        for change in changes:
            if change.change == "created":
                dropped_files.append(change.abs_path)
                builder.emit(
                    "file",
                    "create",
                    target=change.abs_path,
                    args={"size": change.size, "sha256": change.sha256, "entropy": change.entropy},
                    source="snapshot:file",
                    confidence="medium",
                )
                builder.emit(
                    "file",
                    "write",
                    target=change.abs_path,
                    args={"size": change.size, "sha256": change.sha256, "entropy": change.entropy},
                    source="snapshot:file",
                    confidence="medium",
                )
            elif change.change == "modified":
                builder.emit(
                    "file",
                    "write",
                    target=change.abs_path,
                    args={
                        "size": change.size,
                        "sha256": change.sha256,
                        "old_sha256": change.old_sha256,
                        "entropy": change.entropy,
                    },
                    source="snapshot:file",
                    confidence="medium",
                )
            else:
                builder.emit(
                    "file",
                    "delete",
                    target=change.abs_path,
                    args={"old_size": change.old_size, "old_sha256": change.old_sha256},
                    source="snapshot:file",
                    confidence="medium",
                )

        try:
            reg_changes = snapshot.diff_registry(before_reg, after_reg)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"注册表 diff 失败: {exc}")
            reg_changes = []
        for change in reg_changes:
            action = {"created": "create", "modified": "set", "deleted": "delete"}[change.change]
            args: dict[str, Any] = {"name": change.name, "raw": change.data}
            if change.old_data:
                args["previous"] = change.old_data
            builder.emit(
                "registry",
                action,
                target=change.target,
                args=args,
                source="snapshot:registry",
                confidence="medium",
            )
        if reg_changes:
            try:
                rolled_back, reg_cleanup_errors = snapshot.rollback_created_values(reg_changes)
            except Exception as exc:  # noqa: BLE001
                reg_cleanup_errors = [str(exc)]

        isolation_items = list(iso.items)
        if job is not None and job.configured:
            isolation_items.append("job_object")
            isolation_items.extend(job.limits)
        else:
            isolation_items.append("job_object_degraded")
        isolation_items.extend(["workdir_redirect", "timeout_watchdog", "process_tree_kill"])
        if launched_via_restricted_token(launch):
            if "restricted_token" not in isolation_items:
                isolation_items.append("restricted_token")
        elif "restricted_token" in isolation_items:
            isolation_items.remove("restricted_token")

        sandbox = SandboxInfo(
            host=platform.node(),
            isolation=isolation_items,
            limits=policy.limits(),
            started_at=started_at,
            ended_at=_iso_now(),
            terminated_by=terminated_by if launch is not None else "error",
        )
        extra.update(
            {
                "workdir": str(work),
                "env": {"TEMP": str(temp_dir), "TMP": str(temp_dir)},
                "workdir_cleaned": False,
                # 根进程启动信息：供 detect 区分 harness 包装命令行与样本自身行为
                "launch": {
                    "command_line": command_line,
                    "image": program,
                    "pid": int(root_pid),
                    "ppid": os.getpid(),
                    "restricted_token": bool(launch is not None and launch.restricted_token),
                    "integrity_low": bool(launch is not None and launch.low_integrity),
                },
                "dll_loader": launch_spec.dll_loader if launch_spec is not None else None,
                "isolation": iso.report(),
                "job_object": {
                    "ok": bool(job is not None and job.configured),
                    "limits": list(job.limits) if job is not None else [],
                    "error": job.error if job is not None else None,
                },
                "integrity": {
                    "low": "integrity:low" in iso.items,
                    "workdir": workdir_integrity,
                    "note": "低完整性：写入受限（含系统目录），读/执行不受限",
                },
                "hard_kill_watchdog": {
                    "fired": bool(hard_kill is not None and hard_kill.fired),
                    "killed": list(hard_kill.killed) if hard_kill is not None else [],
                },
                "snapshot": {
                    "files_before": len(before_files),
                    "files_after": len(after_files),
                    "file_changes": len(changes),
                    "registry_changes": len(reg_changes),
                    "registry_errors": reg_errors[:20],
                    "registry_rollback": {"rolled_back": rolled_back, "errors": reg_cleanup_errors[:20]},
                },
                "netmon": {"polls": net.polls, "unique_connections": net.seen_count},
                "processes": {
                    "tracked": len(tracker.tracked) if tracker is not None else 0,
                    "killed": killed,
                },
                "notes": notes,
            }
        )
        if etw_session is not None and "etw" not in extra:
            extra["etw"] = {"enabled": True, "ok": False, "error": "ETW 未产出结果"}

        if self.cleanup_workdir and not self.keep_workdir:
            try:
                shutil.rmtree(work_root / trace_id, ignore_errors=True)
                extra["workdir_cleaned"] = True
            except OSError as exc:
                notes.append(f"工作目录清理失败: {exc}")

        trace = build_trace(
            sample=sample,
            engine_version=__version__,
            backend="containment",
            policy=policy.name,
            sandbox=sandbox,
            builder=builder,
            extra=extra,
        )
        trace.summary.dropped_files = sorted(dropped_files)
        return trace


def launched_via_restricted_token(launch: isolation.LaunchResult | None) -> bool:
    return bool(launch is not None and launch.restricted_token)


BACKEND = ContainmentBackend()
