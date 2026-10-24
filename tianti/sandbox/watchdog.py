"""超时监控 + 进程树枚举/强杀（Toolhelp32 + TerminateProcess，ctypes 实现）。

设计目标：任何超时/异常都必须能杀掉整个进程树，不残留子进程。
Job Object 的 KILL_ON_JOB_CLOSE 是第二道保险（见 containment.py）。
"""

from __future__ import annotations

import ctypes
import time
from collections import defaultdict
from ctypes import wintypes as wt
from dataclasses import dataclass

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
STILL_ACTIVE = 259
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * MAX_PATH),
    ]


k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32FirstW.restype = wt.BOOL
k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.restype = wt.BOOL
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
k32.TerminateProcess.restype = wt.BOOL
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.CloseHandle.restype = wt.BOOL
k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
k32.WaitForSingleObject.restype = wt.DWORD
k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
k32.GetExitCodeProcess.restype = wt.BOOL


@dataclass(frozen=True)
class ProcessEntry:
    pid: int
    ppid: int
    name: str


@dataclass(frozen=True)
class WatchResult:
    reason: str  # exited / timeout
    exit_code: int | None
    elapsed_s: float


def list_processes() -> dict[int, ProcessEntry]:
    """枚举全系统进程（pid -> 条目）。失败返回空字典，绝不抛异常。"""
    snapshot = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == INVALID_HANDLE_VALUE:
        return {}
    result: dict[int, ProcessEntry] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            result[int(entry.th32ProcessID)] = ProcessEntry(
                pid=int(entry.th32ProcessID),
                ppid=int(entry.th32ParentProcessID),
                name=str(entry.szExeFile),
            )
            ok = k32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snapshot)
    return result


def children_map(procs: dict[int, ProcessEntry] | None = None) -> dict[int, list[int]]:
    table = procs if procs is not None else list_processes()
    mapping: dict[int, list[int]] = defaultdict(list)
    for entry in table.values():
        mapping[entry.ppid].append(entry.pid)
    return mapping


def descendants(root_pid: int, procs: dict[int, ProcessEntry] | None = None) -> list[int]:
    """返回 root 的全部后代 pid（不含 root），按 BFS 层级顺序。"""
    mapping = children_map(procs)
    found: list[int] = []
    queue = list(mapping.get(root_pid, []))
    seen: set[int] = set()
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        found.append(pid)
        queue.extend(mapping.get(pid, []))
    return found


def is_alive(pid: int) -> bool:
    return int(pid) in list_processes()


def _terminate(pid: int) -> bool:
    handle = k32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, int(pid))
    if not handle:
        return False
    try:
        return bool(k32.TerminateProcess(handle, 1))
    finally:
        k32.CloseHandle(handle)


def kill_pid(pid: int) -> bool:
    return _terminate(pid)


def kill_tree(root_pid: int, *, rounds: int = 6, pause_s: float = 0.05) -> list[int]:
    """从叶子往根强杀整棵进程树，多轮重试以覆盖杀进程期间新生的子进程。"""
    killed: set[int] = set()
    for _ in range(max(1, rounds)):
        procs = list_processes()
        if not procs:
            break
        # 收集根 + 后代；根已退出时仍按“曾记录的 ppid 链”找不到根，故用 root 起始 BFS 即可
        order = descendants(root_pid, procs)
        targets = list(reversed(order))
        if root_pid in procs:
            targets.append(root_pid)
        for pid in targets:
            if pid in procs and _terminate(pid):
                killed.add(pid)
        time.sleep(pause_s)
        remaining = [pid for pid in targets if pid in list_processes()]
        if not remaining:
            break
    return sorted(killed)


def wait_process(
    process_handle: int,
    timeout_s: float,
    *,
    poll_s: float = 0.2,
    on_tick=None,
) -> WatchResult:
    """等待进程退出或超时；每个 poll 周期回调 on_tick(elapsed_s)。"""
    started = time.monotonic()
    deadline = started + max(0.0, float(timeout_s))
    poll_s = max(0.05, float(poll_s))
    while True:
        now = time.monotonic()
        remaining = deadline - now
        if remaining <= 0:
            return WatchResult("timeout", None, now - started)
        wait_ms = max(1, int(min(poll_s, remaining) * 1000))
        code = k32.WaitForSingleObject(process_handle, wait_ms)
        if code == WAIT_OBJECT_0:
            exit_code = wt.DWORD()
            k32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code))
            return WatchResult("exited", int(exit_code.value), time.monotonic() - started)
        if on_tick is not None:
            try:
                on_tick(time.monotonic() - started)
            except Exception:  # 观测回调失败不能中断超时保障
                pass
