"""TCP 连接表轮询：GetExtendedTcpTable(ctypes) -> network connect 事件。

只观测、不拦截（拦截由 isolation.py 的防火墙规则负责）。
查询失败一律返回空列表，不抛异常，避免观测失败拖垮沙箱。
"""

from __future__ import annotations

import ctypes
import socket
import struct
from ctypes import wintypes as wt
from dataclasses import dataclass

iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
ERROR_INSUFFICIENT_BUFFER = 122
NO_ERROR = 0

STATE_NAMES = {
    1: "closed",
    2: "listen",
    3: "syn_sent",
    4: "syn_received",
    5: "established",
    6: "fin_wait1",
    7: "fin_wait2",
    8: "close_wait",
    9: "closing",
    10: "last_ack",
    11: "time_wait",
    12: "delete_tcb",
}


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wt.DWORD),
        ("dwLocalAddr", wt.DWORD),
        ("dwLocalPort", wt.DWORD),
        ("dwRemoteAddr", wt.DWORD),
        ("dwRemotePort", wt.DWORD),
        ("dwOwningPid", wt.DWORD),
    ]


iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wt.DWORD),
    wt.BOOL,
    wt.DWORD,
    wt.DWORD,
    wt.DWORD,
]
iphlpapi.GetExtendedTcpTable.restype = wt.DWORD


@dataclass(frozen=True)
class TcpConnection:
    pid: int
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str

    @property
    def target(self) -> str:
        return f"{self.remote_addr}:{self.remote_port}"

    def to_args(self) -> dict:
        return {
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "local_addr": self.local_addr,
            "local_port": self.local_port,
            "state": self.state,
            "pid": self.pid,
        }


def _addr(value: int) -> str:
    try:
        return socket.inet_ntoa(struct.pack("<L", int(value) & 0xFFFFFFFF))
    except OSError:
        return "0.0.0.0"


def _port(value: int) -> int:
    return int(socket.ntohs(int(value) & 0xFFFF))


def tcp_connections() -> list[TcpConnection]:
    """读取当前全部 TCP 连接（IPv4，含 owning pid）。失败返回 []。"""
    size = wt.DWORD(0)
    rc = iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if rc not in (NO_ERROR, ERROR_INSUFFICIENT_BUFFER) or size.value == 0:
        return []
    buffer = ctypes.create_string_buffer(size.value)
    rc = iphlpapi.GetExtendedTcpTable(buffer, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if rc != NO_ERROR:
        return []
    try:
        count = ctypes.cast(buffer, ctypes.POINTER(wt.DWORD)).contents.value
    except (ValueError, OSError):
        return []
    row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
    raw = buffer.raw
    rows: list[TcpConnection] = []
    for index in range(int(count)):
        offset = 4 + index * row_size
        if offset + row_size > len(raw):
            break
        row = MIB_TCPROW_OWNER_PID.from_buffer_copy(raw[offset : offset + row_size])
        rows.append(
            TcpConnection(
                pid=int(row.dwOwningPid),
                local_addr=_addr(row.dwLocalAddr),
                local_port=_port(row.dwLocalPort),
                remote_addr=_addr(row.dwRemoteAddr),
                remote_port=_port(row.dwRemotePort),
                state=STATE_NAMES.get(int(row.dwState), f"state_{int(row.dwState)}"),
            )
        )
    return rows


class NetMonitor:
    """轮询并去重样本进程树的 TCP 外联连接。"""

    def __init__(self) -> None:
        self._seen: set[tuple[int, str, int]] = set()
        self.polls = 0

    def poll(self, pids: set[int] | None = None, *, include_listen: bool = False) -> list[TcpConnection]:
        self.polls += 1
        tracked = {int(p) for p in (pids or set())}
        if not tracked:
            # 永远不能“没有 pid 就收集全系统连接”：空集合表示无可归属进程，直接返回
            return []
        fresh: list[TcpConnection] = []
        for conn in tcp_connections():
            if conn.pid not in tracked:
                continue
            if not include_listen and (conn.state == "listen" or conn.remote_port == 0):
                continue
            key = (conn.pid, conn.remote_addr, conn.remote_port)
            if key in self._seen:
                continue
            self._seen.add(key)
            fresh.append(conn)
        return fresh

    @property
    def seen_count(self) -> int:
        return len(self._seen)
