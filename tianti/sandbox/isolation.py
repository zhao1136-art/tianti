"""隔离能力（ctypes）：受限令牌 + 低完整性 + 按程序防火墙阻断 + 创建挂起进程。

安全语义：
- 网络默认 blocked；防火墙规则添加/校验失败 -> 抛 SandboxError（fail-closed，不跑样本）。
- 令牌 = CreateRestrictedToken(DISABLE_MAX_PRIVILEGES) + SetTokenInformation(TokenIntegrityLevel)
  = SECURITY_MANDATORY_LOW_RID（S-1-16-4096），并在 sandbox.isolation 中如实声明
  restricted_token / integrity:low。
- 低完整性语义：**写入受限**（含 C:\\Windows 等中/高完整性位置），**读/执行不受限**；
  因此工作目录必须显式打低完整性标签，样本才能在其中落盘（containment 负责）。
- 受限令牌创建失败允许降级：优先保留低完整性（DuplicateTokenEx 路径），
  两者都失败才回退普通令牌，并把实际缺失项写入 missing/details。
- 执行结束 finally 中必须删除防火墙规则、关闭令牌句柄（由 containment 调用 cleanup）。
"""

from __future__ import annotations

import ctypes
import os
import subprocess
from ctypes import wintypes as wt
from dataclasses import dataclass, field
from typing import Any

from ..core.errors import SandboxError

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

MAXIMUM_ALLOWED = 0x02000000
DISABLE_MAX_PRIVILEGES = 0x00000001
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
ERROR_ACCESS_DENIED = 5
INFINITE = 0xFFFFFFFF

shell32.IsUserAnAdmin.argtypes = []
shell32.IsUserAnAdmin.restype = wt.BOOL
k32.GetCurrentProcess.argtypes = []
k32.GetCurrentProcess.restype = wt.HANDLE
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.CloseHandle.restype = wt.BOOL
adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
adv.OpenProcessToken.restype = wt.BOOL
adv.CreateRestrictedToken.argtypes = [
    wt.HANDLE,
    wt.DWORD,
    wt.DWORD,
    ctypes.c_void_p,
    wt.DWORD,
    ctypes.c_void_p,
    wt.DWORD,
    ctypes.c_void_p,
    ctypes.POINTER(wt.HANDLE),
]
adv.CreateRestrictedToken.restype = wt.BOOL

# 低完整性（Mandatory Integrity Control）：写入受限，读/执行不受限
TOKEN_INTEGRITY_LEVEL = 25
TOKEN_PRIMARY = 1
SECURITY_IMPERSONATION = 2
SE_GROUP_INTEGRITY = 0x00000020
SECURITY_MANDATORY_LOW_RID = "S-1-16-4096"

adv.ConvertStringSidToSidW.argtypes = [wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
adv.ConvertStringSidToSidW.restype = wt.BOOL
adv.GetLengthSid.argtypes = [ctypes.c_void_p]
adv.GetLengthSid.restype = wt.DWORD
adv.SetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
adv.SetTokenInformation.restype = wt.BOOL
adv.DuplicateTokenEx.argtypes = [
    wt.HANDLE,
    wt.DWORD,
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(wt.HANDLE),
]
adv.DuplicateTokenEx.restype = wt.BOOL
k32.LocalFree.argtypes = [ctypes.c_void_p]
k32.LocalFree.restype = ctypes.c_void_p


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("lpReserved", wt.LPWSTR),
        ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR),
        ("dwX", wt.DWORD),
        ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD),
        ("dwYSize", wt.DWORD),
        ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD),
        ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD),
        ("wShowWindow", wt.WORD),
        ("cbReserved2", wt.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wt.HANDLE),
        ("hStdOutput", wt.HANDLE),
        ("hStdError", wt.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
    ]


adv.CreateProcessAsUserW.argtypes = [
    wt.HANDLE,
    wt.LPCWSTR,
    wt.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wt.BOOL,
    wt.DWORD,
    ctypes.c_void_p,
    wt.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
adv.CreateProcessAsUserW.restype = wt.BOOL
k32.CreateProcessW.argtypes = [
    wt.LPCWSTR,
    wt.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wt.BOOL,
    wt.DWORD,
    ctypes.c_void_p,
    wt.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
k32.CreateProcessW.restype = wt.BOOL
k32.ResumeThread.argtypes = [wt.HANDLE]
k32.ResumeThread.restype = wt.DWORD


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def _handle_value(handle: Any) -> int:
    if handle is None:
        return 0
    value = getattr(handle, "value", handle)
    return int(value or 0)


@dataclass
class LaunchResult:
    pid: int
    process_handle: int
    thread_handle: int
    restricted_token: bool
    command_line: str
    low_integrity: bool = False


def _create_restricted_token() -> tuple[int | None, str]:
    """返回 (token 句柄, 说明)。失败返回 (None, 原因)，允许调用方降级。"""
    original = wt.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), MAXIMUM_ALLOWED, ctypes.byref(original)):
        return None, f"OpenProcessToken 失败 (winerror={ctypes.get_last_error()})"
    try:
        restricted = wt.HANDLE()
        ok = adv.CreateRestrictedToken(
            original,
            DISABLE_MAX_PRIVILEGES,
            0,
            None,
            0,
            None,
            0,
            None,
            ctypes.byref(restricted),
        )
        if not ok:
            return None, f"CreateRestrictedToken(DISABLE_MAX_PRIVILEGES) 失败 (winerror={ctypes.get_last_error()})"
        handle = _handle_value(restricted)
        if not handle:
            return None, "CreateRestrictedToken 返回空句柄"
        return handle, "CreateRestrictedToken(DISABLE_MAX_PRIVILEGES) ok"
    finally:
        k32.CloseHandle(original)


def _set_low_integrity(token_handle: int) -> tuple[bool, str]:
    """SetTokenInformation(TokenIntegrityLevel) -> SECURITY_MANDATORY_LOW_RID。

    低完整性只限制“向上写入”（含系统目录），不限制读/执行；工作目录需要显式
    打低完整性标签后样本才能落盘（见 containment._set_tree_low_integrity）。
    """
    sid = ctypes.c_void_p()
    if not adv.ConvertStringSidToSidW(SECURITY_MANDATORY_LOW_RID, ctypes.byref(sid)):
        return False, f"ConvertStringSidToSidW({SECURITY_MANDATORY_LOW_RID}) 失败 (winerror={ctypes.get_last_error()})"
    try:
        sid_length = int(adv.GetLengthSid(sid))
        struct_size = ctypes.sizeof(TOKEN_MANDATORY_LABEL)
        buffer = ctypes.create_string_buffer(struct_size + sid_length)
        label = TOKEN_MANDATORY_LABEL.from_buffer(buffer)
        ctypes.memmove(ctypes.byref(buffer, struct_size), sid, sid_length)
        label.Label.Attributes = SE_GROUP_INTEGRITY
        label.Label.Sid = ctypes.cast(ctypes.byref(buffer, struct_size), ctypes.c_void_p)
        if not adv.SetTokenInformation(
            token_handle,
            TOKEN_INTEGRITY_LEVEL,
            buffer,
            struct_size + sid_length,
        ):
            return False, f"SetTokenInformation(TokenIntegrityLevel=LOW) 失败 (winerror={ctypes.get_last_error()})"
        return True, "TokenIntegrityLevel=SECURITY_MANDATORY_LOW_RID (S-1-16-4096)"
    finally:
        if sid:
            k32.LocalFree(sid)


def _create_low_integrity_token() -> tuple[int | None, str]:
    """降级路径：复制当前主令牌并设为低完整性（不含 restricting SIDs）。"""
    original = wt.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), MAXIMUM_ALLOWED, ctypes.byref(original)):
        return None, f"OpenProcessToken 失败 (winerror={ctypes.get_last_error()})"
    try:
        duplicate = wt.HANDLE()
        if not adv.DuplicateTokenEx(
            original,
            MAXIMUM_ALLOWED,
            None,
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            ctypes.byref(duplicate),
        ):
            return None, f"DuplicateTokenEx 失败 (winerror={ctypes.get_last_error()})"
        handle = _handle_value(duplicate)
        ok, detail = _set_low_integrity(handle)
        if not ok:
            k32.CloseHandle(duplicate)
            return None, detail
        return handle, detail
    finally:
        k32.CloseHandle(original)


def _netsh(*args: str, timeout_s: float = 30.0) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            ["netsh", *args],
            capture_output=True,
            text=True, errors="replace",
            timeout=timeout_s,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    return completed.returncode, ((completed.stdout or "") + (completed.stderr or "")).strip()


class Isolation:
    """一次沙箱执行对应的隔离上下文（令牌 + 防火墙规则）。"""

    def __init__(
        self,
        *,
        trace_id: str,
        network: str = "blocked",
        use_firewall: bool = True,
    ) -> None:
        self.trace_id = trace_id
        self.network = str(network or "blocked")
        self.use_firewall = bool(use_firewall)
        self.items: list[str] = []
        self.missing: list[str] = []
        self.details: dict[str, str] = {}
        self.rules: list[str] = []
        self._token: int | None = None
        self._low_integrity = False
        self._prepared = False
        self._program_path = ""

    # -- 准备 ---------------------------------------------------------
    def prepare(self, program_path: str) -> dict[str, Any]:
        self._program_path = str(program_path)
        restricted_token, restricted_detail = _create_restricted_token()
        self.details["restricted_token"] = restricted_detail
        if restricted_token:
            low_ok, low_detail = _set_low_integrity(restricted_token)
            if low_ok:
                self._token = restricted_token
                self._low_integrity = True
                self.items.extend(["restricted_token", "integrity:low"])
                self.details["integrity"] = low_detail
            else:
                # 受限令牌无法设低完整性 -> 回退“仅低完整性”令牌，仍保留写入限制
                fallback, fallback_detail = _create_low_integrity_token()
                k32.CloseHandle(restricted_token)
                if fallback:
                    self._token = fallback
                    self._low_integrity = True
                    self.items.append("integrity:low")
                    self.missing.append("restricted_token")
                    self.details["restricted_token"] = f"{restricted_detail}；{low_detail}"
                    self.details["integrity"] = fallback_detail
                else:
                    self.missing.extend(["restricted_token", "integrity:low"])
                    self.details["restricted_token"] = f"{restricted_detail}；{low_detail}"
                    self.details["integrity"] = fallback_detail
        else:
            fallback, fallback_detail = _create_low_integrity_token()
            if fallback:
                self._token = fallback
                self._low_integrity = True
                self.items.append("integrity:low")
                self.missing.append("restricted_token")
                self.details["integrity"] = fallback_detail
            else:
                self.missing.extend(["restricted_token", "integrity:low"])
                self.details["integrity"] = fallback_detail

        if self.network.lower() == "blocked":
            if not self.use_firewall:
                raise SandboxError(
                    "network=blocked 但防火墙阻断被禁用：fail-closed，中止执行",
                    reason="firewall_disabled",
                )
            self._install_firewall_rules()
        else:
            self.details["firewall"] = f"network={self.network}，未启用阻断（非默认策略）"
        self._prepared = True
        return self.report()

    def report(self) -> dict[str, Any]:
        return {
            "items": list(self.items),
            "missing": list(self.missing),
            "details": dict(self.details),
            "rules": list(self.rules),
        }

    def _rule_name(self, direction: str) -> str:
        return f"tianti-{self.trace_id}-{direction}"

    def _install_firewall_rules(self) -> None:
        if not is_admin():
            raise SandboxError(
                "需要管理员权限才能添加防火墙阻断规则（fail-closed，不执行样本）",
                reason="not_admin",
            )
        program = self._program_path
        for direction in ("out", "in"):
            name = self._rule_name(direction)
            rc, output = _netsh(
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={name}",
                f"dir={direction}",
                f"program={program}",
                "action=block",
                "enable=yes",
                "profile=any",
            )
            if rc != 0:
                self._delete_rules()
                raise SandboxError(
                    f"防火墙阻断规则添加失败（fail-closed，不执行样本）: dir={direction}: {output[:200]}",
                    reason="firewall_add_failed",
                )
            self.rules.append(name)
        for name in self.rules:
            rc, output = _netsh("advfirewall", "firewall", "show", "rule", f"name={name}")
            if rc != 0:
                self._delete_rules()
                raise SandboxError(
                    f"防火墙规则校验失败（fail-closed，不执行样本）: {name}: {output[:200]}",
                    reason="firewall_verify_failed",
                )
        self.items.extend(["fw_block_out", "fw_block_in"])
        self.details["firewall"] = f"按程序阻断 {program} 的 in/out 流量（netsh advfirewall，已校验）"

    def _delete_rules(self) -> list[str]:
        errors: list[str] = []
        for name in list(self.rules):
            rc, output = _netsh("advfirewall", "firewall", "delete", "rule", f"name={name}")
            if rc == 0:
                self.rules.remove(name)
            else:
                errors.append(f"{name}: rc={rc} {output[:120]}")
        self.details["firewall_cleanup_errors"] = "; ".join(errors) if errors else "ok"
        return errors

    # -- 启动进程 -----------------------------------------------------
    def launch(self, command_line: str, cwd: str) -> LaunchResult:
        if not self._prepared:
            raise SandboxError("Isolation.prepare() 必须先于 launch() 调用")
        flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_BREAKAWAY_FROM_JOB
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        si.dwFlags = 0x00000001  # STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE

        restricted = self._token is not None
        last_error = 0
        ok = False
        pi = PROCESS_INFORMATION()
        for attempt_breakaway in (True, False):
            buf = ctypes.create_unicode_buffer(command_line)
            pi = PROCESS_INFORMATION()
            current_flags = flags if attempt_breakaway else (flags & ~CREATE_BREAKAWAY_FROM_JOB)
            if restricted:
                ok = bool(
                    adv.CreateProcessAsUserW(
                        self._token,
                        None,
                        buf,
                        None,
                        None,
                        False,
                        current_flags,
                        None,
                        cwd,
                        ctypes.byref(si),
                        ctypes.byref(pi),
                    )
                )
            else:
                ok = bool(
                    k32.CreateProcessW(
                        None,
                        buf,
                        None,
                        None,
                        False,
                        current_flags,
                        None,
                        cwd,
                        ctypes.byref(si),
                        ctypes.byref(pi),
                    )
                )
            if ok:
                break
            last_error = ctypes.get_last_error()
            if last_error != ERROR_ACCESS_DENIED:
                break

        if not ok and restricted:
            # 受限令牌启动失败：降级为普通令牌（记录 missing），但不放弃执行
            detail = f"CreateProcessAsUserW 失败 (winerror={last_error})，降级普通令牌"
            self.details["restricted_token"] = detail
            if "restricted_token" in self.items:
                self.items.remove("restricted_token")
            if "restricted_token" not in self.missing:
                self.missing.append("restricted_token")
            restricted = False
            for attempt_breakaway in (True, False):
                buf = ctypes.create_unicode_buffer(command_line)
                pi = PROCESS_INFORMATION()
                current_flags = flags if attempt_breakaway else (flags & ~CREATE_BREAKAWAY_FROM_JOB)
                ok = bool(
                    k32.CreateProcessW(
                        None,
                        buf,
                        None,
                        None,
                        False,
                        current_flags,
                        None,
                        cwd,
                        ctypes.byref(si),
                        ctypes.byref(pi),
                    )
                )
                if ok:
                    break
                last_error = ctypes.get_last_error()
                if last_error != ERROR_ACCESS_DENIED:
                    break

        if not ok:
            raise SandboxError(
                f"CreateProcess 失败 (winerror={last_error}): {command_line}",
                reason="create_process_failed",
                command_line=command_line,
            )
        return LaunchResult(
            pid=int(pi.dwProcessId),
            process_handle=_handle_value(pi.hProcess),
            thread_handle=_handle_value(pi.hThread),
            restricted_token=restricted,
            command_line=command_line,
            low_integrity=self._low_integrity,
        )

    # -- 清理 ---------------------------------------------------------
    def cleanup(self) -> dict[str, Any]:
        rules_before = list(self.rules)
        errors = self._delete_rules()
        removed = [name for name in rules_before if name not in self.rules]
        if self._token:
            k32.CloseHandle(self._token)
            self._token = None
        return {"rules_removed": removed, "errors": errors}
