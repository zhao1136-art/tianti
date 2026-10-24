"""脚本静态特征：PowerShell / VBS / JS / Batch（不执行脚本）。"""

from __future__ import annotations

import re
from typing import Any

from .util import decode_text, merge_signals, signal

MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_BASE64_BLOBS = 20

_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")

# (language or "any", signal_id, severity, detail, regex)
_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    # ---- PowerShell ----
    ("powershell", "script.encoded_command", "high", "PowerShell 编码命令（-enc/-EncodedCommand）",
     r"(?i)(?:^|[\s\"'])-\s*(?:enc|encodedcommand)\b"),
    ("powershell", "script.execution_policy_bypass", "medium", "执行策略绕过（-ExecutionPolicy Bypass）",
     r"(?i)-executionpolicy\s+(?:bypass|unrestricted)|\b-ep\s+bypass\b"),
    ("powershell", "script.download_string", "high", "远程下载字符串/文件（DownloadString/DownloadFile）",
     r"(?i)downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|start-bitstransfer|net\.webclient"),
    ("powershell", "script.dynamic_execution", "medium", "动态执行（IEX/Invoke-Expression）",
     r"(?i)\b(?:iex|invoke-expression)\b"),
    ("powershell", "script.hidden_window", "medium", "隐藏窗口执行（-WindowStyle Hidden / -w hidden）",
     r"(?i)-windowstyle\s+hidden|-w\s+hidden|createnowindow"),
    ("powershell", "script.amsi_bypass", "high", "AMSI 绕过痕迹（AmsiUtils/amsiInitFailed）",
     r"(?i)amsiutils|amsiinitfailed|amsi\s*bypass"),
    ("powershell", "script.defender_tamper", "high", "关闭/篡改 Defender（Set-MpPreference/DisableRealtimeMonitoring）",
     r"(?i)set-mppreference|add-mppreference|disablerealtimemonitoring|disable-windowsdefender"),
    ("powershell", "script.reflection", "medium", "反射加载程序集（[Reflection.Assembly]::Load / Add-Type）",
     r"(?i)\[reflection\.assembly\]::load|\badd-type\b"),
    ("powershell", "script.vss_delete", "critical", "删除卷影/禁用恢复（vssadmin/wbadmin/bcdedit）",
     r"(?i)vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit\s+/set|win32_shadowcopy"),
    ("powershell", "script.scheduled_task", "high", "计划任务持久化（schtasks/Register-ScheduledTask）",
     r"(?i)schtasks|register-scheduledtask|new-scheduledtask"),
    ("powershell", "script.persistence", "high", "注册表 Run 键持久化",
     r"(?i)currentversion\\run|new-itemproperty[^\n]{0,80}run|set-itemproperty[^\n]{0,80}run"),
    ("powershell", "script.uac_bypass", "high", "UAC 绕过链（fodhelper/eventvwr/computerdefaults/runas）",
     r"(?i)fodhelper|eventvwr|computerdefaults|start-process[^\n]{0,80}-verb\s+runas"),
    ("powershell", "script.credential_access", "critical", "凭据窃取痕迹（Mimikatz/lsass/sekurlsa）",
     r"(?i)mimikatz|invoke-mimikatz|sekurlsa|lsass|dumpcreds|comsvcs\.dll"),
    ("powershell", "script.network", "high", "原始网络通信（TcpClient/Net.Sockets/WebClient）",
     r"(?i)tcpclient|net\.sockets|new-object\s+net\.webclient|httpclient"),
    ("powershell", "script.log_clear", "high", "清除日志（wevtutil cl / Clear-EventLog）",
     r"(?i)wevtutil\s+cl|clear-eventlog|remove-eventlog"),
    ("powershell", "script.lolbin", "medium", "系统工具滥用（mshta/rundll32/regsvr32/certutil）",
     r"(?i)\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild)\b"),
    ("powershell", "script.security_software", "high", "安全软件/防护探测（Defender/AMSI/防火墙查询）",
     r"(?i)get-mppreference|netsh\s+advfirewall|sc\s+(?:stop|config)\s+windefend"),
    ("powershell", "script.sandbox_evasion", "low", "沙箱/分析环境探测",
     r"(?i)vmware|virtualbox|vboxservice|sandboxie|cuckoo|wireshark|process\s*hacker|procmon"),
    ("powershell", "script.sleep", "low", "长时间休眠（沙箱规避）",
     r"(?i)start-sleep\s+(?:-[a-z]+\s+)?(?:[6-9]\d|\d{3,})|sleep\s+(?:[6-9]\d|\d{3,})"),
    ("powershell", "script.account_manip", "high", "账号操作（net user /add）",
     r"(?i)net\s+user\s+\S+\s+/add|net\s+localgroup\s+administrators"),

    # ---- VBScript ----
    ("vbscript", "script.shell_object", "medium", "WScript.Shell 对象",
     r"(?i)wscript\.shell|createobject\s*\(\s*[\"']wscript\.shell"),
    ("vbscript", "script.shell_exec", "medium", "Shell.Run/Exec 执行命令",
     r"(?i)\.(?:run|exec)\s*\("),
    ("vbscript", "script.network", "high", "XMLHTTP/WinHttp 网络请求",
     r"(?i)msxml2\.xmlhttp|microsoft\.xmlhttp|winhttp\.winhttprequest"),
    ("vbscript", "script.file_drop", "medium", "ADODB.Stream 写文件",
     r"(?i)adodb\.stream|scripting\.filesystemobject"),
    ("vbscript", "script.autoexec", "high", "文档自动执行宏入口（AutoOpen/Document_Open）",
     r"(?i)autoopen|document_open|workbook_open"),

    # ---- JavaScript ----
    ("javascript", "script.activex", "medium", "ActiveXObject 调用",
     r"(?i)activexobject"),
    ("javascript", "script.dynamic_execution", "medium", "动态执行（eval/Function）",
     r"(?i)\beval\s*\(|new\s+function\s*\("),
    ("javascript", "script.obfuscation", "medium", "JS 混淆特征（unescape/fromCharCode）",
     r"(?i)\bunescape\s*\(|string\.fromcharcode"),
    ("javascript", "script.network", "high", "网络请求（XMLHTTP/fetch）",
     r"(?i)xmlhttp|fetch\s*\(|new\s+activexobject\s*\(\s*[\"']msxml2"),
    ("javascript", "script.shell_object", "medium", "WScript.Shell 对象",
     r"(?i)wscript\.shell|wscript\.createobject"),

    # ---- Batch ----
    ("batch", "script.encoded_command", "high", "批处理调用 PowerShell 编码命令",
     r"(?i)powershell(?:\.exe)?[^\n]{0,80}-(?:enc|encodedcommand)\b"),
    ("batch", "script.certutil_decode", "high", "certutil 解码/下载（-decode / -urlcache）",
     r"(?i)certutil(?:\.exe)?[^\n]{0,80}-(?:decode|urlcache)"),
    ("batch", "script.download", "high", "bitsadmin/certutil 下载",
     r"(?i)bitsadmin(?:\.exe)?[^\n]{0,80}/transfer"),
    ("batch", "script.vss_delete", "critical", "删除卷影/禁用恢复（vssadmin/wbadmin/bcdedit）",
     r"(?i)vssadmin(?:\.exe)?\s+delete|wbadmin(?:\.exe)?\s+delete|bcdedit(?:\.exe)?\s+/set"),
    ("batch", "script.scheduled_task", "high", "计划任务（schtasks /create）",
     r"(?i)schtasks(?:\.exe)?[^\n]{0,60}/create|\bat\s+\d{1,2}:\d{2}"),
    ("batch", "script.persistence", "high", "注册表 Run 键持久化",
     r"(?i)reg(?:\.exe)?\s+add[^\n]{0,120}\\run\b"),
    ("batch", "script.service_persistence", "high", "安装/修改服务（sc create/config）",
     r"(?i)\bsc(?:\.exe)?\s+(?:create|config)\s+"),
    ("batch", "script.log_clear", "high", "清除日志（wevtutil cl / del *.evtx）",
     r"(?i)wevtutil(?:\.exe)?\s+cl|del[^\n]{0,60}\.evtx"),
    ("batch", "script.account_manip", "high", "账号操作（net user /add）",
     r"(?i)net\s+user\s+\S+\s+/add|net\s+localgroup\s+administrators\s+\S+\s+/add"),
    ("batch", "script.destructive", "medium", "批量删除/格式化（del /f /q、rd /s /q、format）",
     r"(?i)\bdel\s+/[fqs]|\brd\s+/s\s+/q|\bformat\s+[a-z]:"),
    ("batch", "script.recon", "low", "主机发现命令（whoami/systeminfo/net user/tasklist）",
     r"(?i)\b(?:whoami|systeminfo|tasklist|ipconfig|net\s+user|net\s+view|wmic)\b"),

    # ---- 通用 ----
    ("any", "script.lolbin", "medium", "系统工具滥用（mshta/rundll32/regsvr32/certutil）",
     r"(?i)\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild)\b"),
    ("any", "script.persistence", "medium", "持久化关键词",
     r"(?i)currentversion\\run|register-scheduledtask|schtasks\s+/create"),
    ("any", "script.staging_path", "low", "临时目录暂存",
     r"(?i)%temp%|\$env:temp|appdata\\local\\temp"),
)


def _detect_language(name: str, sample_type: str, text: str) -> str:
    suffix = ""
    if "." in name:
        suffix = name.rsplit(".", 1)[-1].lower()
    if "powershell" in sample_type or suffix in ("ps1", "psm1", "psd1"):
        return "powershell"
    if "vbs" in sample_type or suffix in ("vbs", "vbe"):
        return "vbscript"
    if "script/js" in sample_type or suffix in ("js", "jse"):
        return "javascript"
    if "batch" in sample_type or suffix in ("bat", "cmd"):
        return "batch"
    low = text.lower()
    if "powershell" in low or "invoke-" in low:
        return "powershell"
    if "createobject" in low and "wscript" in low:
        return "vbscript"
    if "function" in low and ("var " in low or "activexobject" in low):
        return "javascript"
    if low.startswith("@echo") or "goto " in low or "set /a" in low:
        return "batch"
    return "unknown"


def _obfuscation_score(text: str) -> int:
    low = text.lower()
    indicators = 0
    if low.count(chr(96)) >= 3:
        indicators += 1
    if "[char[]]" in low or "char[]" in low:
        indicators += 1
    if "-join" in low:
        indicators += 1
    if "frombase64string" in low:
        indicators += 1
    if low.count("\\x") >= 8:
        indicators += 1
    if "string.fromcharcode" in low:
        indicators += 1
    longest = max((len(line) for line in text.splitlines()), default=0)
    if longest > 1000:
        indicators += 1
    return indicators


def analyze_script(data: bytes | str, *, name: str = "", sample_type: str = "") -> dict[str, Any]:
    """分析脚本内容（字节或文本），返回语言、编码与 signals。绝不执行。"""
    truncated = False
    if isinstance(data, str):
        text, encoding, size = data, "text", len(data.encode("utf-8", errors="replace"))
    else:
        raw = bytes(data)
        if len(raw) > MAX_SCRIPT_BYTES:
            raw = raw[:MAX_SCRIPT_BYTES]
            truncated = True
        size = len(raw)
        text, encoding = decode_text(raw)

    language = _detect_language(name, sample_type, text)
    signals: list[dict[str, str]] = []
    matched_rules: set[str] = set()
    for rule_language, signal_id, severity, detail, pattern in _RULES:
        if rule_language != "any" and rule_language != language:
            continue
        if signal_id in matched_rules:
            continue
        if re.search(pattern, text):
            signals.append(signal(signal_id, severity, detail))
            matched_rules.add(signal_id)

    blob_count = len(_BASE64_BLOB_RE.findall(text))
    if blob_count:
        signals.append(signal("script.base64_blob", "medium", f"脚本含 {blob_count} 段长 Base64 块"))
    if "script.encoded_command" in matched_rules and blob_count:
        signals.append(signal("script.encoded_command_blob", "high", "编码命令参数后跟长 Base64 载荷"))
    if {"script.dynamic_execution", "script.download_string"} <= matched_rules:
        signals.append(signal("script.download_cradle", "critical", "IEX + 远程下载组合（典型下载执行链）"))

    obfuscation = _obfuscation_score(text)
    if obfuscation >= 2:
        signals.append(signal("script.obfuscation", "medium", f"混淆特征 {obfuscation} 项（反引号/-join/Base64/超长行等）"))

    if language == "batch" and re.search(r"(?i)powershell(?:\.exe)?[^\n]{0,80}-(?:enc|e)\b", text):
        signals.append(signal("script.encoded_command", "high", "批处理调用 PowerShell 编码命令"))

    signals = merge_signals(signals)
    return {
        "language": language,
        "encoding": encoding,
        "size": size,
        "line_count": text.count("\n") + 1 if text else 0,
        "truncated": truncated,
        "base64_blobs": min(blob_count, MAX_BASE64_BLOBS),
        "signals": signals,
    }
