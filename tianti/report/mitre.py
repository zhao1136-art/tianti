"""ATT&CK 战术矩阵数据与渲染辅助。

只做“数据 + 映射”，不做 HTML 转义（转义由 report/html.py 负责）。
数据是 v1 常用子集，未知技术按 ID 原样展示。
"""

from __future__ import annotations

from typing import Any, Iterable

# 12 个战术（Enterprise），id 与名称保持稳定
TACTICS: list[dict[str, str]] = [
    {"id": "TA0001", "key": "initial-access", "name": "Initial Access", "name_zh": "初始访问"},
    {"id": "TA0002", "key": "execution", "name": "Execution", "name_zh": "执行"},
    {"id": "TA0003", "key": "persistence", "name": "Persistence", "name_zh": "持久化"},
    {"id": "TA0004", "key": "privilege-escalation", "name": "Privilege Escalation", "name_zh": "提权"},
    {"id": "TA0005", "key": "defense-evasion", "name": "Defense Evasion", "name_zh": "防御规避"},
    {"id": "TA0006", "key": "credential-access", "name": "Credential Access", "name_zh": "凭据访问"},
    {"id": "TA0007", "key": "discovery", "name": "Discovery", "name_zh": "发现"},
    {"id": "TA0008", "key": "lateral-movement", "name": "Lateral Movement", "name_zh": "横向移动"},
    {"id": "TA0009", "key": "collection", "name": "Collection", "name_zh": "收集"},
    {"id": "TA0010", "key": "exfiltration", "name": "Exfiltration", "name_zh": "数据外传"},
    {"id": "TA0011", "key": "command-and-control", "name": "Command and Control", "name_zh": "命令与控制"},
    {"id": "TA0040", "key": "impact", "name": "Impact", "name_zh": "影响"},
]

TACTIC_BY_ID: dict[str, dict[str, str]] = {item["id"]: item for item in TACTICS}
TACTIC_BY_KEY: dict[str, dict[str, str]] = {item["key"]: item for item in TACTICS}
TACTIC_BY_ZH: dict[str, dict[str, str]] = {item["name_zh"]: item for item in TACTICS}

# 常用技术 -> 战术 / 中文名（v1 报告展示子集，未知技术用 ID 展示）
_TECHNIQUE_ROWS: list[tuple[str, str, str, str]] = [
    ("T1547.001", "TA0003", "Registry Run Keys / Startup Folder", "注册表 Run 键 / 启动目录"),
    ("T1543.003", "TA0003", "Windows Service", "Windows 服务"),
    ("T1053.005", "TA0003", "Scheduled Task", "计划任务"),
    ("T1547.004", "TA0003", "Winlogon Helper DLL", "Winlogon 辅助 DLL"),
    ("T1546.003", "TA0003", "WMI Event Subscription", "WMI 事件订阅"),
    ("T1136.001", "TA0003", "Local Account", "本地账户"),
    ("T1053.002", "TA0003", "At", "At 任务"),
    ("T1543.002", "TA0003", "Systemd Service", "Systemd 服务"),
    ("T1003.001", "TA0006", "LSASS Memory", "LSASS 内存"),
    ("T1552.001", "TA0006", "Credentials in Files", "文件中的凭据"),
    ("T1552.002", "TA0006", "Credentials in Registry", "注册表中的凭据"),
    ("T1555.003", "TA0006", "Credentials from Web Browsers", "浏览器凭据"),
    ("T1134", "TA0004", "Access Token Manipulation", "访问令牌操作"),
    ("T1548.002", "TA0004", "Bypass User Account Control", "绕过 UAC"),
    ("T1055", "TA0005", "Process Injection", "进程注入"),
    ("T1055.002", "TA0005", "Portable Executable Injection", "PE 注入"),
    ("T1055.003", "TA0005", "Thread Execution Hijacking", "线程执行劫持"),
    ("T1055.012", "TA0005", "Process Hollowing", "进程镂空"),
    ("T1562.001", "TA0005", "Disable or Modify Tools", "禁用或修改安全工具"),
    ("T1562.004", "TA0005", "Disable or Modify System Firewall", "禁用或修改防火墙"),
    ("T1070.001", "TA0005", "Clear Windows Event Logs", "清除 Windows 事件日志"),
    ("T1070.004", "TA0005", "File Deletion", "文件删除"),
    ("T1490", "TA0040", "Inhibit System Recovery", "禁用系统恢复"),
    ("T1218", "TA0005", "System Binary Proxy Execution", "系统二进制代理执行"),
    ("T1218.011", "TA0005", "Rundll32", "Rundll32"),
    ("T1218.010", "TA0005", "Regsvr32", "Regsvr32"),
    ("T1218.005", "TA0005", "Mshta", "Mshta"),
    ("T1564", "TA0005", "Hide Artifacts", "隐藏痕迹"),
    ("T1564.003", "TA0005", "Hidden Window", "隐藏窗口"),
    ("T1036", "TA0005", "Masquerading", "伪装"),
    ("T1036.005", "TA0005", "Match Legitimate Name or Location", "伪装合法名称或路径"),
    ("T1497", "TA0005", "Virtualization / Sandbox Evasion", "虚拟化 / 沙箱规避"),
    ("T1112", "TA0005", "Modify Registry", "修改注册表"),
    ("T1027", "TA0005", "Obfuscated Files or Information", "混淆文件或信息"),
    ("T1140", "TA0005", "Deobfuscate / Decode Files or Information", "解码 / 去混淆"),
    ("T1105", "TA0011", "Ingress Tool Transfer", "工具传入"),
    ("T1059", "TA0002", "Command and Scripting Interpreter", "命令与脚本解释器"),
    ("T1059.001", "TA0002", "PowerShell", "PowerShell"),
    ("T1059.003", "TA0002", "Windows Command Shell", "Windows 命令 Shell"),
    ("T1059.005", "TA0002", "Visual Basic", "Visual Basic"),
    ("T1204", "TA0002", "User Execution", "用户执行"),
    ("T1047", "TA0002", "Windows Management Instrumentation", "WMI"),
    ("T1106", "TA0002", "Native API", "原生 API"),
    ("T1082", "TA0007", "System Information Discovery", "系统信息发现"),
    ("T1087", "TA0007", "Account Discovery", "账户发现"),
    ("T1018", "TA0007", "Remote System Discovery", "远程系统发现"),
    ("T1016", "TA0007", "System Network Configuration Discovery", "网络配置发现"),
    ("T1560", "TA0009", "Archive Collected Data", "归档收集数据"),
    ("T1560.001", "TA0009", "Archive via Utility", "使用工具归档"),
    ("T1071", "TA0011", "Application Layer Protocol", "应用层协议"),
    ("T1071.001", "TA0011", "Web Protocols", "Web 协议"),
    ("T1071.004", "TA0011", "DNS", "DNS"),
    ("T1095", "TA0011", "Non-Application Layer Protocol", "非应用层协议"),
    ("T1571", "TA0011", "Non-Standard Port", "非标准端口"),
    ("T1021.002", "TA0008", "SMB / Windows Admin Shares", "SMB / Windows 管理共享"),
    ("T1021.001", "TA0008", "Remote Desktop Protocol", "远程桌面协议"),
    ("T1041", "TA0010", "Exfiltration Over C2 Channel", "通过 C2 通道外传"),
    ("T1048", "TA0010", "Exfiltration Over Alternative Protocol", "通过其他协议外传"),
    ("T1486", "TA0040", "Data Encrypted for Impact", "为影响而加密数据"),
    ("T1485", "TA0040", "Data Destruction", "数据破坏"),
    ("T1489", "TA0040", "Service Stop", "停止服务"),
    ("T1531", "TA0040", "Account Access Removal", "删除账户访问"),
    ("T1222", "TA0005", "File and Directory Permissions Modification", "修改文件与目录权限"),
]
TECHNIQUE_TACTIC: dict[str, str] = {row[0]: row[1] for row in _TECHNIQUE_ROWS}
TECHNIQUE_NAME: dict[str, str] = {row[0]: row[2] for row in _TECHNIQUE_ROWS}
TECHNIQUE_NAME_ZH: dict[str, str] = {row[0]: row[3] for row in _TECHNIQUE_ROWS}

# 战术 -> 技术（仅矩阵展示用，保持稳定顺序）
TECHNIQUES_BY_TACTIC: dict[str, list[str]] = {item["id"]: [] for item in TACTICS}
for _tid, _tactic in TECHNIQUE_TACTIC.items():
    TECHNIQUES_BY_TACTIC.setdefault(_tactic, []).append(_tid)


def normalise_technique(technique: str) -> str:
    return str(technique).strip().upper()


def tactic_for_technique(technique: str, *, default: str | None = None) -> str | None:
    """技术 -> 战术；先查精确映射，再按主技术 ID（去子技术后缀）兜底。"""
    tid = normalise_technique(technique)
    if not tid:
        return default
    if tid in TECHNIQUE_TACTIC:
        return TECHNIQUE_TACTIC[tid]
    base = tid.split(".", 1)[0]
    if base in TECHNIQUE_TACTIC:
        return TECHNIQUE_TACTIC[base]
    return default


def technique_name(technique: str, *, zh: bool = True) -> str:
    tid = normalise_technique(technique)
    names = TECHNIQUE_NAME_ZH if zh else TECHNIQUE_NAME
    return names.get(tid) or names.get(tid.split(".", 1)[0]) or tid


def tactic_name(tactic: str, *, zh: bool = True) -> str:
    key = str(tactic).strip().upper()
    item = TACTIC_BY_ID.get(key) or TACTIC_BY_KEY.get(key.lower())
    if item is None:
        return str(tactic)
    return item["name_zh"] if zh else item["name"]


def _unique(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def build_matrix(
    tactics: Iterable[str] = (),
    techniques: Iterable[str] = (),
    *,
    technique_tactics: dict[str, str] | None = None,
) -> dict[str, Any]:
    """构建 ATT&CK 矩阵数据。

    返回 {"columns": [...], "unmapped": [...]}：
    - columns：12 个战术列；hit 表示该战术被命中；techniques 为该战术下被命中的技术。
    - unmapped：无法映射到战术的技术（仍会在报告中单独列出）。
    """
    explicit = {normalise_technique(k): str(v).upper() for k, v in (technique_tactics or {}).items()}
    tactic_hits = {str(t).strip().upper() for t in tactics if str(t).strip()}
    mapped: dict[str, list[str]] = {item["id"]: [] for item in TACTICS}
    unmapped: list[str] = []
    for tech in _unique(techniques):
        tid = normalise_technique(tech)
        tactic = explicit.get(tid) or tactic_for_technique(tid)
        if tactic in mapped:
            mapped[tactic].append(tid)
            tactic_hits.add(tactic)
        else:
            unmapped.append(tid)
    for tactic in tactic_hits:
        mapped.setdefault(tactic, [])
    columns: list[dict[str, Any]] = []
    for item in TACTICS:
        technique_ids = mapped.get(item["id"], [])
        columns.append(
            {
                "id": item["id"],
                "key": item["key"],
                "name": item["name"],
                "name_zh": item["name_zh"],
                "hit": item["id"] in tactic_hits,
                "count": len(technique_ids),
                "techniques": [
                    {"id": tid, "name": technique_name(tid), "name_en": technique_name(tid, zh=False)}
                    for tid in technique_ids
                ],
            }
        )
    return {"columns": columns, "unmapped": [{"id": tid, "name": technique_name(tid)} for tid in unmapped]}
