"""单文件 HTML 报告渲染器（内联 CSS，无任何外部资源，中文，双击可开）。

安全要求：所有动态内容（文件名、路径、命令行、备注、规则名等）必须经过
HTML 转义，样本文件名可能包含 <script> 等注入载荷。
"""

from __future__ import annotations

import html as _html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .. import __version__
from ..detect.base import SEVERITY_RANK
from ..rules.base import RuleMeta
from . import mitre
from .base import RESULT_SCHEMA, ScanResult

_TECHNIQUE_RE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
_CSS_TOKEN_RE = re.compile(r"[^a-z0-9_-]+")

_VERDICT_ZH = {"clean": "干净", "suspicious": "可疑", "malicious": "恶意"}
_SEVERITY_ZH = {"low": "低", "medium": "中", "high": "高", "critical": "严重"}
_KIND_ZH = {"capability": "能力", "detector": "检测器", "static": "静态", "behavior": "行为"}
_NS_ZH = {
    "initial-access": "初始访问",
    "execution": "执行",
    "persistence": "持久化",
    "privilege-escalation": "提权",
    "defense-evasion": "防御规避",
    "credential-access": "凭据访问",
    "discovery": "发现",
    "lateral-movement": "横向移动",
    "collection": "收集",
    "exfiltration": "数据外传",
    "command-and-control": "命令与控制",
    "impact": "影响",
    "capability": "能力",
    "anti-analysis": "反分析",
    "communication": "通信",
    "data-manipulation": "数据处理",
    "host-interaction": "主机交互",
}

_SUMMARY_FIELDS: list[tuple[str, str]] = [
    ("processes", "进程创建"),
    ("threads", "线程"),
    ("file_writes", "文件写入"),
    ("file_drops", "文件落地"),
    ("reg_sets", "注册表写入"),
    ("net_connects", "网络连接"),
    ("dns_queries", "DNS 查询"),
    ("services", "服务操作"),
    ("tasks", "计划任务"),
    ("apis", "API 调用"),
    ("event_count", "事件总数"),
]

_CSS = """
:root {
  --bg: #0b0f14; --panel: #121820; --panel2: #0f141b; --line: #24303d;
  --text: #e6edf3; --muted: #8b98a5; --accent: #4cc2ff;
  --clean: #35c46f; --suspicious: #f5b83d; --malicious: #ff5b5b;
  --crit: #ff4d4d; --high: #ff9f43; --med: #f5d547; --low: #6fb3ff;
  --mono: "Cascadia Mono", Consolas, "Courier New", monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text);
  font-family: "Microsoft YaHei", "PingFang SC", "Segoe UI", sans-serif; font-size: 14px; line-height: 1.6; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 28px 22px 56px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, .mono { font-family: var(--mono); font-size: 12px; }
code { background: #0a0e13; border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px;
  word-break: break-all; }
.top { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px;
  border-bottom: 1px solid var(--line); padding-bottom: 14px; margin-bottom: 22px; }
.brand { font-size: 22px; font-weight: 700; letter-spacing: 1px; }
.brand .sub { font-size: 12px; font-weight: 400; color: var(--muted); margin-left: 10px; letter-spacing: 0; }
.topmeta { color: var(--muted); font-size: 12px; text-align: right; }
.hero { display: flex; flex-wrap: wrap; gap: 18px; justify-content: space-between; align-items: center;
  background: linear-gradient(135deg, #151d27 0%, #10161e 100%);
  border: 1px solid var(--line); border-left: 6px solid var(--clean); border-radius: 12px;
  padding: 20px 24px; margin-bottom: 22px; }
.hero.suspicious { border-left-color: var(--suspicious); }
.hero.malicious { border-left-color: var(--malicious); }
.hero .label { color: var(--muted); font-size: 12px; letter-spacing: 2px; }
.hero .verdict { font-size: 32px; font-weight: 800; line-height: 1.2; }
.hero .verdict .en { font-size: 14px; font-weight: 500; color: var(--muted); margin-left: 10px; }
.hero.clean .verdict { color: var(--clean); }
.hero.suspicious .verdict { color: var(--suspicious); }
.hero.malicious .verdict { color: var(--malicious); }
.hero .meta { color: var(--muted); font-size: 13px; margin-top: 4px; }
.stats { display: flex; gap: 10px; flex-wrap: wrap; }
.stat { min-width: 86px; background: var(--panel2); border: 1px solid var(--line);
  border-radius: 10px; padding: 10px 14px; text-align: center; }
.stat b { display: block; font-size: 22px; }
.stat span { color: var(--muted); font-size: 12px; }
.bars { margin-top: 10px; display: grid; gap: 6px; min-width: 300px; }
.bar-row { display: flex; align-items: center; gap: 10px; font-size: 12px; color: var(--muted); }
.bar-row .bar { flex: 1; height: 7px; background: #0a0e13; border-radius: 4px; overflow: hidden; border: 1px solid var(--line); }
.bar-row .bar i { display: block; height: 100%; background: var(--accent); }
.hero.clean .bar-row .bar i.score { background: var(--clean); }
.hero.suspicious .bar-row .bar i.score { background: var(--suspicious); }
.hero.malicious .bar-row .bar i.score { background: var(--malicious); }
section.block { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 18px 20px; margin-bottom: 18px; }
section.block > h2 { margin: 0 0 4px; font-size: 16px; letter-spacing: .5px; }
section.block > .hint { color: var(--muted); font-size: 12px; margin-bottom: 12px; }
.notice { color: var(--muted); background: var(--panel2); border: 1px dashed var(--line);
  border-radius: 8px; padding: 10px 12px; font-size: 13px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { border-bottom: 1px solid var(--line); padding: 8px 9px; text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; white-space: nowrap;
  background: var(--panel2); }
tr:last-child td { border-bottom: none; }
.table-wrap { overflow-x: auto; }
td.num, th.num { text-align: right; font-family: var(--mono); }
.chip { display: inline-block; padding: 1px 8px; margin: 2px 4px 2px 0; border-radius: 999px;
  border: 1px solid var(--line); background: var(--panel2); font-size: 12px; color: var(--text); }
.chip.hit { border-color: var(--accent); color: var(--accent); }
.badge { display: inline-block; padding: 1px 8px; border-radius: 6px; font-size: 12px;
  font-weight: 600; border: 1px solid currentColor; }
.badge.critical { color: var(--crit); }
.badge.high { color: var(--high); }
.badge.medium { color: var(--med); }
.badge.low { color: var(--low); }
.badge.suppressed { color: var(--muted); }
.verdict-badge.clean { color: var(--clean); }
.verdict-badge.suspicious { color: var(--suspicious); }
.verdict-badge.malicious { color: var(--malicious); }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 14px 22px; }
.kv { display: flex; gap: 10px; padding: 4px 0; border-bottom: 1px dashed #1b2430; font-size: 13px; }
.kv:last-child { border-bottom: none; }
.kv .k { color: var(--muted); min-width: 96px; flex: 0 0 auto; }
.kv .v { word-break: break-word; }
ul.plain { margin: 6px 0; padding-left: 20px; }
ul.plain li { margin: 3px 0; }
.timeline td.ts { font-family: var(--mono); white-space: nowrap; color: var(--muted); }
.timeline td.id { font-family: var(--mono); white-space: nowrap; }
.cat { display: inline-block; min-width: 52px; padding: 0 6px; border-radius: 4px;
  font-family: var(--mono); font-size: 11px; text-align: center; border: 1px solid var(--line);
  background: var(--panel2); color: var(--muted); }
.cat-process { color: #7ee787; } .cat-file { color: #79c0ff; }
.cat-registry { color: #d2a8ff; } .cat-network { color: #ffa657; }
.cat-memory { color: #ff7b72; } .cat-api { color: #a5d6ff; }
.cat-security { color: #ffd33d; } .cat-service, .cat-scheduled_task { color: #f2cc60; }
.small { font-size: 12px; color: var(--muted); }
.args { color: var(--muted); font-family: var(--mono); font-size: 11px;
  max-width: 360px; overflow-wrap: anywhere; }
.evidence { font-size: 12px; color: var(--muted); margin: 2px 0; }
.evidence a { font-family: var(--mono); margin-right: 4px; }
.suppressed-row td { opacity: .55; }
.group + .group { margin-top: 18px; }
.group h3 { margin: 0 0 8px; font-size: 14px; }
.group h3 .count { color: var(--muted); font-weight: 400; font-size: 12px; margin-left: 8px; }
.matrix { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; }
.mtactic { border: 1px solid var(--line); border-radius: 8px; background: var(--panel2);
  padding: 8px 10px; min-height: 74px; }
.mtactic.hit { border-color: var(--accent); background: #10212e; box-shadow: inset 0 0 0 1px #1b4d66; }
.mtactic .tid { font-family: var(--mono); font-size: 11px; color: var(--muted); }
.mtactic .tname { font-weight: 600; font-size: 13px; }
.mtactic .techs { margin-top: 5px; }
.mtactic .tech { display: block; font-size: 11px; color: var(--muted); line-height: 1.5;
  overflow-wrap: anywhere; }
.hitmark { color: var(--accent); font-weight: 700; }
.fidelity { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
.fidelity .chip { font-family: var(--mono); }
.raw { max-height: 260px; overflow: auto; background: #0a0e13; border: 1px solid var(--line);
  border-radius: 6px; padding: 8px; margin: 6px 0; white-space: pre-wrap; word-break: break-all;
  font-family: var(--mono); font-size: 11px; color: var(--muted); }
details > summary { cursor: pointer; color: var(--muted); font-size: 12px; }
footer.foot { color: var(--muted); font-size: 12px; border-top: 1px solid var(--line);
  margin-top: 28px; padding-top: 16px; }
footer.foot p { margin: 6px 0; }
@media print {
  body { background: #fff; color: #111; }
  section.block, .hero, .stat, .mtactic { background: #fff; border-color: #ccc; }
  th { background: #f3f3f3; }
}
"""


def esc(value: Any) -> str:
    """HTML 转义（文本与属性通用）。"""
    if value is None:
        return ""
    return _html.escape(str(value), quote=True)


def _css_token(value: Any) -> str:
    token = _CSS_TOKEN_RE.sub("", str(value or "").lower())
    return token[:40] or "other"


def _fmt_size(size: Any) -> str:
    try:
        number = int(size)
    except (TypeError, ValueError):
        return esc(size)
    if number < 1024:
        return f"{number} B"
    for unit in ("KB", "MB", "GB", "TB"):
        number_f = number / 1024.0
        number = int(number_f)
        if number_f < 1024 or unit == "TB":
            return f"{number_f:.2f} {unit}"
    return f"{number} B"


def _pct(value: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number <= 1.0:
        number *= 100.0
    return max(0.0, min(100.0, number))


def _score_pct(score: float) -> float:
    try:
        return max(0.0, min(100.0, float(score)))
    except (TypeError, ValueError):
        return 0.0


def _verdict_label(verdict: str) -> str:
    return _VERDICT_ZH.get(str(verdict), str(verdict))


def _section(section_id: str, title: str, body: str, *, hint: str = "") -> str:
    hint_html = f'<div class="hint">{hint}</div>' if hint else ""
    return (
        f'<section class="block" id="{esc(section_id)}">'
        f"<h2>{esc(title)}</h2>{hint_html}{body}</section>"
    )


def _kv(key: str, value: str) -> str:
    return f'<div class="kv"><span class="k">{esc(key)}</span><span class="v">{value}</span></div>'


def _value_html(value: Any, *, depth: int = 0) -> str:
    if depth > 3:
        return f"<code>{esc(json.dumps(value, ensure_ascii=False, default=str))}</code>"
    if isinstance(value, bool):
        return "是" if value else "否"
    if value is None:
        return '<span class="small">—</span>'
    if isinstance(value, dict):
        if not value:
            return '<span class="small">（空）</span>'
        rows = "".join(_kv(str(k), _value_html(v, depth=depth + 1)) for k, v in value.items())
        return f'<div class="kv-list">{rows}</div>'
    if isinstance(value, (list, tuple)):
        if not value:
            return '<span class="small">（空）</span>'
        items = "".join(f"<li>{_value_html(item, depth=depth + 1)}</li>" for item in value)
        return f'<ul class="plain">{items}</ul>'
    return esc(value)


def _evidence_ids(ids: Iterable[Any], event_ids: set[str]) -> str:
    parts: list[str] = []
    for event_id in ids:
        text = str(event_id)
        if text in event_ids:
            parts.append(f'<a href="#ev-{esc(text)}">{esc(text)}</a>')
        else:
            parts.append(f"<code>{esc(text)}</code>")
    return "".join(parts) if parts else '<span class="small">—</span>'


def _evidence_map(evidence: dict[str, list[str]], event_ids: set[str]) -> str:
    if not evidence:
        return '<span class="small">—</span>'
    rows: list[str] = []
    for key, values in evidence.items():
        rows.append(
            f'<div class="evidence"><span>{esc(key)}</span> '
            f"{_evidence_ids(values, event_ids)}</div>"
        )
    return "".join(rows)


def _technique_chips(attack_entries: Iterable[str], extra_techniques: Iterable[str] = ()) -> str:
    seen: list[str] = []
    for entry in list(attack_entries) + list(extra_techniques):
        for tid in _TECHNIQUE_RE.findall(str(entry)):
            tid = tid.upper()
            if tid not in seen:
                seen.append(tid)
    if not seen:
        return '<span class="small">—</span>'
    chips: list[str] = []
    for tid in seen:
        tactic = mitre.tactic_for_technique(tid)
        label = f"{tid} {mitre.technique_name(tid)}"
        title = mitre.tactic_name(tactic) if tactic else ""
        chips.append(f'<span class="chip hit" title="{esc(title)}">{esc(label)}</span>')
    return "".join(chips)


def _tactic_chips(tactics: Iterable[str]) -> str:
    chips = [
        f'<span class="chip">{esc(tactic)} {esc(mitre.tactic_name(tactic))}</span>'
        for tactic in tactics
    ]
    return "".join(chips) if chips else '<span class="small">—</span>'


def _event_index(result: ScanResult) -> set[str]:
    return {str(ev.get("id")) for ev in result.events if ev.get("id")}


def _render_summary(result: ScanResult, matrix: dict[str, Any]) -> str:
    verdict = str(result.verdict.verdict or "clean")
    verdict_cls = verdict if verdict in ("clean", "suspicious", "malicious") else "clean"
    extra = result.extra if isinstance(result.extra, dict) else {}
    thresholds = extra.get("thresholds") if isinstance(extra.get("thresholds"), dict) else {}
    clean_below = thresholds.get("clean_below", 10.0)
    malicious_at = thresholds.get("malicious_at", 40.0)
    confidence_pct = _pct(result.verdict.confidence)
    score_pct = _score_pct(result.verdict.score)
    tactic_count = sum(1 for column in matrix.get("columns", []) if column.get("hit"))
    engine_version = str((result.trace.get("engine") or {}).get("version") or __version__)
    source_path = extra.get("source_path") or result.sample.get("path") or "—"
    return (
        f'<section class="hero {verdict_cls}" id="summary">'
        f'<div><div class="label">结论 VERDICT</div>'
        f'<div class="verdict">{esc(_verdict_label(verdict))}'
        f'<span class="en">{esc(verdict)}</span></div>'
        f'<div class="meta">评分 <b>{esc(result.verdict.score)}</b> / 恶意阈值 {esc(malicious_at)}'
        f"（低于 {esc(clean_below)} 判定为干净） · 置信度 <b>{confidence_pct:.0f}%</b></div>"
        f'<div class="bars">'
        f'<div class="bar-row"><span>评分</span><div class="bar"><i class="score" style="width:{score_pct:.1f}%"></i></div>'
        f'<span class="mono">{esc(result.verdict.score)}</span></div>'
        f'<div class="bar-row"><span>置信度</span><div class="bar"><i style="width:{confidence_pct:.1f}%"></i></div>'
        f'<span class="mono">{confidence_pct:.0f}%</span></div>'
        f"</div></div>"
        f'<div class="stats">'
        f'<div class="stat"><b>{len(result.matches)}</b><span>能力命中</span></div>'
        f'<div class="stat"><b>{len(result.hits)}</b><span>危险行为</span></div>'
        f'<div class="stat"><b>{tactic_count}</b><span>命中战术</span></div>'
        f'<div class="stat"><b>{len(result.events)}</b><span>行为事件</span></div>'
        f"</div></section>"
        f'<div class="small" style="margin:-8px 0 18px">样本：<code>{esc(result.sample_name)}</code>'
        f" · 结果 schema：{esc(result.schema or RESULT_SCHEMA)} · 引擎 v{esc(engine_version)}"
        f" · 输入：<code>{esc(source_path)}</code></div>"
    )


def _render_sample(result: ScanResult) -> str:
    sample = result.sample or {}
    rows = [
        _kv("文件名", f"<code>{esc(sample.get('name'))}</code>"),
        _kv("SHA-256", f"<code>{esc(sample.get('sha256'))}</code>"),
        _kv("SHA-1", f"<code>{esc(sample.get('sha1'))}</code>") if sample.get("sha1") else "",
        _kv("MD5", f"<code>{esc(sample.get('md5'))}</code>") if sample.get("md5") else "",
        _kv("大小", f"{esc(_fmt_size(sample.get('size')))}（{esc(sample.get('size'))} 字节）"),
        _kv("类型", f"<code>{esc(sample.get('type'))}</code>"),
        _kv("来源", f"<code>{esc(sample.get('origin'))}</code>" if sample.get("origin") else "—"),
    ]
    return _section("sample", "文件信息", "".join(rows), hint="样本元信息与哈希，均来自入库阶段（L0）。")


def _signal_row(item: Any) -> str:
    if not isinstance(item, dict):
        return (
            '<tr><td><span class="badge medium">中</span></td>'
            f'<td><code>{esc(item)}</code></td><td>—</td><td class="num">—</td></tr>'
        )
    signal_id = item.get("id") or item.get("name") or ""
    severity = str(item.get("severity") or "medium")
    detail = item.get("detail") or item.get("description") or ""
    score = item.get("score")
    score_text = "—" if score is None else str(score)
    return (
        f'<tr><td><span class="badge {esc(_css_token(severity))}">{esc(_SEVERITY_ZH.get(severity, severity))}</span></td>'
        f"<td><code>{esc(signal_id)}</code></td><td>{esc(detail)}</td>"
        f'<td class="num">{esc(score_text)}</td></tr>'
    )


def _static_value_summary(value: Any) -> str:
    """静态报告里的大列表/大字典折叠展示，避免报告体积失控。"""
    if isinstance(value, list):
        if not value:
            return '<span class="small">（空）</span>'
        if len(value) <= 12 and all(not isinstance(item, (dict, list)) for item in value):
            return "".join(f'<span class="chip">{esc(item)}</span>' for item in value)
        preview = esc(json.dumps(value, ensure_ascii=False, default=str)[:2000])
        return f'<details><summary>{len(value)} 项（点击展开）</summary><pre class="raw">{preview}</pre></details>'
    if isinstance(value, dict):
        if not value:
            return '<span class="small">（空）</span>'
        if len(value) <= 8 and all(not isinstance(item, (dict, list)) for item in value.values()):
            return "".join(_kv(str(key), _value_html(item)) for key, item in value.items())
        preview = esc(json.dumps(value, ensure_ascii=False, default=str)[:2000])
        return f'<details><summary>{len(value)} 项（点击展开）</summary><pre class="raw">{preview}</pre></details>'
    return _value_html(value)


def _render_static(result: ScanResult) -> str:
    static = result.static if isinstance(result.static, dict) else {}
    if not static:
        body = '<div class="notice">静态预筛结果为空（M1 静态分析模块尚未接通，或未提供静态输入）。</div>'
        return _section("static", "静态信号", body)
    if static.get("available") is False:
        reason = static.get("reason") or "静态分析模块不可用"
        body = f'<div class="notice">静态信号不可用：{esc(reason)}</div>'
        return _section("static", "静态信号", body)
    parts: list[str] = []
    signals = static.get("signals")
    if isinstance(signals, list) and signals:
        rows = "".join(_signal_row(item) for item in signals[:80])
        parts.append(
            '<div class="table-wrap"><table><thead><tr><th>严重度</th><th>信号 ID</th>'
            '<th>说明</th><th class="num">分数</th></tr></thead><tbody>'
            + rows
            + "</tbody></table></div>"
        )
        if len(signals) > 80:
            parts.append(f'<div class="small">仅展示前 80 条静态信号，共 {len(signals)} 条；完整数据见结果 JSON。</div>')
    else:
        parts.append('<div class="notice">未产出静态信号。</div>')
    findings = static.get("findings")
    if isinstance(findings, list) and findings:
        items = "".join(f"<li>{_value_html(item)}</li>" for item in findings)
        parts.append(f'<h3 style="font-size:13px;margin:14px 0 4px">发现</h3><ul class="plain">{items}</ul>')
    keys = [key for key in static if key not in ("available", "reason", "signals", "findings")]
    if keys:
        parts.append('<div class="grid2" style="margin-top:14px">')
        for key in keys:
            parts.append(_kv(key, _static_value_summary(static[key])))
        parts.append("</div>")
    return _section("static", "静态信号", "".join(parts), hint="PE / 脚本 / 归档等静态特征与启发式信号（M1）。")


def _render_sandbox(result: ScanResult) -> str:
    trace = result.trace or {}
    engine = trace.get("engine") or {}
    sandbox = trace.get("sandbox") or {}
    summary = trace.get("summary") or {}
    limits = sandbox.get("limits") or {}
    info_rows = [
        _kv("trace_id", f"<code>{esc(trace.get('trace_id'))}</code>"),
        _kv("沙箱后端", f"<code>{esc(engine.get('backend'))}</code>"),
        _kv("策略档位", f"<code>{esc(engine.get('policy'))}</code>"),
        _kv("引擎版本", esc(engine.get("version"))),
        _kv("主机", esc(sandbox.get("host"))),
        _kv("终止方式", f"<code>{esc(sandbox.get('terminated_by'))}</code>"),
        _kv("开始时间", esc(sandbox.get("started_at"))),
        _kv("结束时间", esc(sandbox.get("ended_at"))),
        _kv("隔离手段", "".join(f'<span class="chip">{esc(x)}</span>' for x in (sandbox.get("isolation") or [])) or "—"),
        _kv(
            "资源限制",
            f"超时 {esc(limits.get('timeout_s'))}s · 内存 {esc(limits.get('mem_mb'))}MB · "
            f"CPU {esc(limits.get('cpu_s'))}s · 网络 {esc(limits.get('network'))}",
        ),
    ]
    trace_extra = trace.get("extra") if isinstance(trace.get("extra"), dict) else {}
    etw = trace_extra.get("etw")
    if isinstance(etw, dict):
        etw_enabled = etw.get("enabled")
        etw_reason = etw.get("reason") or etw.get("note") or ""
        if etw_enabled is False:
            info_rows.append(_kv("ETW 观测", f'<span class="badge medium">关闭</span> {esc(etw_reason)}'))
        elif etw_enabled is True:
            info_rows.append(_kv("ETW 观测", '<span class="badge low">开启</span>'))
        else:
            info_rows.append(_kv("ETW 观测", esc(etw_reason or "未知")))
    for key, value in trace_extra.items():
        if key in ("etw", "source_path"):
            continue
        info_rows.append(_kv(str(key), _value_html(value)))
    counter_cells: list[str] = []
    for key, label in _SUMMARY_FIELDS:
        if key in summary:
            counter_cells.append(f'<div class="stat"><b>{esc(summary.get(key))}</b><span>{esc(label)}</span></div>')
    counters = "".join(counter_cells)
    truncated = ""
    if summary.get("truncated") or summary.get("dropped"):
        truncated = (
            f'<div class="notice" style="margin-top:12px">轨迹已裁剪：丢弃 {esc(summary.get("dropped"))} 条事件'
            f"（上限保护），结论置信度应在报告中相应下调。</div>"
        )
    dropped_files = summary.get("dropped_files") or []
    dropped_html = ""
    if dropped_files:
        items = "".join(f"<li><code>{esc(path)}</code></li>" for path in dropped_files)
        dropped_html = f'<h3 style="font-size:13px;margin:14px 0 4px">落地文件</h3><ul class="plain">{items}</ul>'
    body = (
        '<div class="grid2">' + "".join(info_rows) + "</div>"
        + f'<div class="stats" style="margin-top:14px">{counters}</div>'
        + truncated + dropped_html
    )
    return _section("sandbox", "沙箱执行摘要", body, hint="执行环境、资源限制与轨迹派生指标（L1/L2）。")


def _render_fidelity(result: ScanResult) -> str:
    counts: dict[str, int] = {}
    for event in result.events:
        source = str(event.get("source") or "unknown").split(":", 1)[0]
        counts[source] = counts.get(source, 0) + 1
    quality = {"api": "high", "etw": "high", "snapshot": "medium", "static-infer": "low"}
    chips = "".join(
        f'<span class="chip">{esc(source)}: {esc(count)} 条 · {esc(quality.get(source, "unknown"))} 保真度</span>'
        for source, count in sorted(counts.items())
    )
    if not chips:
        chips = '<span class="chip">无事件来源信息</span>'
    notes: list[str] = []
    confidence = result.verdict.confidence
    if result.trace.get("sandbox", {}).get("terminated_by") == "timeout":
        notes.append("本次执行因超时被终止，未覆盖的后续行为可能缺失。")
    if confidence < 0.5:
        notes.append("置信度偏低：证据数量或来源保真度不足，建议人工复核。")
    note_html = "".join(f'<div class="small">· {esc(note)}</div>' for note in notes)
    body = (
        '<div class="fidelity">' + chips + "</div>"
        + '<div class="small" style="margin-top:10px">保真度分级：api(high) &gt; etw(high) &gt; snapshot(medium) &gt; static-infer(low)。'
        "结论按来源加权，报告据此说明可解释边界。</div>" + note_html
    )
    return _section("fidelity", "观测保真度", body)


def _render_timeline(result: ScanResult, *, max_events: int = 200) -> str:
    events = result.events
    if not events:
        return _section("timeline", "行为时间线", '<div class="notice">无事件（轨迹为空）。</div>')
    shown = events[:max_events]
    rows: list[str] = []
    for event in shown:
        event_id = str(event.get("id") or "")
        args = event.get("args") or {}
        try:
            args_text = json.dumps(args, ensure_ascii=False, default=str) if args else ""
        except (TypeError, ValueError):
            args_text = str(args)
        if len(args_text) > 180:
            args_text = args_text[:177] + "..."
        image = str(event.get("image") or "")
        image_short = image.rsplit("\\", 1)[-1] if image else ""
        rows.append(
            f'<tr id="ev-{esc(event_id)}">'
            f'<td class="ts">{esc(event.get("ts"))}s</td>'
            f'<td><span class="cat cat-{_css_token(event.get("category"))}">{esc(event.get("category"))}</span></td>'
            f'<td>{esc(event.get("action"))}</td>'
            f'<td><div>{esc(image_short or image)}</div><div class="small mono">pid {esc(event.get("pid"))}</div></td>'
            f'<td><div class="mono">{esc(event.get("target"))}</div><div class="args">{esc(args_text)}</div></td>'
            f'<td class="small">{esc(event.get("source"))}<br>{esc(event.get("confidence"))}</td>'
            f'<td class="id">{esc(event_id)}</td></tr>'
        )
    trunc_note = ""
    if len(events) > max_events:
        trunc_note = f'<div class="small">仅展示前 {max_events} 条事件，共 {len(events)} 条；完整事件见结果 JSON。</div>'
    body = (
        '<div class="table-wrap"><table class="timeline"><thead><tr>'
        "<th>时间</th><th>类别</th><th>动作</th><th>进程</th><th>目标 / 参数</th><th>来源</th><th>事件 ID</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>" + trunc_note
    )
    return _section("timeline", "行为时间线", body, hint="事件 ID 可被能力/行为证据链引用，用于回溯原始轨迹。")


def _render_capabilities(result: ScanResult) -> str:
    event_ids = _event_index(result)
    if not result.matches:
        return _section(
            "capabilities",
            "capa 能力识别",
            '<div class="notice">未命中能力规则（规则包/引擎未接通，或样本未匹配任何规则）。</div>',
        )
    groups: dict[str, list[Any]] = {}
    for match in result.matches:
        namespace = str(getattr(match, "namespace", "") or "")
        root = namespace.split("/", 1)[0] if namespace else "capability"
        groups.setdefault(root, []).append(match)
    parts: list[str] = []
    for root in sorted(groups):
        matches = groups[root]
        label = _NS_ZH.get(root, root)
        rows: list[str] = []
        for match in matches:
            instance = getattr(match, "instance", {}) or {}
            instance_text = " · ".join(f"{esc(k)}={esc(v)}" for k, v in instance.items()) or "—"
            rows.append(
                "<tr>"
                f"<td><b>{esc(getattr(match, 'name', ''))}</b></td>"
                f'<td class="mono">{esc(getattr(match, 'namespace', ''))}</td>'
                f"<td><code>{esc(getattr(match, 'scope', ''))}</code></td>"
                f'<td class="small">{instance_text}</td>'
                f"<td>{_technique_chips(getattr(match, 'attack', []) or [])}</td>"
                f"<td>{_evidence_map(getattr(match, 'evidence', {}) or {}, event_ids)}</td>"
                "</tr>"
            )
        parts.append(
            f'<div class="group"><h3>{esc(label)} <code>{esc(root)}</code>'
            f'<span class="count">{len(matches)} 条</span></h3>'
            '<div class="table-wrap"><table><thead><tr><th>能力</th><th>命名空间</th><th>作用域</th>'
            "<th>命中实例</th><th>ATT&amp;CK</th><th>证据事件</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div></div>"
        )
    return _section(
        "capabilities",
        "capa 能力识别",
        "".join(parts),
        hint="capa 10 兼容规则按命名空间分组；ATT&CK 技术来自规则元数据。",
    )


def _render_behaviors(result: ScanResult) -> str:
    event_ids = _event_index(result)
    if not result.hits:
        return _section(
            "behaviors",
            "危险行为",
            '<div class="notice">未命中危险行为检测器（检测器未接通，或样本行为未达到阈值）。</div>',
        )
    ordered = sorted(
        result.hits,
        key=lambda hit: (
            0 if getattr(hit, "suppressed", False) else 1,
            SEVERITY_RANK.get(str(getattr(hit, "severity", "")), 0),
            float(getattr(hit, "score", 0.0) or 0.0),
        ),
        reverse=True,
    )
    rows: list[str] = []
    for hit in ordered:
        severity = str(getattr(hit, "severity", "") or "medium")
        suppressed = bool(getattr(hit, "suppressed", False))
        cls = "suppressed-row" if suppressed else ""
        tactic = str(getattr(hit, "tactic", "") or "")
        technique = str(getattr(hit, "technique", "") or "")
        tactic_text = f"{esc(tactic)} {esc(mitre.tactic_name(tactic))}".strip() if tactic else "—"
        technique_text = (
            f'<span class="chip hit">{esc(technique)} {esc(mitre.technique_name(technique))}</span>'
            if technique
            else "—"
        )
        evidence = _evidence_ids(getattr(hit, "evidence", []) or [], event_ids)
        detail = getattr(hit, "detail", "") or ""
        if suppressed:
            detail = (detail + " ").strip() + "（已抑制：" + str(getattr(hit, "suppress_reason", "") or "无原因") + "）"
        rows.append(
            f'<tr class="{cls}">'
            f'<td><span class="badge {esc(_css_token(severity))}">{esc(_SEVERITY_ZH.get(severity, severity))}</span></td>'
            f'<td><b>{esc(getattr(hit, "name", "") or getattr(hit, "detector_id", ""))}</b>'
            f'<div class="small mono">{esc(getattr(hit, "detector_id", ""))}</div></td>'
            f"<td>{tactic_text}</td><td>{technique_text}</td>"
            f'<td class="num">{esc(getattr(hit, "score", 0.0))}</td>'
            f'<td>{evidence}</td><td class="small">{esc(detail)}</td></tr>'
        )
    body = (
        '<div class="table-wrap"><table><thead><tr><th>严重度</th><th>检测器</th><th>战术</th>'
        '<th>技术</th><th class="num">分数</th><th>证据事件</th><th>说明</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )
    return _section(
        "behaviors",
        "危险行为",
        body,
        hint="按严重度降序；被抑制项保留展示以便审计，但不计入最终分数。",
    )


def _render_scoring(result: ScanResult) -> str:
    items = result.verdict.items
    if not items:
        return _section(
            "scoring",
            "评分明细",
            '<div class="notice">无评分明细（评分模块未接通时为后备适配器结果，详见备注）。</div>',
        )
    event_ids = _event_index(result)
    rows: list[str] = []
    for item in items:
        cls = "suppressed-row" if item.suppressed else ""
        reason = f'<div class="small">{esc(item.suppress_reason)}</div>' if item.suppress_reason else ""
        rows.append(
            f'<tr class="{cls}"><td><span class="chip">{esc(_KIND_ZH.get(item.kind, item.kind))}</span></td>'
            f'<td>{esc(item.ref)}</td><td class="num">{esc(item.score)}</td>'
            f'<td class="small">{esc(item.detail)}{reason}</td>'
            f"<td>{_evidence_ids(item.evidence, event_ids)}</td></tr>"
        )
    body = (
        '<div class="table-wrap"><table><thead><tr><th>类型</th><th>来源</th>'
        '<th class="num">分数</th><th>说明</th><th>证据事件</th></tr></thead><tbody>'
        + "".join(rows)
        + f'</tbody><tfoot><tr><th colspan="2">合计</th><th class="num">{esc(result.verdict.score)}</th>'
        f'<th colspan="2" class="small">判定阈值由 config/engine.json scoring 段控制</th></tr></tfoot></table></div>'
    )
    return _section("scoring", "评分明细", body, hint="每一条加分/扣分都可追溯到规则、检测器与事件 ID。")


def _render_matrix(result: ScanResult, matrix: dict[str, Any]) -> str:
    columns = matrix.get("columns", [])
    hit_columns = [column for column in columns if column.get("hit")]
    if hit_columns:
        cells: list[str] = []
        for column in columns:
            classes = "mtactic hit" if column.get("hit") else "mtactic"
            techs = column.get("techniques") or []
            tech_html = "".join(
                f'<span class="tech"><span class="hitmark">●</span> {esc(tech.get("id"))} {esc(tech.get("name"))}</span>'
                for tech in techs
            )
            cells.append(
                f'<div class="{classes}">'
                f'<div class="tid">{esc(column.get("id"))}'
                f'{" · 命中" if column.get("hit") else ""}</div>'
                f'<div class="tname">{esc(column.get("name_zh"))}</div>'
                f'<div class="techs">{tech_html}</div></div>'
            )
        body = f'<div class="matrix">{"".join(cells)}</div>'
        unmapped = matrix.get("unmapped") or []
        if unmapped:
            chips = "".join(
                f'<span class="chip hit">{esc(item.get("id"))} {esc(item.get("name"))}</span>'
                for item in unmapped
            )
            body += f'<div style="margin-top:12px"><span class="small">未映射到战术的技术：</span>{chips}</div>'
    else:
        body = '<div class="notice">未命中可映射的 ATT&amp;CK 战术（无规则/检测器命中）。</div>'
    return _section("attack", "ATT&CK 战术矩阵", body, hint="按 Enterprise 12 战术展示命中覆盖，蓝色为已命中。")


def _render_notes(result: ScanResult) -> str:
    if not result.notes:
        return ""
    items = "".join(f"<li>{esc(note)}</li>" for note in result.notes)
    return _section("notes", "分析备注与限制", f'<ul class="plain">{items}</ul>')


def _render_disclaimer(result: ScanResult) -> str:
    engine_version = str((result.trace.get("engine") or {}).get("version") or __version__)
    fidelity = (
        "动态结论基于沙箱观测（api/etw 高保真，snapshot 中保真，static-infer 低保真）；"
        "事件裁剪、超时终止、反分析规避都会降低结论置信度。"
    )
    return (
        '<footer class="foot">'
        f"<p><b>免责声明</b>：本报告由天体引擎 v{esc(engine_version)} 自动生成，仅用于获得授权的安全分析、"
        "检测能力验证与教学研究。报告结论是对样本在受控观测环境中所表现行为的归纳，"
        "不构成对真实环境中全部行为的保证，也不应作为唯一处置依据。</p>"
        "<p><b>保真度说明</b>："
        + esc(fidelity)
        + "</p>"
        "<p><b>安全边界</b>：本机沙箱仅运行无害模拟样本与系统程序拷贝，禁止真实恶意样本；"
        "样本默认断网执行，超时强制终止。详见 docs/THREAT_MODEL.md。</p>"
        f'<p class="small">结果 schema：{esc(result.schema or RESULT_SCHEMA)} · 生成时间：{esc(result.created_at or "—")}</p>'
        "</footer>"
    )


def render_html(
    result: ScanResult,
    *,
    title: str | None = None,
    max_events: int = 200,
) -> str:
    """渲染单文件 HTML 报告（全部动态内容已转义）。"""
    if not isinstance(result, ScanResult):
        result = ScanResult.from_dict(result)
    tactics = list(result.verdict.tactics)
    techniques = list(result.verdict.techniques)
    for match in result.matches:
        try:
            meta = RuleMeta(name=match.name, attack=list(match.attack))
            tactics.extend(meta.tactics())
            techniques.extend(meta.techniques())
        except Exception:
            continue
    for hit in result.hits:
        if hit.tactic:
            tactics.append(hit.tactic)
        if hit.technique:
            techniques.append(hit.technique)
    matrix = mitre.build_matrix(tactics, techniques)
    page_title = title or f"天体引擎报告 - {result.sample_name}"
    generated = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    body = "".join(
        [
            _render_summary(result, matrix),
            _render_sample(result),
            _render_static(result),
            _render_sandbox(result),
            _render_fidelity(result),
            _render_timeline(result, max_events=max_events),
            _render_capabilities(result),
            _render_behaviors(result),
            _render_scoring(result),
            _render_matrix(result, matrix),
            _render_notes(result),
            _render_disclaimer(result),
            f'<div class="small">报告生成于 {esc(generated)}</div>',
        ]
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="zh-CN">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{esc(page_title)}</title>\n<style>{_CSS}</style>\n</head>\n"
        f'<body><div class="wrap"><header class="top"><div class="brand">◎ 天体引擎'
        '<span class="sub">TianTi Behavior Analysis Report</span></div>'
        f'<div class="topmeta">单文件离线报告 · 无外部资源<br>'
        f"引擎 v{esc(__version__)} · schema {esc(RESULT_SCHEMA)}</div></header>"
        f"{body}</div></body>\n</html>\n"
    )


def save_html(
    result: ScanResult,
    path: str | Path,
    *,
    title: str | None = None,
    max_events: int = 200,
) -> Path:
    """渲染并写入 HTML 文件，返回实际路径。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_html(result, title=title, max_events=max_events), encoding="utf-8")
    return target
