"""把 CAPE / capa 官方动态分析报告 JSON 转换为 tianti.trace/1。

用途：上游 capa 规则大量依赖 api 级特征（api(call, name=...)），而本地沙箱
目前主要产出 ETW 内核事件；本工具把 CAPE 报告（processes[].calls[]）或
capa 动态报告（calls[]）转成带 api/file/registry/network 事件的行为轨迹，
从而让 rules/upstream 的 api 级规则可以离线回放验证。

输入兼容：
- CAPE：{"behavior": {"processes": [{"process_id": ..., "calls": [{api, arguments, ...}]}]}}
- capa 动态：{"calls": [{"api": "...", "args": {...}, "thread": {"process_id": ...}}]}
输出：合法 tianti.trace/1（直接复用 tianti.trace.schema 校验）。

命令行：
    python -m tianti convert-cape <report.json> --out <trace.json>
    python -m tools.report2trace <report.json> --out <trace.json>   # 等价
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

if __package__ in (None, ""):  # 允许 python tools/report2trace.py 直接运行
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tianti import __version__  # noqa: E402
from tianti.core.errors import TraceError  # noqa: E402
from tianti.trace import schema  # noqa: E402
from tianti.trace.schema import (  # noqa: E402
    Event,
    EngineInfo,
    SampleInfo,
    SandboxInfo,
    SandboxLimits,
    Trace,
    TraceSummary,
    new_trace_id,
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BACKSLASH = chr(92)
DEFAULT_SAMPLE_TYPE = "pe32"
MAX_CALLS = 200_000


# --------------------------------------------------------------------- JSON 读取
def load_report(path: str | Path) -> dict[str, Any]:
    """读取报告 JSON；结构不合法时抛 TraceError（CLI 统一转结构化错误）。"""
    report_path = Path(path)
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TraceError(f"报告读取失败: {report_path}: {exc}", path=str(report_path)) from exc
    except ValueError as exc:
        raise TraceError(f"报告 JSON 解析失败: {report_path}: {exc}", path=str(report_path)) from exc
    if not isinstance(payload, dict):
        raise TraceError("报告 JSON 顶层必须是对象", path=str(report_path))
    return payload


# --------------------------------------------------------------------- 通用取值
def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _first(payload: Any, *names: str, default: Any = None) -> Any:
    if not isinstance(payload, dict):
        return default
    for name in names:
        if name in payload:
            value = payload[name]
            if value is not None and value != "":
                return value
    return default


def _to_int(value: Any, default: int | None = None) -> int | None:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_args(raw: Any) -> dict[str, Any]:
    """CAPE 的 arguments 可能是 dict，也可能是 [{name, value}] 或 [[k, v]]。"""
    if isinstance(raw, dict):
        return {str(key): value for key, value in raw.items()}
    result: dict[str, Any] = {}
    for item in _as_list(raw):
        if isinstance(item, dict):
            name = item.get("name") or item.get("key") or item.get("arg")
            if name is not None:
                result[str(name)] = item.get("value", item.get("data"))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            result[str(item[0])] = item[1]
    return result


def _arg(args: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in args and args[name] not in (None, ""):
            return args[name]
        for key, value in args.items():
            if str(key).lower() == name.lower() and value not in (None, ""):
                return value
    return None


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


# --------------------------------------------------------------------- 报告结构归一化
def _iter_process_containers(report: dict[str, Any]) -> list[list[Any]]:
    behavior = _as_dict(report.get("behavior"))
    containers: list[list[Any]] = []
    for source in (report, behavior):
        for key in ("processes", "process_list", "processtree", "process_tree"):
            value = source.get(key)
            if isinstance(value, list):
                containers.append(value)
    return containers


def _process_from_entry(entry: dict[str, Any]) -> dict[str, Any]:
    pid = _to_int(_first(entry, "process_id", "pid", "processId", "id"), 0) or 0
    ppid = _to_int(_first(entry, "parent_id", "ppid", "parent_pid", "parent_process_id"), None)
    image = _string(
        _first(entry, "process_name", "image", "executable", "path", "module_path", default="")
    )
    command_line = _string(_first(entry, "command_line", "cmdline", "command", default=""))
    started = _to_float(_first(entry, "start_time", "first_seen", "timestamp", "started_at"), 0.0)
    return {
        "pid": pid,
        "ppid": ppid,
        "image": image,
        "command_line": command_line,
        "started": started,
    }


def _collect_processes(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any]]]]:
    """返回 (进程元信息列表, [(进程元信息, call), ...])。"""
    processes: dict[int, dict[str, Any]] = {}
    calls: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for container in _iter_process_containers(report):
        for entry in container:
            if not isinstance(entry, dict):
                continue
            info = _process_from_entry(entry)
            pid = int(info["pid"])
            existing = processes.get(pid)
            if existing is None:
                processes[pid] = info
            else:
                for key in ("image", "command_line"):
                    if not existing.get(key) and info.get(key):
                        existing[key] = info[key]
                if existing.get("ppid") is None and info.get("ppid") is not None:
                    existing["ppid"] = info["ppid"]
            for call in _as_list(_first(entry, "calls", "api_calls", "calls_list")):
                if isinstance(call, dict):
                    calls.append((processes[pid], call))
    return list(processes.values()), calls


def _global_calls(report: dict[str, Any]) -> list[dict[str, Any]]:
    behavior = _as_dict(report.get("behavior"))
    calls: list[Any] = []
    for source in (report, behavior):
        for key in ("calls", "api_calls"):
            value = source.get(key)
            if isinstance(value, list):
                calls.extend(value)
                break
    return [call for call in calls if isinstance(call, dict)]


def _call_api(call: dict[str, Any]) -> str:
    value = _first(call, "api", "name", "Api", "api_name", "function", "call")
    if isinstance(value, dict):
        value = _first(value, "name", "api", default="")
    return _string(value)


def _call_context(call: dict[str, Any], process: dict[str, Any] | None) -> tuple[int, int | None, str, int | None]:
    """解析 call 的 pid / tid / image / ppid。"""
    source_process = _as_dict(call.get("process"))
    source_thread = _as_dict(call.get("thread"))
    pid = _to_int(_first(call, "process_id", "pid", "processId"), None)
    if pid is None:
        pid = _to_int(_first(source_process, "process_id", "pid", "id"), None)
    if pid is None:
        pid = _to_int(_first(source_thread, "process_id", "pid"), None)
    if pid is None and process is not None:
        pid = _to_int(process.get("pid"), 0)
    tid = _to_int(_first(call, "thread_id", "tid"), None)
    if tid is None:
        tid = _to_int(_first(source_thread, "thread_id", "tid", "id"), None)
    image = _string(_first(call, "image", "process_name", "module", default=""))
    if not image and process is not None:
        image = _string(process.get("image"))
    ppid = _to_int(_first(call, "parent_id", "ppid"), None)
    if ppid is None and process is not None:
        ppid = _to_int(process.get("ppid"), None)
    return int(pid or 0), tid, image, ppid


# --------------------------------------------------------------------- 语义事件映射
FILE_CREATE = {"createfilew", "createfilea", "createfile2", "ntcreatefile", "createfilemappingw"}
FILE_WRITE = {"writefile", "writefileex", "ntwritefile", "fwrite", "copyfilew", "copyfileexw"}
FILE_READ = {"readfile", "readfileex", "ntreadfile"}
FILE_DELETE = {"deletefilew", "deletefilea", "ntdeletefile", "removedirectoryw", "removefilew"}
FILE_RENAME = {"movefilew", "movefileexw", "ntrenamefile", "renamefile", "movefilewithprogressw"}
REG_SET = {"regsetvalueexw", "regsetvalueexa", "regsetvaluew", "regsetkeyvaluew", "ntsetvaluekey"}
REG_CREATE = {"regcreatekeyexw", "regcreatekeyexa", "regcreatekeyw", "ntcreatekey"}
REG_DELETE = {"regdeletekeyw", "regdeletevaluew", "ntdeletekey", "ntdeletevaluekey"}
REG_QUERY = {"regqueryvalueexw", "regqueryvalueexa", "regopenkeyexw", "ntqueryvaluekey"}
NET_CONNECT = {"connect", "connectex", "internetconnectw", "winhttpconnect", "wsaconnect"}
NET_DNS = {"gethostbyname", "getaddrinfo", "dnsquery_w", "dnsquery_a", "dnsqueryex"}
NET_SEND = {"send", "wsasend", "httpsendrequestw", "internetsendrequest"}
MEM_ALLOC = {"virtualalloc", "virtualallocex", "ntallocatevirtualmemory"}
MEM_WRITE = {"writeprocessmemory", "ntwritevirtualmemory", "rtlwriteprocessmemory"}
MEM_PROTECT = {"virtualprotect", "virtualprotectex", "ntprotectvirtualmemory"}
THREAD_REMOTE = {"createremotethread", "createremotethreadex", "ntcreatethread", "rtlcreateuserthread"}
PROC_CREATE = {"createprocessw", "createprocessa", "shellexecutew", "shellexecuteexw", "winexec"}


def _file_target(args: dict[str, Any]) -> str:
    value = _arg(
        args,
        "file_name",
        "filename",
        "filepath",
        "lpfilename",
        "path",
        "target",
        "object_name",
        "source",
    )
    if value is None:
        value = _arg(args, "name")
    return _string(value)


def _registry_target(args: dict[str, Any]) -> str:
    key = _arg(args, "key_name", "key", "hkey", "root_key", "registry_key", "subkey", "key_path")
    value_name = _arg(args, "value_name", "value", "valname", "name")
    key_text = _string(key)
    value_text = _string(value_name)
    if key_text and value_text:
        return key_text + BACKSLASH + value_text
    return key_text or value_text


def _network_target(args: dict[str, Any]) -> str:
    host = _arg(args, "host", "hostname", "server_name", "ip", "address", "node", "name")
    port = _arg(args, "port", "server_port", "dest_port", "remote_port")
    host_text = _string(host)
    if host_text and port is not None:
        return host_text + ":" + _string(port)
    return host_text


def _semantic_events(api: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    """把有语义的 API 调用映射为 file/registry/network/memory/thread/process 事件。"""
    name = api.lower()
    output: list[dict[str, Any]] = []

    def add(category: str, action: str, target: str, extra: dict[str, Any] | None = None) -> None:
        output.append({
            "category": category,
            "action": action,
            "target": target,
            "args": dict(extra or {}),
        })

    if name in FILE_CREATE:
        add("file", "create", _file_target(args), {
            "desired_access": _arg(args, "desired_access", "access", "granted_access"),
        })
    elif name in FILE_WRITE:
        add("file", "write", _file_target(args), {"size": _arg(args, "size", "length", "number_of_bytes_to_write")})
    elif name in FILE_READ:
        add("file", "read", _file_target(args))
    elif name in FILE_DELETE:
        add("file", "delete", _file_target(args))
    elif name in FILE_RENAME:
        add("file", "rename", _file_target(args), {"new_name": _string(_arg(args, "new_name", "new_filename", "destination"))})
    elif name in REG_SET:
        add("registry", "set", _registry_target(args), {
            "value": _arg(args, "data", "value_data", "buffer", "lpdata"),
            "value_type": _arg(args, "value_type", "type", "dwtype"),
        })
    elif name in REG_CREATE:
        add("registry", "create", _registry_target(args))
    elif name in REG_DELETE:
        add("registry", "delete", _registry_target(args))
    elif name in REG_QUERY:
        add("registry", "query", _registry_target(args))
    elif name in NET_CONNECT:
        add("network", "connect", _network_target(args), {"proto": "tcp"})
    elif name in NET_DNS:
        add("network", "dns", _network_target(args))
    elif name in NET_SEND:
        add("network", "send", _network_target(args))
    elif name in MEM_ALLOC:
        add("memory", "alloc", _string(_arg(args, "process_id", "process_handle", "handle")), {
            "size": _arg(args, "size", "region_size", "allocation_size"),
            "protect": _arg(args, "protect", "flprotect", "protection"),
        })
    elif name in MEM_WRITE:
        add("memory", "write", _string(_arg(args, "process_id", "process_handle", "handle")), {
            "size": _arg(args, "size", "number_of_bytes_to_write", "buffer_length"),
        })
    elif name in MEM_PROTECT:
        add("memory", "protect", _string(_arg(args, "process_id", "process_handle", "handle")), {
            "protect": _arg(args, "protect", "flnewprotect", "new_protect"),
        })
    elif name in THREAD_REMOTE:
        add("thread", "remote_create", _string(_arg(args, "process_id", "process_handle", "handle")))
    elif name in PROC_CREATE:
        add("process", "create", _string(_arg(args, "application_name", "command_line", "app_name", "image_path")), {
            "command_line": _string(_arg(args, "command_line", "cmdline", "command")),
        })
    return output


# --------------------------------------------------------------------- 时间归一化
def _normalize_timestamps(raw_timestamps: list[float]) -> tuple[list[float], str]:
    if not raw_timestamps:
        return [], "relative"
    values = list(raw_timestamps)
    largest = max(values)
    scale = 1.0
    if largest > 1e11:
        scale = 1000.0
    values = [value / scale for value in values]
    smallest = min(values)
    if smallest > 1e6:
        return [max(0.0, value - smallest) for value in values], "epoch"
    return [max(0.0, value) for value in values], "relative"


# --------------------------------------------------------------------- 样本/环境
def _find_sha256(report: dict[str, Any], target: dict[str, Any]) -> str:
    candidates: list[Any] = []
    target_file = _as_dict(target.get("file"))
    for source in (target, target_file, _as_dict(report.get("sample")), _as_dict(report.get("meta")), report):
        for key in ("sha256", "SHA256", "sha_256"):
            candidates.append(source.get(key))
    for candidate in candidates:
        text = _string(candidate).strip().lower()
        if SHA256_RE.match(text):
            return text
    digest = hashlib.sha256(
        json.dumps(report, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    return digest


def _sample_info(report: dict[str, Any], source_name: str) -> SampleInfo:
    target = _as_dict(report.get("target"))
    file_info = _as_dict(target.get("file"))
    sample_dict = _as_dict(report.get("sample"))
    name = _string(
        _first(file_info, "name", default="")
        or _first(target, "name", "file_name", default="")
        or _first(sample_dict, "name", default="")
        or source_name
        or "report_sample.bin"
    )
    size = _to_int(
        _first(file_info, "size", default=None)
        or _first(target, "size", default=None)
        or _first(sample_dict, "size", default=None)
        or 0,
        0,
    ) or 0
    sample_type = _string(
        _first(file_info, "type", default="")
        or _first(target, "type", default="")
        or _first(sample_dict, "type", default="")
        or DEFAULT_SAMPLE_TYPE
    ).strip().lower().replace(" ", "")
    if not sample_type:
        sample_type = DEFAULT_SAMPLE_TYPE
    return SampleInfo(name=Path(name).name or "report_sample.bin", sha256=_find_sha256(report, target), size=max(0, int(size)), type=sample_type)


def _sandbox_host(report: dict[str, Any]) -> str:
    machine = _as_dict(report.get("machine"))
    return _string(
        _first(machine, "name", "hostname", default="")
        or _first(report, "host", "hostname", default="")
        or "cape-report"
    )


# --------------------------------------------------------------------- 转换主流程
def convert_report(report: dict[str, Any], *, source_name: str = "report.json") -> Trace:
    """CAPE/capa 动态报告 dict -> 已校验的 Trace。"""
    if not isinstance(report, dict):
        raise TraceError("报告必须是 JSON 对象")
    processes, process_calls = _collect_processes(report)
    global_calls = _global_calls(report)
    call_items: list[tuple[dict[str, Any] | None, dict[str, Any]]] = [
        (None, call) for call in global_calls
    ] + [(process, call) for process, call in process_calls]
    if len(call_items) > MAX_CALLS:
        call_items = call_items[:MAX_CALLS]
    if not call_items and not processes:
        raise TraceError("报告中未找到 processes/calls，无法转换")

    # 时间戳先归一化
    raw_times: list[float] = []
    for process in processes:
        raw_times.append(_to_float(process.get("started"), 0.0))
    for _, call in call_items:
        raw_times.append(_to_float(_first(call, "timestamp", "time", "ts"), 0.0))
    normalized, time_mode = _normalize_timestamps([value for value in raw_times if value])
    time_index = 0
    process_times: dict[int, float] = {}
    for process in processes:
        if _to_float(process.get("started"), 0.0):
            process_times[int(process.get("pid") or 0)] = normalized[time_index]
            time_index += 1
        else:
            process_times[int(process.get("pid") or 0)] = 0.0
    call_times: list[float] = []
    for _, call in call_items:
        raw = _to_float(_first(call, "timestamp", "time", "ts"), 0.0)
        if raw:
            call_times.append(normalized[time_index])
            time_index += 1
        else:
            call_times.append(0.0)

    raw_events: list[dict[str, Any]] = []
    seq = 0

    def append_event(payload: dict[str, Any]) -> None:
        nonlocal seq
        seq += 1
        payload["_seq"] = seq
        raw_events.append(payload)

    for process in processes:
        pid = int(process.get("pid") or 0)
        image = _string(process.get("image"))
        append_event({
            "ts": process_times.get(pid, 0.0),
            "category": "process",
            "action": "create",
            "pid": pid,
            "ppid": process.get("ppid"),
            "image": image,
            "target": image,
            "args": {"command_line": _string(process.get("command_line"))},
            "source": "report:process",
            "confidence": "high",
        })

    for index, (process, call) in enumerate(call_items):
        api = _call_api(call)
        if not api:
            continue
        args = _normalize_args(_first(call, "arguments", "args", "parameters", default={}))
        return_value = _first(call, "return_value", "retval", "return", "ret")
        pid, tid, image, ppid = _call_context(call, process)
        ts = call_times[index] if index < len(call_times) else 0.0
        append_event({
            "ts": ts,
            "category": "api",
            "action": "call",
            "pid": pid,
            "tid": tid,
            "ppid": ppid,
            "image": image,
            "target": api,
            "args": {**args, "api": api, "return_value": return_value},
            "source": "report:api",
            "confidence": "high",
        })
        for semantic in _semantic_events(api, args):
            append_event({
                "ts": ts,
                "category": semantic["category"],
                "action": semantic["action"],
                "pid": pid,
                "tid": tid,
                "ppid": ppid,
                "image": image,
                "target": semantic["target"],
                "args": semantic["args"],
                "source": "report:semantic",
                "confidence": "medium",
            })

    raw_events.sort(key=lambda item: (round(float(item["ts"]), 6), item["_seq"]))
    events: list[Event] = []
    for index, item in enumerate(raw_events, start=1):
        events.append(
            Event(
                id=f"e{index:05d}",
                ts=max(0.0, round(float(item["ts"]), 6)),
                category=str(item["category"]),
                action=str(item["action"]),
                pid=item.get("pid"),
                tid=item.get("tid"),
                ppid=item.get("ppid"),
                image=item.get("image") or None,
                target=item.get("target") or None,
                args=dict(item.get("args") or {}),
                source=str(item.get("source") or "report:unknown"),
                confidence=str(item.get("confidence") or "medium"),
            )
        )
    summary = TraceSummary.from_events(events, dropped=0)
    file_targets: list[str] = []
    for event in events:
        if event.category == "file" and event.action in ("create", "write") and event.target:
            if event.target not in file_targets:
                file_targets.append(event.target)
    summary.dropped_files = file_targets[:50]

    trace = Trace(
        trace_id=new_trace_id(),
        sample=_sample_info(report, source_name),
        engine=EngineInfo(version=__version__, backend="replay", policy="report2trace"),
        sandbox=SandboxInfo(
            host=_sandbox_host(report),
            isolation=["report-replay"],
            limits=SandboxLimits(timeout_s=0, mem_mb=0, cpu_s=0, network="unknown"),
            started_at="",
            ended_at="",
            terminated_by="exited",
        ),
        events=events,
        summary=summary,
        created_at="",
        extra={
            "source_report": source_name,
            "converter": "tools/report2trace.py",
            "format": "cape" if process_calls else "capa",
            "time_mode": time_mode,
            "api_calls": sum(1 for event in events if event.category == "api"),
            "semantic_events": sum(1 for event in events if event.source == "report:semantic"),
            "processes": len(processes),
        },
    )
    trace.sort_events()
    trace.validate()
    return trace


def convert_file(report_path: str | Path, out_path: str | Path | None = None) -> Path:
    """读取报告、转换为 Trace 并落盘；返回输出路径。"""
    source = Path(report_path)
    report = load_report(source)
    trace = convert_report(report, source_name=source.name)
    target = Path(out_path) if out_path is not None else Path("out") / (source.stem + ".trace.json")
    return schema.save(trace, target)


# --------------------------------------------------------------------- 命令行（独立运行）
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="report2trace",
        description="把 CAPE / capa 动态分析报告 JSON 转换为 tianti.trace/1",
    )
    parser.add_argument("report", help="CAPE / capa 动态报告 JSON 路径")
    parser.add_argument("--out", default=None, help="输出 trace JSON（默认 out/<report>.trace.json）")
    args = parser.parse_args(argv)
    try:
        trace = convert_report(load_report(args.report), source_name=Path(args.report).name)
        out = Path(args.out) if args.out else Path("out") / (Path(args.report).stem + ".trace.json")
        path = schema.save(trace, out)
    except TraceError as exc:
        sys.stderr.write(json.dumps(exc.to_dict(), ensure_ascii=False) + chr(10))
        return 1
    print(f"已生成 trace: {path}")
    print(f"事件: {len(trace.events)}  api: {trace.extra.get('api_calls')}  trace_id: {trace.trace_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
