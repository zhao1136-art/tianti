"""天体引擎 CLI 入口（L5）。

命令：version / trace / replay / rules / detectors / report / scan / serve。
编排统一走 tianti.api.pipeline（L5 适配层）；分析模块缺失时输出友好错误（退出码 1）
而不是 traceback。argparse 负责 --help（退出码 0）与未知参数（退出码 2）。
"""

from __future__ import annotations

import argparse
import importlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .core.config import Config
from .core.errors import SampleError, TiantiError
from .trace.normalize import EventBuilder, build_trace
from .trace.schema import SCHEMA_ID, SandboxInfo, Trace

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NOT_IMPLEMENTED = 3  # 保留常量兼容旧导入；M6 起不再有 stub 命令

BACKEND_MODULES = {
    "replay": "tianti.sandbox.replay",
    "containment": "tianti.sandbox.containment",
    "emulation": "tianti.sandbox.emulation",
    "vm": "tianti.sandbox.vm",
}

MAX_DIR_FILES = 200


# --------------------------------------------------------------------- 基础工具
def _fail(message: str, *, hint: str = "", code: int = EXIT_ERROR) -> int:
    sys.stderr.write(f"错误: {message}\n")
    if hint:
        sys.stderr.write(f"提示: {hint}\n")
    return code


def _backend_status() -> dict[str, dict[str, Any]]:
    status: dict[str, dict[str, Any]] = {}
    for name, module_name in BACKEND_MODULES.items():
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            status[name] = {"available": False, "reason": f"模块未实现: {module_name}"}
            continue
        except Exception as exc:  # 导入期异常也要降级，不影响 CLI
            status[name] = {"available": False, "reason": f"导入失败: {exc}"}
            continue
        backend = getattr(module, "BACKEND", None)
        if backend is None or not hasattr(backend, "available"):
            status[name] = {"available": False, "reason": "未导出 BACKEND.available()"}
            continue
        try:
            ok, reason = backend.available()
        except Exception as exc:
            status[name] = {"available": False, "reason": f"检测异常: {exc}"}
            continue
        status[name] = {"available": bool(ok), "reason": str(reason)}
    return status


def _count_files(directory: Path, pattern: str) -> int:
    if not directory.exists():
        return 0
    return sum(1 for _ in directory.rglob(pattern))


def _self_test() -> dict[str, Any]:
    """契约自检：构造一条 trace 并 round-trip。"""
    from .core.model import Sample

    builder = EventBuilder(max_events=8, source="selftest")
    builder.start()
    builder.emit("process", "create", pid=1, image="selftest.exe", target="selftest.exe", source="selftest", confidence="high")
    builder.emit("file", "write", pid=1, target="C:/tianti/selftest.tmp", source="selftest", confidence="medium")
    sample = Sample.from_bytes(b"tianti-selftest", "selftest.bin")
    trace = build_trace(
        sample=sample,
        engine_version=__version__,
        backend="replay",
        policy="selftest",
        sandbox=SandboxInfo(isolation=["selftest"]),
        builder=builder,
    )
    restored = Trace.from_dict(trace.to_dict())
    restored.validate()
    return {
        "ok": restored.to_dict() == trace.to_dict(),
        "events": len(trace.events),
        "schema": SCHEMA_ID,
    }


def _resolve_out_path(value: str | None, *, default_dir: Path, filename: str) -> Path:
    """--out 可给文件路径或目录；无后缀/已存在目录视为目录。"""
    if not value:
        return default_dir / filename
    candidate = Path(value)
    if candidate.is_dir() or not candidate.suffix:
        return candidate / filename
    return candidate


def _result_common_name(default_json_name: str) -> str:
    """demo_ransom.ps1.result.json -> demo_ransom.ps1。"""
    suffix = ".result.json"
    if default_json_name.endswith(suffix):
        return default_json_name[: -len(suffix)]
    return Path(default_json_name).stem


def _result_summary_lines(result: Any) -> list[str]:
    verdict = result.verdict
    lines = [
        f"样本:     {result.sample_name}",
        f"trace_id: {result.trace_id or '—'}",
        f"结论:     {verdict.verdict}（score={verdict.score}，confidence={verdict.confidence}）",
        f"能力命中: {len(result.matches)}  危险行为: {len(result.hits)}",
    ]
    if result.hits:
        lines.append("主要命中:")
        ordered = sorted(
            result.hits,
            key=lambda hit: (0 if hit.suppressed else 1, float(hit.score or 0)),
            reverse=True,
        )
        for hit in ordered[:5]:
            flag = "（已抑制）" if hit.suppressed else ""
            lines.append(f"  - [{hit.severity}] {hit.detector_id} {hit.name} score={hit.score}{flag}")
    for note in result.notes:
        lines.append(f"备注: {note}")
    return lines


def _iter_dir_files(directory: Path) -> list[Path]:
    """递归列出目录下所有文件（排序稳定）；数量上限由 cmd_scan 截断并提示。"""
    return [path for path in sorted(directory.rglob("*")) if path.is_file()]


def _dir_output_stem(relative: Path, index: int) -> str:
    """目录模式的结果文件名主干：序号 + 相对路径，保证不冲突（同名不同目录也唯一）。"""
    from .report import jsonr

    parts = [part for part in relative.parts if part not in ("", ".")]
    joined = "__".join(parts) if parts else "sample"
    return f"{index:04d}__{jsonr.safe_stem(joined)}"


# --------------------------------------------------------------------- version
def cmd_version(args: argparse.Namespace) -> int:
    cfg = Config.default()
    payload: dict[str, Any] = {
        "engine": "天体引擎 / TianTi",
        "version": __version__,
        "schema": SCHEMA_ID,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "root": str(cfg.paths.root),
        "config": {"path": str(cfg.paths.config), "exists": cfg.paths.config.exists()},
        "default_policy": cfg.default_policy,
        "policies": sorted(cfg.policies),
        "counts": {
            "rules": _count_files(cfg.paths.rules, "*.yml") + _count_files(cfg.paths.rules, "*.yaml"),
            "detectors": _count_files(cfg.paths.detectors, "*.yml") + _count_files(cfg.paths.detectors, "*.yaml"),
        },
        "backends": _backend_status(),
    }
    if args.check:
        payload["self_test"] = _self_test()

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return EXIT_OK

    print(f"天体引擎 / TianTi {__version__}")
    print(f"schema:   {SCHEMA_ID}")
    print(f"python:   {platform.python_version()} ({platform.platform()})")
    print(f"root:     {cfg.paths.root}")
    config_state = "存在" if payload["config"]["exists"] else "缺失（使用内置默认值）"
    print(f"config:   {cfg.paths.config} [{config_state}]")
    print(f"policies: {', '.join(payload['policies'])}（默认 {cfg.default_policy}）")
    print(f"rules:    {payload['counts']['rules']} 个文件")
    print(f"detectors:{payload['counts']['detectors']} 个文件")
    print("backends:")
    for name, state in payload["backends"].items():
        flag = "ok  " if state["available"] else "n/a "
        print(f"  {flag}{name:<12} {state['reason']}")
    if args.check:
        self_test = payload["self_test"]
        print(f"self-test: {'ok' if self_test['ok'] else 'FAILED'} ({self_test['events']} events, round-trip)")
    return EXIT_OK


# --------------------------------------------------------------------- trace
def cmd_trace(args: argparse.Namespace) -> int:
    from .api import pipeline

    cfg = Config.load()
    trace, info = pipeline.run_backend(args.path, policy_name=args.policy, config=cfg)
    out = _resolve_out_path(args.out, default_dir=cfg.paths.out, filename=f"{trace.trace_id}.trace.json")
    from .trace import schema

    path = schema.save(trace, out)
    print(f"已产出 trace: {path}")
    print(f"后端: {info.get('backend')}  事件: {len(trace.events)}  trace_id: {trace.trace_id}")
    return EXIT_OK


# --------------------------------------------------------------------- replay
def cmd_replay(args: argparse.Namespace) -> int:
    from .api import pipeline
    from .report import jsonr
    from .trace import schema

    cfg = Config.load()
    trace = schema.load(args.trace)
    result = pipeline.analyze_trace(trace, config=cfg, include_upstream=args.include_upstream)
    if args.format == "json":
        text = jsonr.dumps(result)
        if args.out:
            path = _resolve_out_path(args.out, default_dir=cfg.paths.out, filename=jsonr.result_filename(result.sample_name))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text + "\n", encoding="utf-8")
            print(str(path))
        else:
            print(text)
        return EXIT_OK
    summary = "\n".join(_result_summary_lines(result))
    if args.out:
        path = _resolve_out_path(args.out, default_dir=cfg.paths.out, filename=f"{jsonr.result_filename(result.sample_name)}.txt")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(summary + "\n", encoding="utf-8")
        print(str(path))
    else:
        print(summary)
    return EXIT_OK


# --------------------------------------------------------------------- report
def cmd_report(args: argparse.Namespace) -> int:
    from .report import html, jsonr

    cfg = Config.load()
    result = jsonr.load_result(args.result)
    common = _result_common_name(jsonr.result_filename(result.sample_name))
    out = _resolve_out_path(args.out, default_dir=cfg.paths.out, filename=f"{common}.report.html")
    path = html.save_html(result, out, title=f"天体引擎报告 - {result.sample_name}")
    print(f"已生成 HTML 报告: {path}")
    print(f"结论: {result.verdict.verdict}  score={result.verdict.score}  confidence={result.verdict.confidence}")
    return EXIT_OK


# --------------------------------------------------------------------- scan
def _scan_one(
    path: Path,
    *,
    policy: str | None,
    out_dir: Path,
    fmt: str,
    cfg: Config,
    stem_override: str | None = None,
    include_upstream: bool = False,
    expand_archives: bool = True,
    static_only: bool = False,
    use_cache: bool = True,
) -> list[Path]:
    from .api import pipeline
    from .report import html, jsonr

    result = pipeline.scan_path(
        path,
        policy=policy,
        config=cfg,
        include_upstream=include_upstream,
        expand_archives=expand_archives,
        static_only=static_only,
        use_cache=use_cache,
    )
    common = stem_override or _result_common_name(jsonr.result_filename(result.sample_name))
    written: list[Path] = []
    if fmt in ("json", "both"):
        written.append(jsonr.save_result(result, out_dir / f"{common}.result.json"))
    if fmt in ("html", "both"):
        written.append(html.save_html(result, out_dir / f"{common}.report.html"))
    print(f"[{result.verdict.verdict}] {result.sample_name} score={result.verdict.score} "
          f"matches={len(result.matches)} hits={len(result.hits)}")
    archive = (result.extra or {}).get("archive")
    if isinstance(archive, dict):
        if archive.get("expanded"):
            print(
                f"  压缩包: 已静态分析 {archive.get('count', 0)}/{archive.get('discovered', 0)} 个条目"
                + ("（已截断）" if archive.get("truncated") else "")
            )
        elif archive.get("format") in ("archive/zip", "archive/rar", "archive/7z"):
            print(f"  压缩包: 未展开（{archive.get('format')}），仅归档级静态分析")
    for item in written:
        print(f"  -> {item}")
    return written


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = Config.load()
    target = Path(args.path)
    if not target.exists():
        raise SampleError(f"路径不存在: {target}", path=str(target))
    out_dir = Path(args.out) if args.out else cfg.paths.out
    if target.is_dir():
        all_files = _iter_dir_files(target)
        if not all_files:
            raise SampleError(f"目录下没有可扫描文件: {target}", path=str(target))
        files = all_files[:MAX_DIR_FILES]
        if len(all_files) > MAX_DIR_FILES:
            sys.stderr.write(
                f"警告: 目录下共 {len(all_files)} 个文件，单次最多扫描 {MAX_DIR_FILES} 个；"
                f"其余 {len(all_files) - MAX_DIR_FILES} 个未处理（请缩小目录或分批扫描）\n"
            )
        out_dir.mkdir(parents=True, exist_ok=True)
        failed = 0
        for index, file_path in enumerate(files, start=1):
            relative = file_path.relative_to(target)
            stem_override = _dir_output_stem(relative, index)
            try:
                print(f"[{index}/{len(files)}] 扫描 {file_path}")
                _scan_one(
                    file_path,
                    policy=args.policy,
                    out_dir=out_dir,
                    fmt=args.format,
                    cfg=cfg,
                    stem_override=stem_override,
                    include_upstream=args.include_upstream,
                    expand_archives=not args.no_archive_expand,
                    static_only=args.static_only,
                    use_cache=not args.no_cache,
                )
            except TiantiError as exc:
                failed += 1
                sys.stderr.write(json.dumps(exc.to_dict(), ensure_ascii=False) + "\n")
            except Exception as exc:  # 单文件失败不影响整目录
                failed += 1
                sys.stderr.write(f"错误: 扫描 {file_path} 失败: {exc}\n")
        if failed:
            _fail(f"目录扫描完成，{failed}/{len(files)} 个文件失败", code=EXIT_ERROR)
            return EXIT_ERROR
        return EXIT_OK
    out_dir.mkdir(parents=True, exist_ok=True)
    _scan_one(
        target,
        policy=args.policy,
        out_dir=out_dir,
        fmt=args.format,
        cfg=cfg,
        include_upstream=args.include_upstream,
        expand_archives=not args.no_archive_expand,
        static_only=args.static_only,
        use_cache=not args.no_cache,
    )
    return EXIT_OK


# --------------------------------------------------------------------- rules
def _print_pack_info(info: dict[str, Any], label: str) -> None:
    if info.get("available"):
        print(f"{label}引擎: {info.get('engine') or '已接通'}")
        print(f"数量: {info.get('count', 0)}")
        upstream = info.get("upstream")
        if isinstance(upstream, dict) and upstream.get("requested"):
            if upstream.get("available"):
                print(f"上游规则: 已加载 {upstream.get('files', 0)} 个文件（{upstream.get('path')}）")
            else:
                print(f"上游规则: 未就绪（{upstream.get('reason') or upstream.get('path')}）")
        for name in info.get("rules") or info.get("detectors") or []:
            if name:
                print(f"  - {name}")
        errors = info.get("errors") or []
        unsupported = info.get("unsupported") or []
        if errors:
            print(f"加载错误: {len(errors)} 条")
            for error in errors[:10]:
                print(f"  ! {error}")
        if unsupported:
            print(f"不支持语法: {len(unsupported)} 条")
    else:
        reason = str(info.get("reason", "未知原因"))
        if not reason.startswith(f"{label}引擎"):
            reason = f"{label}引擎尚未接通: {reason}"
        print(reason)
        files = info.get("files") or []
        print(f"已发现 {info.get('count', len(files))} 个{label}文件（未解析）")
        for name in files[:20]:
            print(f"  - {name}")


def cmd_rules(args: argparse.Namespace) -> int:
    from .api import pipeline
    from .trace import schema

    cfg = Config.load()
    if args.action == "list":
        info = pipeline.describe_rules(cfg, include_upstream=args.include_upstream)
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
        else:
            _print_pack_info(info, "规则")
        return EXIT_OK
    if args.action == "validate":
        ok, info = pipeline.validate_rules(cfg, include_upstream=args.include_upstream)
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
        else:
            _print_pack_info(info, "规则")
        if not info.get("available"):
            _fail(str(info.get("reason") or "规则引擎不可用"), hint="规则引擎由 M4（rules）交付；当前只能浏览规则文件")
            return EXIT_ERROR
        if not ok:
            upstream = info.get("upstream") if isinstance(info.get("upstream"), dict) else {}
            if upstream.get("requested") and not upstream.get("available"):
                _fail(
                    str(upstream.get("reason") or "rules/upstream 尚未就绪"),
                    hint="上游规则导入由 rules 负责；去掉 --include-upstream 可只校验本地规则",
                )
                return EXIT_ERROR
            _fail("规则校验失败，详见上方错误")
            return EXIT_ERROR
        print("规则校验通过")
        return EXIT_OK
    if not args.target:
        _fail("rules match 需要 trace 路径", hint="python -m tianti rules match <trace.json>", code=EXIT_USAGE)
        return EXIT_USAGE
    trace = schema.load(args.target)
    matches, note = pipeline.run_rules(trace, config=cfg, include_upstream=args.include_upstream)
    if note and not matches:
        _fail(note, hint="规则引擎由 M4（rules）交付；可先用 replay 查看检测器结果")
        return EXIT_ERROR
    payload = {"count": len(matches), "matches": [match.to_dict() for match in matches]}
    if note:
        payload["warning"] = note
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return EXIT_OK


# --------------------------------------------------------------------- detectors
def cmd_detectors(args: argparse.Namespace) -> int:
    from .api import pipeline
    from .trace import schema

    cfg = Config.load()
    if args.action == "list":
        info = pipeline.describe_detectors(cfg)
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
        else:
            _print_pack_info(info, "检测器")
        return EXIT_OK
    if not args.target:
        _fail("detectors run 需要 trace 路径", hint="python -m tianti detectors run <trace.json>", code=EXIT_USAGE)
        return EXIT_USAGE
    trace = schema.load(args.target)
    hits, note = pipeline.run_detectors(trace, config=cfg)
    if note and not hits:
        _fail(note, hint="检测器由 M5（detect）交付")
        return EXIT_ERROR
    payload = {"count": len(hits), "hits": [hit.to_dict() for hit in hits]}
    if note:
        payload["warning"] = note
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return EXIT_OK


# --------------------------------------------------------------------- convert-cape
def cmd_convert_cape(args: argparse.Namespace) -> int:
    from .trace import schema

    try:
        from tools.report2trace import convert_file
    except ModuleNotFoundError as exc:
        _fail(
            f"报告转换器不可用: {exc}",
            hint="需要仓库根 tools/report2trace.py，并在仓库根运行 python -m tianti",
        )
        return EXIT_ERROR
    cfg = Config.load()
    source = Path(args.report)
    out = Path(args.out) if args.out else cfg.paths.out / (source.stem + ".trace.json")
    path = convert_file(source, out)
    trace = schema.load(path)
    print(f"已生成 trace: {path}")
    print(
        f"事件: {len(trace.events)}  api: {trace.extra.get('api_calls')}  "
        f"sample: {trace.sample.name}  trace_id: {trace.trace_id}"
    )
    return EXIT_OK


# --------------------------------------------------------------------- serve
def cmd_serve(args: argparse.Namespace) -> int:
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        _fail(f"仅允许监听回环地址，拒绝: {args.host}", hint="使用 --host 127.0.0.1")
        return EXIT_ERROR
    from .api import httpd

    httpd.serve(args.host, args.port)
    return EXIT_OK


# --------------------------------------------------------------------- parser
def cmd_gui(args: argparse.Namespace) -> int:
    """启动 Tk 桌面前端（tkinter 缺失时给出可读错误）。"""
    try:
        from .gui.app import main as gui_main
    except ImportError as exc:
        sys.stderr.write(f"当前 Python 缺少 tkinter，无法启动 GUI：{exc}\n")
        return EXIT_ERROR
    argv: list[str] = []
    for name in ("path", "trace", "screenshot"):
        value = getattr(args, name, None)
        if value:
            argv.extend([f"--{name}", str(value)])
    if getattr(args, "demo", False):
        argv.append("--demo")
    if getattr(args, "smoke", False):
        argv.append("--smoke")
    return int(gui_main(argv))

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tianti",
        description="天体引擎：沙箱 + capa 规则能力识别 + 危险行为检测",
    )
    parser.add_argument("--version", action="store_true", help="打印版本后退出")
    sub = parser.add_subparsers(dest="command")

    p_version = sub.add_parser("version", help="版本与环境自检")
    p_version.add_argument("--json", action="store_true", help="以 JSON 输出")
    p_version.add_argument("--check", action="store_true", help="运行契约自检")
    p_version.set_defaults(func=cmd_version)

    p_trace = sub.add_parser("trace", help="只跑沙箱并输出 trace")
    p_trace.add_argument("path", help="样本文件路径")
    p_trace.add_argument("--policy", default=None, help="fast / deep / paranoid")
    p_trace.add_argument("--out", default=None, help="输出文件或目录")
    p_trace.set_defaults(func=cmd_trace)

    p_replay = sub.add_parser("replay", help="回放 trace（规则 / 检测器 / 判定）")
    p_replay.add_argument("trace", help="trace JSON 路径")
    p_replay.add_argument("--policy", default=None, help="覆盖策略档位（仅记录）")
    p_replay.add_argument("--format", default="json", choices=["json", "summary"], help="输出格式")
    p_replay.add_argument("--out", default=None, help="结果输出文件或目录")
    p_replay.add_argument(
        "--include-upstream",
        action="store_true",
        help="加载 rules/upstream 官方 capa 规则（默认关闭，避免影响基线）",
    )
    p_replay.set_defaults(func=cmd_replay)

    p_rules = sub.add_parser("rules", help="规则包管理")
    p_rules.add_argument("action", choices=["list", "validate", "match"], help="list / validate / match")
    p_rules.add_argument("target", nargs="?", help="match 时的 trace 路径")
    p_rules.add_argument("--json", action="store_true", help="以 JSON 输出")
    p_rules.add_argument(
        "--include-upstream",
        action="store_true",
        help="加载 rules/upstream 官方 capa 规则（默认关闭，避免影响基线）",
    )
    p_rules.set_defaults(func=cmd_rules)

    p_detectors = sub.add_parser("detectors", help="检测器管理")
    p_detectors.add_argument("action", choices=["list", "run"], help="list / run")
    p_detectors.add_argument("target", nargs="?", help="run 时的 trace 路径")
    p_detectors.add_argument("--json", action="store_true", help="以 JSON 输出")
    p_detectors.set_defaults(func=cmd_detectors)

    p_report = sub.add_parser("report", help="由结果 JSON 生成单文件 HTML 报告")
    p_report.add_argument("result", help="result JSON 路径")
    p_report.add_argument("--out", default=None, help="HTML 输出文件或目录")
    p_report.add_argument("--html", action="store_true", help="兼容写法：始终生成 HTML")
    p_report.set_defaults(func=cmd_report)

    p_scan = sub.add_parser("scan", help="全流程扫描（文件或目录）")
    p_scan.add_argument("path", help="样本文件或目录")
    p_scan.add_argument("--policy", default=None, help="fast / deep / paranoid")
    p_scan.add_argument("--out", default=None, help="输出目录")
    p_scan.add_argument("--format", default="both", choices=["json", "html", "both"], help="输出格式")
    p_scan.add_argument(
        "--include-upstream",
        action="store_true",
        help="加载 rules/upstream 官方 capa 规则（默认关闭，避免影响基线）",
    )
    p_scan.add_argument(
        "--no-archive-expand",
        action="store_true",
        help="不解压 zip（只看归档级静态信号；默认展开 zip 逐条静态分析）",
    )
    p_scan.add_argument(
        "--static-only",
        action="store_true",
        help="只做静态分析（不执行样本，不跑沙箱）",
    )
    p_scan.add_argument(
        "--no-cache",
        action="store_true",
        help="不使用轨迹缓存（默认命中相同样本 sha256 时复用上次沙箱轨迹，避免重复执行）",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_convert = sub.add_parser("convert-cape", help="把 CAPE / capa 动态报告 JSON 转换为 trace")
    p_convert.add_argument("report", help="CAPE / capa 动态报告 JSON 路径")
    p_convert.add_argument("--out", default=None, help="输出 trace JSON（默认 out/<report>.trace.json）")
    p_convert.set_defaults(func=cmd_convert_cape)

    p_gui = sub.add_parser("gui", help="启动御天分析（Tk 桌面前端）")
    p_gui.add_argument("--path", default=None, help="启动时填入的样本/轨迹路径")
    p_gui.add_argument("--demo", action="store_true", help="加载 golden trace 演示数据")
    p_gui.add_argument("--trace", default=None, help="配合 --demo 指定 trace 文件")
    p_gui.add_argument("--screenshot", default=None, help="渲染后截图保存 PNG（需要 Pillow）")
    p_gui.add_argument("--smoke", action="store_true", help="自检：创建窗口后立即退出")
    p_gui.set_defaults(func=cmd_gui)

    p_serve = sub.add_parser("serve", help="启动本地 HTTP API（127.0.0.1）")
    p_serve.add_argument("--host", default="127.0.0.1", help="仅允许回环地址")
    p_serve.add_argument("--port", type=int, default=8765, help="端口（0 表示随机）")
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        args.json = False
        args.check = False
        return cmd_version(args)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return EXIT_OK
    try:
        return int(func(args))
    except TiantiError as exc:
        sys.stderr.write(json.dumps(exc.to_dict(), ensure_ascii=False) + "\n")
        return EXIT_ERROR
    except ModuleNotFoundError as exc:
        _fail(f"依赖模块缺失: {exc.name or exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        sys.stderr.write("已中断\n")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
