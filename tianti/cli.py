"""天体引擎 CLI 入口。

M0 只实现 version / --help；其余命令返回 EXIT_NOT_IMPLEMENTED 并提示对应里程碑，
由 delivery 在 M6 接管实现。
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
from .core.errors import TiantiError
from .trace.normalize import EventBuilder, build_trace
from .trace.schema import SCHEMA_ID, SandboxInfo, Trace

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_IMPLEMENTED = 3

BACKEND_MODULES = {
    "replay": "tianti.sandbox.replay",
    "containment": "tianti.sandbox.containment",
    "emulation": "tianti.sandbox.emulation",
    "vm": "tianti.sandbox.vm",
}


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
    builder.emit("file", "write", pid=1, target="C:\\tianti\\selftest.tmp", source="selftest", confidence="medium")
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


_STUB_HINTS = {
    "scan": "M6（delivery）",
    "trace": "M3（sandbox）",
    "replay": "M2/M4/M5（sandbox/rules/detect）",
    "rules": "M4（rules）",
    "detectors": "M5（detect）",
    "report": "M6（delivery）",
    "serve": "M6（delivery）",
}


def cmd_stub(args: argparse.Namespace) -> int:
    hint = _STUB_HINTS.get(args.command, "后续里程碑")
    sys.stderr.write(
        f"命令 '{args.command}' 尚未实现（计划 {hint}）。\n"
        f"当前可用：python -m tianti version [--json] [--check]\n"
    )
    return EXIT_NOT_IMPLEMENTED


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

    p_scan = sub.add_parser("scan", help="[M6] 全流程扫描（文件或目录）")
    p_scan.add_argument("path")
    p_scan.add_argument("--policy", default=None, help="fast / deep / paranoid")
    p_scan.add_argument("--out", default=None, help="输出目录")
    p_scan.add_argument("--format", default="both", choices=["json", "html", "both"])
    p_scan.set_defaults(func=cmd_stub)

    p_trace = sub.add_parser("trace", help="[M3] 只跑沙箱并输出 trace")
    p_trace.add_argument("path")
    p_trace.add_argument("--policy", default=None)
    p_trace.add_argument("--out", default=None)
    p_trace.set_defaults(func=cmd_stub)

    p_replay = sub.add_parser("replay", help="[M2] 回放 trace（规则/检测器/判定）")
    p_replay.add_argument("trace")
    p_replay.add_argument("--policy", default=None)
    p_replay.add_argument("--format", default="json", choices=["json", "summary"])
    p_replay.set_defaults(func=cmd_stub)

    p_rules = sub.add_parser("rules", help="[M4] 规则包管理")
    p_rules.add_argument("action", choices=["list", "validate", "match"])
    p_rules.add_argument("target", nargs="?")
    p_rules.set_defaults(func=cmd_stub)

    p_detectors = sub.add_parser("detectors", help="[M5] 检测器管理")
    p_detectors.add_argument("action", choices=["list", "run"])
    p_detectors.add_argument("target", nargs="?")
    p_detectors.set_defaults(func=cmd_stub)

    p_report = sub.add_parser("report", help="[M6] 生成 HTML 报告")
    p_report.add_argument("result")
    p_report.add_argument("--out", default=None)
    p_report.set_defaults(func=cmd_stub)

    p_serve = sub.add_parser("serve", help="[M6] 启动本地 API")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.set_defaults(func=cmd_stub)

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
    except KeyboardInterrupt:
        sys.stderr.write("已中断\n")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
