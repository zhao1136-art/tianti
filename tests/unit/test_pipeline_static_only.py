"""非可执行文件回落静态分析（不交给沙箱执行）。"""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from tianti.api import pipeline
from tianti.report import ScanResult


def _minimal_pe64() -> bytes:
    head = bytearray(0x200)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x40).to_bytes(4, "little")
    head[0x40:0x44] = b"PE\x00\x00"
    head[0x44:0x46] = (0x8664).to_bytes(2, "little")
    return bytes(head)


class StaticOnlyScanTests(unittest.TestCase):
    def test_text_file(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "readme.txt"
            path.write_text("hello yutian analysis", encoding="utf-8")
            result = pipeline.scan_path(path)
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(result.extra.get("input"), "static-only")
        self.assertEqual(dict(result.extra.get("backend") or {}).get("backend"), "static")
        self.assertEqual(result.events, [])
        self.assertEqual(result.trace.get("sandbox", {}).get("terminated_by"), "not-executed")
        self.assertTrue(any("静态分析" in note for note in result.notes))

    def test_zip_file(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "sample.zip"
            with zipfile.ZipFile(path, "w") as handle:
                handle.writestr("readme.txt", "hello")
            result = pipeline.scan_path(path)
        self.assertEqual(result.extra.get("input"), "static-only")
        self.assertEqual(result.sample.get("type"), "archive/zip")
        self.assertEqual(result.events, [])

    def test_dll_is_static_only(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "library.dll"
            path.write_bytes(_minimal_pe64())
            result = pipeline.scan_path(path)
        self.assertEqual(result.sample.get("type"), "pe64")
        self.assertEqual(result.extra.get("input"), "static-only")

    def test_executable_still_uses_sandbox(self) -> None:
        """exe 不应被误判成静态-only（这里只验证类型判定，不真的执行）。"""
        from tianti.core.model import Sample

        exe = Sample.from_bytes(_minimal_pe64(), "demo.exe")
        dll = Sample.from_bytes(_minimal_pe64(), "demo.dll")
        self.assertTrue(pipeline.dynamically_executable(exe))
        self.assertFalse(pipeline.dynamically_executable(dll))

    def test_script_type_detection(self) -> None:
        from tianti.core.model import Sample

        ps1 = Sample.from_bytes(b"Write-Host hi", "a.ps1")
        psm1 = Sample.from_bytes(b"function x {}", "a.psm1")
        self.assertTrue(pipeline.dynamically_executable(ps1))
        self.assertFalse(pipeline.dynamically_executable(psm1))


class StaticOnlyModeTests(unittest.TestCase):
    def test_static_only_skips_sandbox(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "demo.exe"
            path.write_bytes(_minimal_pe64())
            result = pipeline.scan_path(path, static_only=True)
        self.assertEqual(result.extra.get("input"), "static-only")
        self.assertEqual(result.events, [])
        self.assertTrue(any("静态模式" in note for note in result.notes))

    def test_fast_policy_disables_registry_snapshot(self) -> None:
        from tianti.core.config import Config

        cfg = Config.default()
        self.assertFalse(cfg.policy("fast").registry_snapshot)
        self.assertTrue(cfg.policy("deep").registry_snapshot)


class TraceCacheTests(unittest.TestCase):
    def test_cache_hit_reuses_trace(self) -> None:
        from tianti.core.config import Config, PathsConfig
        from tianti.core.model import Sample
        from tianti.trace.normalize import EventBuilder, build_trace
        from tianti.trace.schema import SandboxInfo

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            cfg = Config.default()
            cfg.paths = PathsConfig.from_root(root)
            sample_path = root / "hello.ps1"
            sample_path.write_text("Write-Host hi", encoding="utf-8")
            sample = Sample.from_path(sample_path)
            builder = EventBuilder(max_events=10, source="test")
            builder.start()
            builder.emit("process", "create", pid=1, image="powershell.exe", source="test", confidence="high")
            trace = build_trace(
                sample=sample,
                engine_version="0.0-test",
                backend="containment",
                policy="deep",
                sandbox=SandboxInfo(host="test", terminated_by="exited"),
                builder=builder,
            )
            cache_path = pipeline._trace_cache_path(cfg, sample, "deep")
            pipeline._store_cached_trace(trace, cache_path)
            self.assertTrue(cache_path.is_file())

            result = pipeline.scan_path(sample_path, config=cfg)
        backend = dict((result.extra or {}).get("backend") or {})
        self.assertEqual(backend.get("backend"), "cache")
        self.assertTrue(any("轨迹缓存" in note for note in result.notes))

    def test_cli_scan_flags(self) -> None:
        from tianti.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "x.bin", "--static-only", "--no-cache"])
        self.assertTrue(args.static_only)
        self.assertTrue(args.no_cache)


class HarnessFilterTests(unittest.TestCase):
    def _trace(self):
        from tianti.core.model import Sample
        from tianti.trace.normalize import EventBuilder, build_trace
        from tianti.trace.schema import SandboxInfo

        builder = EventBuilder(max_events=10, source="test").start()
        root = builder.emit(
            "process", "create", pid=100, image="powershell.exe",
            target="powershell.exe",
            args={"command_line": 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "x.ps1"'},
            source="test", confidence="high",
        )
        child = builder.emit(
            "process", "create", pid=200, ppid=100, image="cmd.exe", target="cmd.exe",
            args={"command_line": "cmd.exe /c whoami"}, source="test", confidence="high",
        )
        sample = Sample.from_bytes(b"probe", "probe.ps1")
        trace = build_trace(
            sample=sample,
            engine_version="0.0-test",
            backend="containment",
            policy="deep",
            sandbox=SandboxInfo(host="test", terminated_by="exited"),
            builder=builder,
            extra={
                "launch": {
                    "pid": 100,
                    "command_line": 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "x.ps1"',
                }
            },
        )
        return trace, root.id, child.id

    def test_harness_only_match_dropped(self) -> None:
        from tianti.api.pipeline import _filter_harness_matches
        from tianti.rules.base import RuleMatch

        trace, root_id, child_id = self._trace()
        harness_match = RuleMatch(name="绕过执行策略", evidence={"string: /ExecutionPolicy Bypass/": [root_id]})
        real_match = RuleMatch(name="创建子进程", evidence={"process: cmd.exe": [child_id]})
        mixed_match = RuleMatch(name="混合证据", evidence={"a": [root_id], "b": [child_id]})
        kept, dropped = _filter_harness_matches(trace, [harness_match, real_match, mixed_match])
        self.assertEqual(dropped, 1)
        self.assertEqual([m.name for m in kept], ["创建子进程", "混合证据"])

    def test_no_launch_info_keeps_all(self) -> None:
        from tianti.api.pipeline import _filter_harness_matches
        from tianti.core.model import Sample
        from tianti.rules.base import RuleMatch
        from tianti.trace.normalize import EventBuilder, build_trace
        from tianti.trace.schema import SandboxInfo

        builder = EventBuilder(max_events=5, source="test").start()
        event = builder.emit("process", "create", pid=1, image="x.exe", source="test", confidence="high")
        trace = build_trace(
            sample=Sample.from_bytes(b"x", "x.exe"),
            engine_version="0.0-test",
            backend="replay",
            policy="deep",
            sandbox=SandboxInfo(host="test", terminated_by="exited"),
            builder=builder,
        )
        match = RuleMatch(name="x", evidence={"k": [event.id]})
        kept, dropped = _filter_harness_matches(trace, [match])
        self.assertEqual(dropped, 0)
        self.assertEqual(len(kept), 1)
