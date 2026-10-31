"""M3 containment 沙箱集成测试 + 观测组件单元测试。

安全边界：只执行 samples/sim/ 下的无害模拟脚本（scripts 均为自写、无恶意行为）。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path

from tianti.core.model import Sample
from tianti.sandbox import netmon, snapshot, telemetry_etw, watchdog
from tianti.sandbox.base import SandboxPolicy
from tianti.sandbox.containment import BACKEND, ContainmentBackend
from tianti.trace import schema

ROOT = Path(__file__).resolve().parents[2]
SIM = ROOT / "samples" / "sim"


def _skip_reason() -> str | None:
    if os.name != "nt":
        return "containment 仅支持 Windows"
    ok, reason = BACKEND.available()
    return None if ok else reason


SKIP = _skip_reason()


@unittest.skipIf(SKIP, SKIP or "")
class ContainmentIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="tianti_it_"))
        cls.backend = ContainmentBackend(use_etw=False, keep_workdir=True)
        for name in ("hello.ps1", "sleep_timeout.ps1", "net_probe.ps1", "low_integrity_probe.ps1"):
            assert (SIM / name).is_file(), f"缺少模拟样本: {name}"

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _run(self, name: str, *, timeout_s: int = 20):
        policy = SandboxPolicy(
            name="deep",
            timeout_s=timeout_s,
            mem_mb=512,
            cpu_s=10,
            network="blocked",
            workdir_root=self.tmp,
        )
        started = time.monotonic()
        trace = self.backend.run(Sample.from_path(SIM / name), policy)
        elapsed = time.monotonic() - started
        trace.validate()
        return trace, elapsed

    def _assert_no_residual(self, trace) -> None:
        """后端返回后，Trace 中记录的所有进程都必须已退出（无孤儿/残留）。"""
        pids = {
            int(event.pid)
            for event in trace.events
            if event.category == "process" and event.action == "create" and event.pid
        }
        alive = sorted(pid for pid in pids if watchdog.is_alive(pid))
        self.assertEqual(alive, [], f"后端返回后仍有残留进程: {alive}")
        hard_kill = trace.extra.get("hard_kill_watchdog") or {}
        self.assertFalse(hard_kill.get("fired"), f"硬杀看门狗被触发（主等待可能挂起）: {hard_kill}")
        cleanup = trace.extra.get("isolation_cleanup") or {}
        self.assertEqual(cleanup.get("errors"), [], f"防火墙规则清理失败: {cleanup}")
        self.assertEqual(len(cleanup.get("rules_removed") or []), 2, f"防火墙规则未完成清理: {cleanup}")

    def test_hello_produces_valid_trace(self) -> None:
        trace, elapsed = self._run("hello.ps1")
        self.assertEqual(trace.engine.backend, "containment")
        self.assertEqual(trace.sandbox.terminated_by, "exited")
        categories = {event.category for event in trace.events}
        self.assertIn("process", categories)
        self.assertIn("file", categories)
        self.assertTrue(trace.sandbox.isolation, "sandbox.isolation 不能为空")
        for item in (
            "restricted_token",
            "integrity:low",
            "job_object",
            "fw_block_out",
            "fw_block_in",
            "workdir_redirect",
        ):
            self.assertIn(item, trace.sandbox.isolation)
        self.assertTrue(
            any(e.category == "process" and e.action == "create" and e.pid for e in trace.events),
            "缺少 process create 事件",
        )
        self.assertTrue(
            any("hello.txt" in (e.target or "") for e in trace.events if e.category == "file"),
            "缺少 hello.txt 的 file 事件",
        )
        self.assertTrue(any("payload.bin" in p for p in trace.summary.dropped_files))
        launch = trace.extra.get("launch") or {}
        self.assertIn("hello.ps1", launch.get("command_line", ""))
        self.assertTrue(str(launch.get("image", "")).lower().endswith("powershell.exe"))
        self.assertIsInstance(launch.get("pid"), int)
        self.assertLess(elapsed, 30.0)
        self._assert_no_residual(trace)
        json.dumps(trace.to_dict(), ensure_ascii=False)

    def test_timeout_kills_process_tree(self) -> None:
        trace, elapsed = self._run("sleep_timeout.ps1", timeout_s=1)
        self.assertEqual(trace.sandbox.terminated_by, "timeout")
        self.assertLess(elapsed, 30.0)
        self._assert_no_residual(trace)

    def test_network_blocked_by_firewall(self) -> None:
        trace, elapsed = self._run("net_probe.ps1")
        self.assertIn("fw_block_out", trace.sandbox.isolation)
        self.assertIn("fw_block_in", trace.sandbox.isolation)
        workdir = Path(trace.extra["workdir"])
        results = list(workdir.rglob("net_result.txt"))
        self.assertTrue(results, "net_probe 未写出 net_result.txt")
        content = results[0].read_text(encoding="utf-8-sig").strip()
        self.assertTrue(content.startswith("blocked"), f"外联未被阻断: {content[:200]}")
        self.assertLess(elapsed, 30.0)
        self._assert_no_residual(trace)

    def test_low_integrity_limits_write_not_read_or_execute(self) -> None:
        """integrity:low：写系统目录被拒；读/执行不受限；工作目录写入正常。"""
        probe = Path(r"C:\Windows\tianti_sandbox_lowil_probe.txt")
        self.addCleanup(lambda: probe.unlink() if probe.exists() else None)
        trace, elapsed = self._run("low_integrity_probe.ps1")
        self.assertIn("integrity:low", trace.sandbox.isolation)
        workdir = Path(trace.extra["workdir"])
        result = workdir / "low_integrity.result"
        self.assertTrue(result.is_file(), "低完整性样本未写出 low_integrity.result")
        lines = {line.strip() for line in result.read_text(encoding="utf-8-sig").splitlines() if line.strip()}
        self.assertIn("system_write=blocked", lines, f"低完整性未阻止系统目录写入: {sorted(lines)}")
        self.assertIn("system_read=ok", lines, f"低完整性不应阻止读: {sorted(lines)}")
        self.assertIn("workdir_write=ok", lines, f"低完整性工作目录写入失败: {sorted(lines)}")
        self.assertIn("child_execute=ok", lines, f"低完整性不应阻止执行: {sorted(lines)}")
        self.assertFalse(probe.exists(), "系统目录探针文件不应存在")
        self.assertLess(elapsed, 30.0)
        self._assert_no_residual(trace)

    @unittest.skipUnless(
        os.environ.get("TIANTI_TEST_DLL_LOADING") == "1",
        "DLL 动态加载实验默认关闭：rundll32 调用任意导出会崩溃，且与 explorer 崩溃循环时间重合",
    )
    def test_dll_sample_runs_via_rundll32(self) -> None:
        """DLL 样本应通过 rundll32.exe 动态加载，产出合法 Trace 且无残留进程（需显式开启）。"""
        version_dll = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "version.dll"
        if not version_dll.is_file():
            self.skipTest("系统缺少 version.dll")
        policy = SandboxPolicy(
            name="dll",
            timeout_s=5,
            mem_mb=512,
            cpu_s=5,
            network="blocked",
            workdir_root=self.tmp,
        )
        started = time.monotonic()
        trace = self.backend.run(Sample.from_path(version_dll), policy)
        elapsed = time.monotonic() - started
        trace.validate()

        process_creates = [
            event for event in trace.events if event.category == "process" and event.action == "create"
        ]
        self.assertTrue(process_creates, "DLL 执行缺少 process create 事件")
        self.assertIn(
            trace.sandbox.terminated_by,
            ("exited", "timeout", "killed"),
            f"terminated_by 异常: {trace.sandbox.terminated_by}",
        )

        loader = trace.extra.get("dll_loader") or {}
        self.assertEqual(loader.get("launcher"), "rundll32")
        export = loader.get("export")
        self.assertIsInstance(export, str)
        self.assertTrue(export)
        launch = trace.extra.get("launch") or {}
        command_line = str(launch.get("command_line", ""))
        self.assertIn("rundll32", command_line.lower())
        self.assertIn("," + export, command_line)
        self.assertIn("version.dll", command_line)
        self.assertLess(elapsed, 30.0)
        self._assert_no_residual(trace)
        json.dumps(trace.to_dict(), ensure_ascii=False)


class SnapshotTests(unittest.TestCase):
    def test_file_snapshot_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "keep.txt").write_text("same", encoding="utf-8")
            (root / "modify.txt").write_text("before", encoding="utf-8")
            (root / "remove.txt").write_text("bye", encoding="utf-8")
            before = snapshot.snapshot_tree(root)

            (root / "modify.txt").write_text("after-much-longer", encoding="utf-8")
            (root / "remove.txt").unlink()
            (root / "new.bin").write_bytes(b"B" * 256)
            after = snapshot.snapshot_tree(root)

            changes = {change.rel_path: change for change in snapshot.diff_files(before, after, root=root)}
            self.assertEqual(changes["modify.txt"].change, "modified")
            self.assertEqual(changes["remove.txt"].change, "deleted")
            self.assertEqual(changes["new.bin"].change, "created")
            self.assertEqual(changes["new.bin"].size, 256)
            self.assertEqual(len(changes["new.bin"].sha256), 64)
            self.assertNotIn("keep.txt", changes)

    def test_entropy_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            low = Path(tmp) / "low.bin"
            low.write_bytes(b"\x00" * 4096)
            self.assertEqual(snapshot.file_entropy(low), 0.0)
            high = Path(tmp) / "high.bin"
            high.write_bytes(bytes(range(256)) * 16)
            self.assertGreater(snapshot.file_entropy(high), 7.9)

    def test_registry_parse_and_diff(self) -> None:
        base = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        before = snapshot.parse_reg_export(
            "Windows Registry Editor Version 5.00\n\n"
            f"[{base.replace('HKCU', 'HKEY_CURRENT_USER')}]\n"
            '"keep"="1"\n"change"="old"\n"gone"="x"\n'
        )
        after = snapshot.parse_reg_export(
            "Windows Registry Editor Version 5.00\n\n"
            f"[{base.replace('HKCU', 'HKEY_CURRENT_USER')}]\n"
            '"keep"="1"\n"change"="new"\n"created"="y"\n'
        )
        self.assertIn(base, before)
        self.assertEqual(before[base]["change"], '"old"')
        changes = snapshot.diff_registry(before, after)
        kinds = {(change.target, change.change) for change in changes}
        self.assertIn((base + r"\change", "modified"), kinds)
        self.assertIn((base + r"\created", "created"), kinds)
        self.assertIn((base + r"\gone", "deleted"), kinds)
        self.assertEqual(len(changes), 3)


class WatchdogTests(unittest.TestCase):
    def test_list_processes_contains_self(self) -> None:
        self.assertIn(os.getpid(), watchdog.list_processes())

    def test_kill_tree_removes_grandchildren(self) -> None:
        child_code = "import time; time.sleep(30)"
        parent_code = (
            "import subprocess, sys, time; "
            f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            "time.sleep(30)"
        )
        process = subprocess.Popen([sys.executable, "-c", parent_code])
        grandchildren: list[int] = []
        try:
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                grandchildren = watchdog.descendants(process.pid)
                if grandchildren:
                    break
                time.sleep(0.1)
            self.assertTrue(watchdog.is_alive(process.pid))
            killed = watchdog.kill_tree(process.pid)
            process.wait(timeout=15)
            self.assertIsNotNone(process.poll())
            # 用“root 的后代集合是否为空”判定，避免 PID 复用导致的误报
            deadline = time.monotonic() + 5.0
            remaining = watchdog.descendants(process.pid)
            while remaining and time.monotonic() < deadline:
                time.sleep(0.1)
                remaining = watchdog.descendants(process.pid)
            self.assertEqual(remaining, [], f"孙进程未被清理: {remaining}")
            self.assertTrue(killed, "kill_tree 未报告任何被终止进程")
        finally:
            if process.poll() is None:
                process.kill()


class NetmonTests(unittest.TestCase):
    def test_tcp_connections_shape(self) -> None:
        rows = netmon.tcp_connections()
        self.assertIsInstance(rows, list)
        for row in rows[:5]:
            self.assertGreaterEqual(row.pid, 0)
            self.assertIsInstance(row.remote_addr, str)

    def test_empty_pid_set_never_collects_whole_system(self) -> None:
        monitor = netmon.NetMonitor()
        self.assertEqual(monitor.poll(set()), [])
        self.assertEqual(monitor.poll({999999}), [])


class EtwTests(unittest.TestCase):
    XML = (
        "<Events>"
        "<Event><System>"
        '<Provider Guid="{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"/>'
        "<EventID>1</EventID>"
        '<TimeCreated SystemTime="2026-10-24T10:00:00.5000000+08:00"/>'
        '<Execution ProcessID="123" ThreadID="4"/>'
        "</System><EventData>"
        '<Data Name="ImageName">C:\\Windows\\System32\\cmd.exe</Data>'
        '<Data Name="ParentProcessID">99</Data>'
        "</EventData></Event>"
        "<Event><System>"
        '<Provider Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}"/>'
        "<EventID>13</EventID>"
        '<TimeCreated SystemTime="2026-10-24T10:00:01.2500000+08:00"/>'
        '<Execution ProcessID="123" ThreadID="5"/>'
        "</System><EventData>"
        '<Data Name="FileName">C:\\work\\dropped.bin</Data>'
        "</EventData></Event>"
        "<Event><System>"
        '<Provider Guid="{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}"/>'
        "<EventID>3006</EventID>"
        '<TimeCreated SystemTime="2026-10-24T10:00:02.0000000+08:00"/>'
        '<Execution ProcessID="123" ThreadID="6"/>'
        "</System><EventData>"
        '<Data Name="QueryName">example.test</Data>'
        "</EventData></Event>"
        "</Events>"
    )

    def test_parse_events_xml(self) -> None:
        t0 = datetime.fromisoformat("2026-10-24T10:00:00+08:00")
        events, meta = telemetry_etw.parse_events_xml(self.XML, t0=t0)
        self.assertEqual(meta["total"], 3)
        self.assertEqual(meta["mapped"], 3)
        self.assertEqual([event.category for event in events], ["process", "file", "network"])
        self.assertEqual(events[0].action, "create")
        self.assertTrue((events[0].target or "").endswith("cmd.exe"))
        self.assertAlmostEqual(events[0].ts, 0.5)
        self.assertEqual(events[1].action, "write")
        self.assertAlmostEqual(events[2].ts, 2.0)
        self.assertEqual(events[2].action, "dns")

    def test_parse_bad_xml_raises(self) -> None:
        with self.assertRaises(telemetry_etw.EtwUnavailable):
            telemetry_etw.parse_events_xml("<Events><broken>")

    def test_available_returns_tuple(self) -> None:
        ok, reason = telemetry_etw.available()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(reason, str)


if __name__ == "__main__":
    unittest.main()


class TempRedirectTests(unittest.TestCase):
    """TEMP/TMP 重定向到 work/_tmp 后，样本写临时文件应产生 file 事件。"""

    def test_temp_redirect_produces_file_events(self) -> None:
        import os
        import tempfile

        from tianti.core.config import Config
        from tianti.core.model import Sample
        from tianti.sandbox.base import SandboxPolicy
        from tianti.sandbox.containment import ContainmentBackend

        root = Path(tempfile.mkdtemp(prefix="tianti_temp_redirect_"))
        sample_path = root / "probe.ps1"
        sample_path.write_text(
            'Set-Content -Path "$env:TEMP\\\\probe_tmp.txt" -Value "hello-temp"\n'
            'Set-Content -Path ".\\\\probe_cwd.txt" -Value "hello-cwd"\n',
            encoding="utf-8",
        )
        try:
            policy = SandboxPolicy.from_config(Config.load().policy("deep"), workdir_root=root / "work")
            trace = ContainmentBackend().run(Sample.from_path(sample_path), policy)
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)

        env = dict((trace.extra or {}).get("env") or {})
        self.assertIn("_tmp", str(env.get("TEMP", "")), "TEMP 应被重定向到 work/_tmp")
        file_events = [e for e in trace.events if e.category == "file"]
        targets = [str(e.target or "") for e in file_events]
        self.assertTrue(any("_tmp" in t and "probe_tmp.txt" in t for t in targets), targets)
        self.assertTrue(any("probe_cwd.txt" in t for t in targets), targets)
        self.assertGreaterEqual(trace.summary.file_writes, 2)
