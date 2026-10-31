r"""安全红线测试（沙箱相关）。

红线来源：docs/THREAT_MODEL.md §4 / docs/PLAN.md §4.6。
  R1 只跑无害模拟脚本（本文件用 samples/sim 下自写 sim_* 脚本）。
  R2 沙箱默认断网；断网失败 -> fail-closed，不执行样本。
  R3 所有执行有超时；超时/异常必须杀掉整个进程树、无残留。
  R4 系统目录写入必须被限制或被记录（不得静默放行）。

组织：
  * SampleCorpusSafetyTests：始终运行——校验 sim/benign 语料本身无害（无下载器、
    无破坏性命令、无 .exe）；这是其他红线用例的安全前提。
  * PolicyRedlineDefaultsTests：始终运行——默认策略必须断网 + 有限超时。
  * ContainmentRedlineTests：依赖 tianti.sandbox.containment。
    containment 未就绪（模块缺失 / available()=False）时按 README 约定 skip，
    skip 原因以"未就绪:"开头；一旦后端可用但行为违反红线则判失败并报 sandbox owner。

运行：
  & $PY -m unittest tests.integration.test_redline -v

安全说明：本文件只会执行 samples/sim 下自写的无害模拟脚本；探测系统目录写入时
只创建 C:\Windows\tianti_qa_redline_probe.txt 并在测试结束清理。
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from typing import Any

from tianti.core.config import Config
from tianti.core.errors import SandboxError, SandboxUnavailable
from tianti.core.model import Sample
from tianti.sandbox.base import SandboxPolicy
from tianti.trace.schema import validate_payload
from tests import qa_helpers as qa

SYSTEM_PROBE = Path(r"C:\Windows\tianti_qa_redline_probe.txt")

# 隔离列表里可接受的"网络已阻断"标记（大小写不敏感，任一命中即可）
NETWORK_BLOCK_TOKENS = (
    "fw_block_out",
    "firewall",
    "block_out",
    "network_block",
    "net_block",
    "network_blocked",
    "appcontainer",
)

# fail-closed 故障注入候选函数名（先按显式清单找，再按名字模糊找）
NETWORK_HOOK_NAMES = (
    "block_program_network",
    "install_firewall_block",
    "apply_network_block",
    "enforce_network_block",
    "block_network",
    "_block_network",
    "_install_firewall_block",
    "_apply_firewall_block",
)

_BACKEND: Any = None
_BACKEND_REASON: str = ""
_BACKEND_PROBED = False


def containment() -> tuple[Any, str]:
    """带缓存的 containment 后端探测。"""
    global _BACKEND, _BACKEND_REASON, _BACKEND_PROBED
    if not _BACKEND_PROBED:
        _BACKEND, _BACKEND_REASON = qa.containment_backend()
        _BACKEND_PROBED = True
    return _BACKEND, _BACKEND_REASON


def _cleanup_system_probe() -> None:
    try:
        if SYSTEM_PROBE.exists() and SYSTEM_PROBE.is_file():
            text = SYSTEM_PROBE.read_text(encoding="utf-8", errors="replace")
            if "tianti qa redline probe" in text.lower():
                SYSTEM_PROBE.unlink()
    except OSError:
        pass


def _run_sim(
    testcase: unittest.TestCase,
    script_name: str,
    *,
    timeout_s: int = 8,
    network: str = "blocked",
) -> tuple[Any, Path]:
    """在 containment 中运行 samples/sim 下的无害脚本，返回 (trace, workdir)。"""
    backend, reason = containment()
    if backend is None:
        testcase.skipTest(reason)

    script = qa.SIM_SAMPLES / script_name
    if not script.exists():
        testcase.fail(f"缺少模拟样本 {script}（QA 语料未就位）")

    workdir = Path(tempfile.mkdtemp(prefix="tianti_redline_"))
    testcase.addCleanup(qa.safe_rmtree, workdir)

    sample = Sample.from_path(script)
    policy = SandboxPolicy(
        name="qa-redline",
        timeout_s=timeout_s,
        mem_mb=256,
        cpu_s=5,
        network=network,
        max_events=50000,
        backend="containment",
        workdir_root=workdir,
        registry_etw=False,  # 红线计时不应包含 ETW 采集/tracerpt 开销
    )
    started = time.monotonic()
    try:
        trace = backend.run(sample, policy)
    except SandboxUnavailable as exc:
        testcase.skipTest(f"{qa.SKIP_PREFIX}: containment.run 不可用: {exc}")
    except Exception as exc:  # 后端崩溃属于红线问题，必须报给 sandbox owner
        testcase.fail(f"containment.run 异常（{type(exc).__name__}: {exc}）")
    elapsed = time.monotonic() - started

    testcase.assertIsNotNone(trace, "containment.run 返回 None")
    testcase.assertLess(
        elapsed,
        timeout_s + 15.0,
        f"单次执行耗时 {elapsed:.1f}s，远超策略超时 {timeout_s}s（watchdog 可能失效）",
    )
    errors = validate_payload(trace.to_dict())
    testcase.assertEqual(errors, [], f"containment 产出的 Trace 不合法: {errors}")
    testcase.assertTrue(trace.events, "containment 未产出任何事件")
    return trace, workdir


def _find_marker(workdir: Path, filename: str) -> Path | None:
    roots = [workdir, qa.ROOT / "work"]
    for root in roots:
        if not Path(root).exists():
            continue
        matches = sorted(Path(root).rglob(filename))
        if matches:
            return matches[0]
    return None


class SampleCorpusSafetyTests(unittest.TestCase):
    """R1 前提：语料自己必须无害；始终运行。"""

    # 360 HIPS 会删除含密集恶意命令字面量的 .py，这里用字符串拼接降低误杀风险
    FORBIDDEN_TOKENS = (
        "download" + "string",
        "invoke-" + "webrequest",
        "start-" + "bitstransfer",
        "bits" + "admin",
        "ms" + "hta",
        "certutil " + "-urlcache",
        "format " + "c:",
        "format " + "d:",
        "vss" + "admin delete",
        "bcd" + "edit",
        "disk" + "part",
        "remove-item -path c:\\ " + "-recurse",
        "cipher " + "/w:c:",
    )

    def _scripts(self) -> list[Path]:
        if not qa.SIM_SAMPLES.exists():
            self.fail("samples/sim 不存在")
        return sorted(
            path
            for path in qa.SIM_SAMPLES.rglob("*")
            if path.is_file() and path.suffix.lower() in {".ps1", ".vbs", ".bat", ".cmd", ".js"}
        )

    def test_sim_scripts_exist_and_are_small(self) -> None:
        scripts = self._scripts()
        self.assertGreaterEqual(len(scripts), 3, "samples/sim 至少需要 3 个模拟脚本")
        for path in scripts:
            with self.subTest(script=path.name):
                self.assertLess(path.stat().st_size, 64 * 1024, "模拟脚本不应过大")

    def test_sim_corpus_contains_no_executables(self) -> None:
        if not qa.SIM_SAMPLES.exists():
            self.fail("samples/sim 不存在")
        bad = [p.name for p in qa.SIM_SAMPLES.rglob("*") if p.suffix.lower() in {".exe", ".dll", ".scr", ".com"}]
        self.assertEqual(bad, [], f"samples/sim 不允许出现可执行文件: {bad}")

    def test_qa_sim_scripts_have_safety_banner(self) -> None:
        for path in self._scripts():
            if not path.name.startswith("sim_"):
                continue  # 其他 owner 的样本只做公共安全扫描
            with self.subTest(script=path.name):
                head = "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[:30])
                self.assertIn("SIMULATION ONLY", head, "sim_* 脚本头部必须有 SIMULATION ONLY 安全声明")
                self.assertIn("无害", head, "sim_* 脚本头部必须声明无害用途")

    def test_sim_corpus_has_no_download_or_destructive_commands(self) -> None:
        for path in self._scripts():
            with self.subTest(script=path.name):
                text = path.read_text(encoding="utf-8", errors="replace").lower().replace("\n", " ")
                for token in self.FORBIDDEN_TOKENS:
                    self.assertNotIn(token, text, f"{path.name} 含高危模式 {token!r}，禁止进入语料")

    def test_benign_corpus_is_safe(self) -> None:
        if not qa.BENIGN_SAMPLES.exists():
            self.fail("samples/benign 不存在")
        files = [p for p in qa.BENIGN_SAMPLES.iterdir() if p.is_file() and p.name not in {".gitignore"}]
        self.assertGreaterEqual(len(files), 2, "samples/benign 至少需要 2 个样本")
        self.assertTrue((qa.BENIGN_SAMPLES / "readme.txt").exists(), "benign 语料需有 readme.txt")
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace").lower().replace("\n", " ")
            for token in self.FORBIDDEN_TOKENS:
                self.assertNotIn(token, text, f"{path.name} 含高危模式")

    def test_benign_zip_is_not_zip_bomb(self) -> None:
        archive = qa.BENIGN_SAMPLES / "benign_data.zip"
        if not archive.exists():
            self.skipTest(f"{qa.SKIP_PREFIX}: benign_data.zip 未生成（可用 Python zipfile 生成）")
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            self.assertTrue(infos, "benign zip 不能为空")
            total_size = sum(info.file_size for info in infos)
            self.assertLess(total_size, 10 * 1024 * 1024, "benign zip 解压后过大")
            for info in infos:
                name = info.filename.replace("\\", "/")
                self.assertFalse(name.startswith("/"), f"zip 含绝对路径: {name}")
                self.assertNotIn("..", name.split("/"), f"zip 含路径穿越: {name}")
                self.assertLess(info.compress_size or 1, 5 * 1024 * 1024)


class PolicyRedlineDefaultsTests(unittest.TestCase):
    """R2/R3 策略默认值：始终运行（不依赖沙箱实现）。"""

    def test_all_default_policies_block_network_and_have_timeout(self) -> None:
        cfg = Config.default()
        self.assertTrue(cfg.policies, "至少需要一个默认策略档位")
        for name, policy in cfg.policies.items():
            with self.subTest(policy=name):
                self.assertEqual(policy.network, "blocked", f"{name} 策略必须默认断网")
                self.assertGreater(policy.timeout_s, 0, f"{name} 必须设置执行超时")
                self.assertLessEqual(policy.timeout_s, 60, f"{name} 超时过长（红线要求有限超时）")
                self.assertGreater(policy.cpu_s, 0)
                self.assertGreater(policy.mem_mb, 0)
                self.assertGreater(policy.max_events, 0)

    def test_golden_traces_declare_isolation(self) -> None:
        for path in qa.golden_trace_paths():
            payload = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(trace=path.name):
                self.assertTrue(payload["sandbox"]["isolation"], "golden trace 必须声明隔离列表")
                self.assertEqual(payload["sandbox"]["limits"]["network"], "blocked")


class ContainmentRedlineTests(unittest.TestCase):
    """R2/R3/R4：containment 就绪后必须通过；未就绪则 skip。"""

    def test_system_dir_write_is_restricted_or_recorded(self) -> None:
        """R4：写 C:\\Windows\\ 必须被限制，或被记录为可审计事件。"""
        _cleanup_system_probe()
        self.addCleanup(_cleanup_system_probe)

        trace, workdir = _run_sim(self, "sim_redline_system_write.ps1", timeout_s=15)
        created = SYSTEM_PROBE.exists()
        system_write_events = [
            event
            for event in trace.events
            if event.category == "file"
            and event.action in {"write", "create", "open"}
            and "\\windows" in (event.target or "").lower()
        ]
        if created:
            # 这是测试探针，确认内容后立刻清理
            content = SYSTEM_PROBE.read_text(encoding="utf-8", errors="replace")
            self.assertIn("tianti qa redline probe", content.lower())
            self.assertTrue(
                system_write_events,
                "写系统目录既未被阻止，也没有被记录（红线 R4 违反）",
            )
        # 未被阻止但有事件记录 -> 通过；被阻止 -> 通过

    def test_child_process_is_observed_and_tree_terminated(self) -> None:
        """进程创建必须被观测，且后端返回后不得有残留子进程。"""
        trace, workdir = _run_sim(self, "sim_spawn_child.ps1", timeout_s=6)
        process_creates = [
            event for event in trace.events if event.category == "process" and event.action == "create"
        ]
        self.assertTrue(process_creates, "未观测到 process/create 事件（子进程行为未被记录）")
        joined = " ".join(
            ((event.image or "") + " " + (event.target or "")).lower() for event in process_creates
        )
        self.assertIn("powershell", joined, "未观测到脚本启动的 powershell 子进程")

        # 1) 轨迹内：所有创建进程都必须有对应退出事件（进程树完整终止）
        created_pids = {
            event.pid for event in process_creates if isinstance(event.pid, int)
        }
        exited_pids = {
            event.pid
            for event in trace.events
            if event.category == "process" and event.action == "exit" and isinstance(event.pid, int)
        }
        if created_pids:
            missing = created_pids - exited_pids
            self.assertEqual(
                missing,
                set(),
                f"以下 pid 没有退出事件（进程树未完整终止）: {sorted(missing)}",
            )

        # 2) 操作系统层：命令行含该 workdir 唯一名的存活进程必须已退出
        leftover = qa.wait_no_processes(workdir.name, timeout_s=6.0)
        self.assertEqual(leftover, [], f"containment 返回后仍存在残留进程: {leftover}")

        # 3) 若心跳文件可定位（未随工作区清理），验证心跳已停止增长
        heartbeat = qa.locate_file(trace, workdir, "spawn_child.heartbeat")
        if heartbeat is not None and heartbeat.exists():
            self.assertTrue(
                qa.wait_heartbeat_stopped(heartbeat, quiet_s=1.5, timeout_s=8.0),
                "containment 返回后子进程仍在写心跳（进程树未终止 / 有残留进程）",
            )

    def test_timeout_terminates_whole_tree(self) -> None:
        """R3：超时必须生效，terminated_by=timeout，且无残留进程。"""
        trace, workdir = _run_sim(self, "sim_spawn_child.ps1", timeout_s=3)
        self.assertEqual(
            trace.sandbox.terminated_by,
            "timeout",
            f"超时用例 terminated_by 应为 timeout，实际 {trace.sandbox.terminated_by!r}",
        )
        heartbeat = qa.locate_file(trace, workdir, "spawn_child.heartbeat")
        if heartbeat is not None and heartbeat.exists():
            self.assertTrue(
                qa.wait_heartbeat_stopped(heartbeat, quiet_s=1.5, timeout_s=8.0),
                "超时强杀后进程仍在写心跳（进程树终止失败）",
            )
        leftover = qa.wait_no_processes(workdir.name, timeout_s=6.0)
        self.assertEqual(leftover, [], f"超时强杀后仍存在残留进程: {leftover}")

    def test_network_is_blocked_or_attempt_recorded(self) -> None:
        """R2：默认断网必须在隔离列表中声明；任何外联尝试都不得成功。"""
        trace, workdir = _run_sim(self, "sim_net_fail.ps1", timeout_s=20)
        self.assertEqual(trace.sandbox.limits.network, "blocked")
        isolation = " ".join(trace.sandbox.isolation).lower()
        self.assertTrue(
            any(token in isolation for token in NETWORK_BLOCK_TOKENS),
            f"隔离列表未声明网络阻断，存在 fail-open 风险: {trace.sandbox.isolation}",
        )
        for event in trace.events:
            if event.category != "network":
                continue
            args = event.args or {}
            for key in ("success", "connected"):
                if key in args:
                    self.assertFalse(bool(args[key]), f"记录到外联成功事件: {event.to_dict()}")
            for key in ("ret", "status"):
                if key in args and isinstance(args[key], (int, float)):
                    self.assertNotEqual(int(args[key]), 0, f"记录到外联成功事件: {event.to_dict()}")

        # 脚本结果文件若被观测到，connected 必须全部为 False
        result_file = qa.locate_file(trace, workdir, "net_fail.result")
        if result_file is not None and result_file.exists():
            text = result_file.read_text(encoding="utf-8", errors="replace").lower()
            self.assertNotIn("connected=true", text, "模拟外联成功率非零，网络隔离失效")

    def test_fail_closed_when_network_isolation_unavailable(self) -> None:
        """R2：断网失败时必须中止执行（fail-closed），不得静默放行样本。"""
        backend, reason = containment()
        if backend is None:
            self.skipTest(reason)

        modules: list[tuple[str, Any]] = []
        for module_name in ("tianti.sandbox.containment", "tianti.sandbox.isolation", "tianti.sandbox.netmon"):
            module, _ = qa.import_optional(module_name)
            if module is not None:
                modules.append((module_name, module))

        # 首选精确注入点：isolation.Isolation._install_firewall_rules
        hook = None
        iso_module, _ = qa.import_optional("tianti.sandbox.isolation")
        iso_cls = getattr(iso_module, "Isolation", None) if iso_module is not None else None
        if iso_cls is not None and callable(getattr(iso_cls, "_install_firewall_rules", None)):
            hook = (
                "isolation.Isolation._install_firewall_rules",
                iso_cls,
                "_install_firewall_rules",
                getattr(iso_cls, "_install_firewall_rules"),
            )
        for module_name, module in ([] if hook is not None else modules):
            for attr in NETWORK_HOOK_NAMES:
                fn = getattr(module, attr, None)
                if callable(fn):
                    hook = (module_name, module, attr, fn)
                    break
            if hook is not None:
                break
        if hook is None:
            for module_name, module in modules:
                for attr in dir(module):
                    lowered = attr.lower()
                    if "firewall" in lowered or "network_block" in lowered or "block_network" in lowered:
                        fn = getattr(module, attr, None)
                        if callable(fn):
                            hook = (module_name, module, attr, fn)
                            break
                if hook is not None:
                    break
        if hook is None:
            self.skipTest(
                f"{qa.SKIP_PREFIX}: containment 未暴露网络隔离安装点（故障注入钩子），"
                "fail-closed 无法自动化验证；请联系 sandbox owner 提供注入点或补充用例"
            )

        module_name, module, attr, original = hook
        calls = {"count": 0}

        def failing_hook(*args: Any, **kwargs: Any) -> Any:
            calls["count"] += 1
            raise SandboxError("QA 故障注入：模拟断网失败（fail-closed 验证）", reason="qa_failure_injection")

        setattr(module, attr, failing_hook)
        self.addCleanup(setattr, module, attr, original)

        workdir = Path(tempfile.mkdtemp(prefix="tianti_failclosed_"))
        self.addCleanup(qa.safe_rmtree, workdir)
        sample = Sample.from_path(qa.SIM_SAMPLES / "sim_redline_start_marker.ps1")
        policy = SandboxPolicy(
            name="qa-failclosed",
            timeout_s=10,
            mem_mb=256,
            cpu_s=5,
            network="blocked",
            max_events=5000,
            backend="containment",
            workdir_root=workdir,
        )
        raised: Exception | None = None
        trace = None
        try:
            trace = backend.run(sample, policy)
        except Exception as exc:  # noqa: BLE001 - 任何异常都视为 fail-closed 生效
            raised = exc

        if calls["count"] == 0:
            self.skipTest(
                f"{qa.SKIP_PREFIX}: 注入点 {module_name}.{attr} 未被 containment 调用，"
                "无法验证 fail-closed（需与 sandbox owner 对齐内部接口）"
            )

        self.assertIsNotNone(raised, "断网隔离安装失败时 containment 未 fail-closed，仍返回了 trace")
        self.assertIsNone(trace, "fail-closed 期望不产出 trace")
        marker = _find_marker(workdir, "executed.marker")
        self.assertIsNone(marker, f"fail-closed 失败：断网失败后样本仍被执行（标记 {marker}）")
