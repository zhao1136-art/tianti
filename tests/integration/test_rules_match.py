"""集成测试：真实规则包对 golden trace 的匹配结果与性能预算。"""

from __future__ import annotations

import time
import unittest
from pathlib import Path

from tianti.rules.engine import RuleEngine, clear_engine_cache, match_trace
from tianti.rules.base import RuleMatch
from tianti.trace import schema

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules"
TRACES = ROOT / "tests" / "fixtures" / "traces"

CRITICAL_PREFIXES = (
    "persistence/",
    "credential-access/",
    "defense-evasion/",
    "injection/",
    "impact/",
    "lateral-movement/",
    "command-and-control/",
)


def flatten_evidence(matches: list[RuleMatch]) -> set[str]:
    ids: set[str] = set()
    for match in matches:
        for values in match.evidence.values():
            ids.update(values)
    return ids


class RuleMatchIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        clear_engine_cache()
        cls.engine = RuleEngine(RULES_DIR)

    def load_trace(self, name: str):
        return schema.load(TRACES / name)

    def namespaces(self, matches: list[RuleMatch]) -> set[str]:
        return {match.namespace for match in matches}

    def test_engine_loaded(self):
        self.assertGreaterEqual(len(self.engine), 40)
        self.assertEqual(self.engine.errors, [])
        self.assertEqual(self.engine.unsupported, [])

    def test_ransom_hits_runkey_shadowcopy_c2(self):
        trace = self.load_trace("golden_ransom_sim.json")
        matches = self.engine.match(trace)
        self.assertEqual(self.engine.errors, [])
        namespaces = self.namespaces(matches)
        self.assertIn("persistence/registry/run-key", namespaces)
        self.assertIn("impact/ransomware/shadow-copy-deletion", namespaces)
        self.assertIn("impact/ransomware/high-entropy-writes", namespaces)
        self.assertIn("impact/ransomware/staged-behavior", namespaces)
        self.assertIn("command-and-control/network/non-standard-port", namespaces)
        # 裸 IP 直连（network/connect/raw-ip）是 network 特征的 golden 基线，必须命中且计数稳定
        self.assertIn("network/connect/raw-ip", namespaces)
        self.assertEqual(len(matches), 15, f"ransom golden 基线应为 15 条，实际 {len(matches)}")
        # 证据可回溯：全部指向 trace 内事件 id
        trace_ids = {event.id for event in trace.events}
        self.assertTrue(flatten_evidence(matches) <= trace_ids)
        runkey = [m for m in matches if m.namespace == "persistence/registry/run-key"]
        self.assertIn("e00003", flatten_evidence(runkey))

    def test_benign_no_critical_matches(self):
        trace = self.load_trace("golden_benign_installer.json")
        matches = self.engine.match(trace)
        self.assertEqual(self.engine.errors, [])
        critical = [
            match
            for match in matches
            if match.namespace.startswith(CRITICAL_PREFIXES)
        ]
        self.assertEqual(
            critical,
            [],
            "良性样本命中了 critical 命名空间规则: "
            + ", ".join(sorted(m.namespace for m in critical)),
        )
        # golden 基线：benign 只有 1 条非 critical 的裸 IP 直连能力命中
        self.assertEqual(len(matches), 1, f"benign golden 基线应为 1 条，实际 {len(matches)}")
        self.assertEqual(matches[0].namespace, "network/connect/raw-ip")

    def test_injection_hits_injection_and_amsi(self):
        trace = self.load_trace("golden_injection.json")
        matches = self.engine.match(trace)
        self.assertEqual(self.engine.errors, [])
        namespaces = self.namespaces(matches)
        self.assertIn("injection/remote-thread", namespaces)
        self.assertIn("injection/api-sequence", namespaces)
        self.assertIn("defense-evasion/amsi-patch", namespaces)
        self.assertIn("network/connect/raw-ip", namespaces)
        self.assertEqual(len(matches), 6, f"injection golden 基线应为 6 条，实际 {len(matches)}")
        amsi = [m for m in matches if m.namespace == "defense-evasion/amsi-patch"]
        self.assertTrue(amsi)
        self.assertIn("e00007", flatten_evidence(amsi))
        self.assertTrue(all(m.attack for m in matches))
        self.assertTrue(all(m.mbc is not None for m in matches))

    def test_module_level_match_trace_is_cached(self):
        clear_engine_cache()
        trace = self.load_trace("golden_ransom_sim.json")
        first = match_trace(trace)
        self.assertTrue(first)
        first_names = sorted(m.namespace for m in first)
        second = match_trace(trace)
        self.assertEqual(sorted(m.namespace for m in second), first_names)
        self.assertIsInstance(first[0], RuleMatch)

    def test_match_results_json_serializable(self):
        import json

        matches = self.engine.match(self.load_trace("golden_injection.json"))
        payload = [match.to_dict() for match in matches]
        text = json.dumps(payload, ensure_ascii=False)
        self.assertIn("evidence", text)

    def test_performance_1000_events_under_one_second(self):
        events = []
        for index in range(1000):
            eid = f"e{index + 1:05d}"
            ts = round(index * 0.01, 6)
            pid = 4100 + (index % 7)
            bucket = index % 5
            if bucket == 0:
                events.append(
                    {
                        "id": eid, "ts": ts, "pid": pid, "category": "file", "action": "write",
                        "target": f"C:\\sandbox\\work\\f{index}.locked",
                        "args": {"size": 4096, "entropy": 7.5},
                        "source": "etw:file", "confidence": "high",
                    }
                )
            elif bucket == 1:
                events.append(
                    {
                        "id": eid, "ts": ts, "pid": pid, "category": "registry", "action": "set",
                        "target": f"HKLM\\Software\\Test\\Key{index}",
                        "source": "etw:registry", "confidence": "high",
                    }
                )
            elif bucket == 2:
                events.append(
                    {
                        "id": eid, "ts": ts, "pid": pid, "category": "process", "action": "create",
                        "target": "C:\\Windows\\System32\\cmd.exe",
                        "args": {"command_line": "cmd.exe /c whoami"},
                        "source": "etw:process", "confidence": "high",
                    }
                )
            elif bucket == 3:
                events.append(
                    {
                        "id": eid, "ts": ts, "pid": pid, "category": "network", "action": "connect",
                        "target": f"10.0.0.{index % 250}:8443",
                        "args": {"proto": "tcp"},
                        "source": "etw:network", "confidence": "medium",
                    }
                )
            else:
                events.append(
                    {
                        "id": eid, "ts": ts, "pid": pid, "category": "api", "action": "call",
                        "args": {"api": "VirtualAllocEx", "ret": "0x1000"},
                        "source": "api:user", "confidence": "high",
                    }
                )
        payload = {
            "trace_id": "20261024T103600Z-1a2b3c4d",
            "schema": "tianti.trace/1",
            "created_at": "2026-10-24T10:36:00+08:00",
            "sample": {"name": "perf.exe", "sha256": "b" * 64, "size": 1, "type": "pe32"},
            "engine": {"version": "0.1.0", "backend": "replay", "policy": "deep"},
            "sandbox": {
                "host": "TEST", "isolation": [], "limits": {},
                "started_at": "", "ended_at": "", "terminated_by": "exited",
            },
            "events": events,
            "summary": {},
        }
        trace = schema.Trace.from_dict(payload)
        started = time.perf_counter()
        matches = self.engine.match(trace)
        elapsed = time.perf_counter() - started
        self.assertTrue(matches)
        self.assertLess(elapsed, 1.0, f"1000 事件匹配耗时 {elapsed * 1000:.1f}ms 超过 1s 预算")
        self.assertEqual(self.engine.errors, [])


if __name__ == "__main__":
    unittest.main()
