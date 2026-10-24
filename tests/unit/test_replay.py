"""M2：replay 后端、replay_io（JSON/JSONL/目录批量）与派生指标测试。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tianti.core.errors import SandboxUnavailable, TraceError
from tianti.core.model import Sample, SampleType
from tianti.sandbox.base import SandboxPolicy
from tianti.sandbox.replay import BACKEND, ReplayBackend
from tianti.trace import metrics, replay_io, schema

TRACES = Path(__file__).resolve().parents[1] / "fixtures" / "traces"
RANSOM = TRACES / "golden_ransom_sim.json"


class ReplayBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = schema.load(RANSOM)
        self.sample = replay_io.sample_from_trace(self.trace)
        self.policy = SandboxPolicy(name="deep", max_events=50000)

    def test_available(self) -> None:
        ok, reason = ReplayBackend().available()
        self.assertTrue(ok)
        self.assertIn("trace", reason)
        self.assertTrue(BACKEND.available()[0])

    def test_event_sequence_identical(self) -> None:
        replayed = ReplayBackend(self.trace).run(self.sample, self.policy)
        self.assertEqual(
            [event.to_dict() for event in replayed.events],
            [event.to_dict() for event in self.trace.events],
        )

    def test_new_trace_validates(self) -> None:
        replayed = ReplayBackend(self.trace).run(self.sample, self.policy)
        replayed.validate()
        self.assertEqual(replayed.engine.backend, "replay")
        self.assertEqual(replayed.engine.policy, "deep")
        self.assertIn("replay", replayed.sandbox.isolation)
        self.assertNotEqual(replayed.trace_id, self.trace.trace_id)
        self.assertEqual(replayed.summary.event_count, len(self.trace.events))

    def test_deterministic(self) -> None:
        first = ReplayBackend(self.trace).run(self.sample, self.policy)
        second = ReplayBackend(self.trace).run(self.sample, self.policy)
        self.assertEqual(
            [event.to_dict() for event in first.events],
            [event.to_dict() for event in second.events],
        )
        self.assertEqual(first.summary.to_dict(), second.summary.to_dict())

    def test_sample_fallback_and_override(self) -> None:
        empty = Sample(name="unknown.bin", sha256="", size=0, type=SampleType.UNKNOWN)
        replayed = ReplayBackend(self.trace).run(empty, self.policy)
        self.assertEqual(replayed.sample.sha256, self.trace.sample.sha256)
        override = Sample.from_bytes(b"override", "override.bin")
        replayed = ReplayBackend(self.trace).run(override, self.policy)
        self.assertEqual(replayed.sample.name, "override.bin")
        self.assertEqual(replayed.sample.sha256, override.sha256)

    def test_on_event_callback(self) -> None:
        seen = []
        ReplayBackend(self.trace).run(self.sample, self.policy, on_event=seen.append)
        self.assertEqual(len(seen), len(self.trace.events))

    def test_source_from_sample_extra(self) -> None:
        sample = Sample(
            name="x.bin",
            sha256="",
            size=0,
            type=SampleType.UNKNOWN,
            extra={"trace_path": str(RANSOM)},
        )
        replayed = ReplayBackend().run(sample, self.policy)
        self.assertEqual(len(replayed.events), len(self.trace.events))

    def test_missing_source_raises(self) -> None:
        with self.assertRaises(SandboxUnavailable):
            ReplayBackend().run(Sample(name="x.bin"), self.policy)

    def test_multiple_traces_merge_in_order(self) -> None:
        replayed = ReplayBackend([self.trace, self.trace]).run(self.sample, self.policy)
        replayed.validate()
        self.assertEqual(len(replayed.events), len(self.trace.events) * 2)
        timestamps = [event.ts for event in replayed.events]
        self.assertEqual(timestamps, sorted(timestamps))
        self.assertEqual(replayed.extra["replay"]["source_count"], 2)

    def test_truncation(self) -> None:
        replayed = ReplayBackend(self.trace).run(self.sample, SandboxPolicy(max_events=5))
        self.assertEqual(len(replayed.events), 5)
        self.assertGreater(replayed.summary.dropped, 0)
        self.assertTrue(replayed.summary.truncated)
        replayed.validate()

    def test_from_path(self) -> None:
        replayed = ReplayBackend.from_path(RANSOM).run(self.sample, self.policy)
        self.assertEqual(len(replayed.events), len(self.trace.events))


class ReplayIOTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = schema.load(RANSOM)

    def test_json_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = replay_io.save_trace(self.trace, Path(tmp) / "t.json")
            restored = replay_io.load_any(path)
            self.assertEqual(restored.to_dict(), self.trace.to_dict())

    def test_jsonl_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = replay_io.save_jsonl(self.trace, Path(tmp) / "t.jsonl")
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), len(self.trace.events) + 1)
            self.assertEqual(json.loads(lines[0])["events"], [])
            restored = replay_io.load_jsonl(path)
            restored.validate()
            self.assertEqual(restored.to_dict(), self.trace.to_dict())
            self.assertEqual(replay_io.load_any(path).to_dict(), self.trace.to_dict())

    def test_jsonl_bad_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text("{not json}\n", encoding="utf-8")
            with self.assertRaises(TraceError):
                replay_io.load_jsonl(path)
            empty = Path(tmp) / "empty.jsonl"
            empty.write_text("", encoding="utf-8")
            with self.assertRaises(TraceError):
                replay_io.load_jsonl(empty)

    def test_discover_and_load_directory(self) -> None:
        paths = replay_io.discover_traces(TRACES)
        self.assertEqual(len(paths), 3)
        self.assertTrue(all(replay_io.is_trace_path(p) for p in paths))
        traces = replay_io.load_directory(TRACES)
        self.assertEqual(len(traces), 3)
        for trace in traces:
            trace.validate()

    def test_replay_directory(self) -> None:
        replayed = replay_io.replay_directory(TRACES, policy=SandboxPolicy(max_events=50000))
        self.assertEqual(len(replayed), 3)
        for trace in replayed:
            trace.validate()
            self.assertEqual(trace.engine.backend, "replay")


def _synthetic_trace():
    from tianti.trace.normalize import EventBuilder, build_trace
    from tianti.trace.schema import SandboxInfo

    builder = EventBuilder(max_events=100, source="test")
    builder.start()
    builder.emit("process", "create", ts=0.1, pid=100, ppid=1, target="C:\\a.exe", source="test", confidence="high")
    builder.emit("process", "create", ts=0.2, pid=200, ppid=100, target="C:\\b.exe", source="test", confidence="high")
    builder.emit("file", "write", ts=0.3, pid=100, target="C:\\w\\1.txt", args={"size": 10, "entropy": 7.5}, source="test", confidence="medium")
    builder.emit("file", "write", ts=0.4, pid=100, target="C:\\w\\1.txt", args={"size": 10, "entropy": 7.2}, source="test", confidence="medium")
    builder.emit("file", "write", ts=0.5, pid=200, target="C:\\w\\2.bin", args={"size": 20, "entropy": 7.9}, source="test", confidence="medium")
    builder.emit("file", "write", ts=1.2, pid=200, target="C:\\w\\3.bin", args={"size": 30, "entropy": 6.1}, source="test", confidence="medium")
    builder.emit("file", "write", ts=2.5, pid=200, target="C:\\w\\4.bin", args={"size": 40}, source="test", confidence="medium")
    builder.emit("file", "create", ts=2.6, pid=200, target="C:\\w\\5.bin", args={"size": 5}, source="test", confidence="medium")
    builder.emit("registry", "set", ts=2.7, pid=100, target="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x", source="test", confidence="medium")
    builder.emit("registry", "set", ts=2.8, pid=100, target="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\y", source="test", confidence="medium")
    builder.emit("network", "connect", ts=3.0, pid=200, target="203.0.113.5:443", args={"remote_port": 443}, source="test", confidence="medium")
    builder.emit("network", "connect", ts=3.1, pid=200, target="203.0.113.5:443", args={"remote_port": 443}, source="test", confidence="medium")
    builder.emit("network", "connect", ts=3.2, pid=200, target="198.51.100.7:8080", args={"remote_port": 8080}, source="test", confidence="medium")
    sample = Sample.from_bytes(b"sim", "sim.ps1")
    return build_trace(
        sample=sample,
        engine_version="0.1.0",
        backend="test",
        policy="test",
        sandbox=SandboxInfo(isolation=["test"]),
        builder=builder,
    )


class MetricsTests(unittest.TestCase):
    def test_golden_metrics(self) -> None:
        trace = schema.load(RANSOM)
        result = metrics.compute(trace)
        self.assertEqual(result.event_count, len(trace.events))
        self.assertEqual(result.process_count, len([e for e in trace.events if e.category == "process" and e.action == "create"]))
        self.assertEqual(result.file_writes, len([e for e in trace.events if e.category == "file" and e.action == "write"]))
        self.assertEqual(result.net_connects, len([e for e in trace.events if e.category == "network" and e.action == "connect"]))
        self.assertEqual(result.registry_sets, len([e for e in trace.events if e.category == "registry" and e.action == "set"]))
        self.assertGreater(result.file_write_entropy.max, 7.0)
        self.assertGreaterEqual(result.file_write_entropy.high_count, 1)
        self.assertEqual(result.timeline.total, len(trace.events))
        self.assertGreaterEqual(result.duration, 0.0)

    def test_synthetic_metrics(self) -> None:
        result = metrics.compute(_synthetic_trace(), bucket_s=1.0, window_s=1.0)
        self.assertEqual(result.event_count, 13)
        self.assertEqual(result.process_count, 2)
        self.assertEqual(sorted(result.process_event_counts), [100, 200])
        self.assertEqual(len(result.file_write_paths), 4)  # 1.txt,2.bin,3.bin,4.bin
        self.assertEqual(result.file_writes, 5)
        self.assertEqual(result.file_write_entropy.count, 4)
        self.assertAlmostEqual(result.file_write_entropy.max, 7.9)
        self.assertAlmostEqual(result.file_write_entropy.min, 6.1)
        self.assertAlmostEqual(result.file_write_entropy.mean, (7.5 + 7.2 + 7.9 + 6.1) / 4)
        self.assertEqual(result.file_write_entropy.high_count, 3)
        self.assertEqual(result.file_write_bytes, 10 + 10 + 20 + 30 + 40)
        self.assertEqual(result.registry_sets, 2)
        self.assertEqual(len(result.registry_keys), 2)
        self.assertEqual(result.net_connects, 3)
        self.assertEqual(result.net_targets, {"198.51.100.7:8080": 1, "203.0.113.5:443": 2})
        self.assertEqual(result.net_ports, [443, 8080])
        self.assertEqual(result.max_writes_in_window, 4)  # ts 0.3/0.4/0.5/1.2 落在同一 1s 窗口
        self.assertEqual(result.timeline.counts, [5, 1, 4, 3])
        self.assertEqual(result.timeline.peak_count, 5)
        self.assertEqual(result.distinct_targets["file"], 5)
        json.dumps(result.to_dict(), ensure_ascii=False)

    def test_timeline_buckets(self) -> None:
        trace = _synthetic_trace()
        timeline = metrics.timeline_buckets(trace, bucket_s=1.0)
        self.assertEqual(timeline.start, 0.1)
        self.assertEqual(timeline.end, 3.2)
        self.assertEqual(timeline.counts, [5, 1, 4, 3])
        self.assertEqual(timeline.peak_bucket, 0)
        self.assertEqual(timeline.total, 13)

    def test_max_events_in_window(self) -> None:
        trace = _synthetic_trace()
        self.assertEqual(metrics.max_events_in_window(metrics.file_write_events(trace), window_s=0.5), 3)
        self.assertEqual(metrics.max_events_in_window([], window_s=1.0), 0)
        self.assertEqual(metrics.max_events_in_window(trace.events, window_s=0), 0)

    def test_empty_trace_metrics(self) -> None:
        from tianti.trace.schema import SandboxInfo

        trace = schema.Trace(
            trace_id="20261024T103500Z-7f3a9c21",
            sample=schema.SampleInfo(name="x", sha256="0" * 64, size=0, type="text"),
            engine=schema.EngineInfo(version="0.1.0", backend="replay", policy="deep"),
            sandbox=SandboxInfo(),
            events=[],
            created_at="2026-10-24T10:35:00+08:00",
        )
        trace.validate()
        result = metrics.compute(trace)
        self.assertEqual(result.event_count, 0)
        self.assertEqual(result.max_writes_in_window, 0)
        self.assertEqual(result.timeline.counts, [])
        json.dumps(result.to_dict(), ensure_ascii=False)


if __name__ == "__main__":
    unittest.main()
