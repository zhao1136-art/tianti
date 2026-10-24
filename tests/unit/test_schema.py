"""Trace 契约测试：golden trace 校验、round-trip、非法输入拒绝。"""

from __future__ import annotations

import copy
import json
import re
import unittest
from pathlib import Path

from tianti.trace import schema

TRACES = Path(__file__).resolve().parents[1] / "fixtures" / "traces"


def load_payload(name: str) -> dict:
    return json.loads((TRACES / name).read_text(encoding="utf-8"))


class GoldenTraceTests(unittest.TestCase):
    def test_golden_traces_exist(self):
        files = sorted(TRACES.glob("*.json"))
        self.assertGreaterEqual(len(files), 3, "至少需要 3 份 golden trace")

    def test_all_golden_traces_validate(self):
        for path in sorted(TRACES.glob("*.json")):
            with self.subTest(path=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(schema.validate_payload(payload), [])
                trace = schema.loads(path.read_text(encoding="utf-8"))
                trace.validate()
                self.assertEqual(trace.to_dict()["schema"], schema.SCHEMA_ID)

    def test_round_trip(self):
        for path in sorted(TRACES.glob("*.json")):
            with self.subTest(path=path.name):
                trace = schema.load(path)
                restored = schema.Trace.from_dict(trace.to_dict())
                self.assertEqual(restored.to_dict(), trace.to_dict())
                self.assertEqual(json.loads(schema.dumps(trace))["trace_id"], trace.trace_id)

    def test_summary_counts_are_consistent(self):
        trace = schema.load(TRACES / "golden_ransom_sim.json")
        self.assertEqual(trace.summary.event_count, len(trace.events))
        self.assertEqual(
            trace.summary.processes,
            len([ev for ev in trace.events_of("process") if ev.action == "create"]),
        )
        self.assertEqual(trace.summary.net_connects, len([e for e in trace.events_of("network") if e.action == "connect"]))


class ValidationRejectsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = copy.deepcopy(load_payload("golden_ransom_sim.json"))

    def assert_rejected(self) -> None:
        self.assertNotEqual(schema.validate_payload(self.payload), [])

    def test_bad_schema(self):
        self.payload["schema"] = "tianti.trace/2"
        self.assert_rejected()

    def test_bad_trace_id(self):
        self.payload["trace_id"] = "not-a-trace-id"
        self.assert_rejected()

    def test_bad_sha256(self):
        self.payload["sample"]["sha256"] = "xyz"
        self.assert_rejected()

    def test_unknown_category(self):
        self.payload["events"][0]["category"] = "explode"
        self.assert_rejected()

    def test_illegal_action_for_category(self):
        self.payload["events"][0]["action"] = "write"
        self.assert_rejected()

    def test_duplicate_event_id(self):
        self.payload["events"][1]["id"] = self.payload["events"][0]["id"]
        self.assert_rejected()

    def test_decreasing_ts(self):
        self.payload["events"][2]["ts"] = 0.0
        self.assert_rejected()

    def test_missing_events(self):
        self.payload.pop("events")
        self.assert_rejected()

    def test_loads_raises(self):
        with self.assertRaises(schema.TraceError):
            schema.loads(json.dumps({"trace_id": "bad"}))


class TraceIdTests(unittest.TestCase):
    def test_format(self):
        trace_id = schema.new_trace_id()
        self.assertIsNotNone(re.match(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$", trace_id))

    def test_unique(self):
        self.assertNotEqual(schema.new_trace_id(), schema.new_trace_id())
