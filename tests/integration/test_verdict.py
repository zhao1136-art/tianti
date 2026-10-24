# -*- coding: utf-8 -*-
"""M5 集成测试：3 份 golden trace 端到端（检测 -> 评分 -> Verdict）。

验收：ransom -> malicious；injection -> malicious；benign -> clean 或 suspicious 且 score < 40。
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tianti.core.config import ScoringConfig
from tianti.core.verdict import Verdict
from tianti.detect.base import DetectorHit
from tianti.detect.detectors import load_detectors, run_detectors, run_detectors_detailed
from tianti.detect.scoring import evaluate
from tianti.trace.schema import Trace, load

ROOT = Path(__file__).resolve().parents[2]
TRACES = ROOT / "tests" / "fixtures" / "traces"
GOLDEN = ("golden_ransom_sim.json", "golden_injection.json", "golden_benign_installer.json")


class TestGoldenVerdicts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cfg = ScoringConfig()
        cls.loaded = load_detectors()
        cls.results = {name: cls._scan(name) for name in GOLDEN}

    @classmethod
    def _scan(cls, name: str) -> tuple[Trace, object, Verdict]:
        trace = load(TRACES / name)
        detailed = run_detectors_detailed(trace, cls.loaded)
        verdict = evaluate(trace, [], detailed.hits, cfg=cls.cfg)
        return trace, detailed, verdict

    def test_detectors_loaded(self) -> None:
        self.assertGreaterEqual(len(self.loaded.detectors), 26)
        self.assertEqual(self.loaded.errors, [])

    def test_ransom_is_malicious(self) -> None:
        trace, detailed, verdict = self.results["golden_ransom_sim.json"]
        self.assertEqual(verdict.verdict, "malicious")
        self.assertGreaterEqual(verdict.score, self.cfg.malicious_at)
        hit_ids = {hit.detector_id for hit in detailed.hits}
        self.assertIn("shadow_copy_delete", hit_ids)
        self.assertIn("run_key_persistence", hit_ids)
        self.assertIn("TA0040", verdict.tactics)
        self.assertIn("T1490", verdict.techniques)
        self.assertEqual(detailed.errors, [])
        self.assertGreater(verdict.confidence, 0.5)

    def test_injection_is_malicious(self) -> None:
        trace, detailed, verdict = self.results["golden_injection.json"]
        self.assertEqual(verdict.verdict, "malicious")
        self.assertGreaterEqual(verdict.score, self.cfg.malicious_at)
        hit_ids = {hit.detector_id for hit in detailed.hits}
        self.assertIn("process_injection", hit_ids)
        self.assertIn("amsi_etw_patch", hit_ids)
        self.assertIn("TA0005", verdict.tactics)
        self.assertIn("T1055", verdict.techniques)
        self.assertEqual(detailed.errors, [])

    def test_benign_is_clean_or_suspicious_below_40(self) -> None:
        trace, detailed, verdict = self.results["golden_benign_installer.json"]
        self.assertIn(verdict.verdict, ("clean", "suspicious"))
        self.assertLess(verdict.score, 40.0)
        for hit in detailed.hits:
            self.assertNotEqual(hit.severity, "critical")

    def test_evidence_chain_traceable_for_all_golden(self) -> None:
        for name, (trace, detailed, verdict) in self.results.items():
            trace_ids = {event.id for event in trace.events}
            for item in verdict.items:
                self.assertTrue(set(item.evidence) <= trace_ids, f"{name}: item {item.ref}")
            for hit in detailed.hits:
                self.assertTrue(set(hit.evidence) <= trace_ids, f"{name}: hit {hit.detector_id}")

    def test_run_detectors_contract(self) -> None:
        trace = load(TRACES / "golden_ransom_sim.json")
        errors: list[str] = []
        hits = run_detectors(trace, errors=errors)
        self.assertIsInstance(hits, list)
        self.assertTrue(all(isinstance(hit, DetectorHit) for hit in hits))
        detailed = run_detectors_detailed(trace)
        self.assertEqual(len(hits), len(detailed.hits))
        self.assertEqual(errors, [])

    def test_verdict_json_roundtrip(self) -> None:
        for name, (_, _, verdict) in self.results.items():
            restored = Verdict.from_dict(json.loads(json.dumps(verdict.to_dict(), ensure_ascii=False)))
            self.assertEqual(restored.verdict, verdict.verdict, name)
            self.assertEqual(restored.score, verdict.score, name)
            self.assertEqual(restored.tactics, verdict.tactics, name)
            self.assertEqual(len(restored.items), len(verdict.items), name)

    def test_default_engine_config_whitelist_keeps_malicious(self) -> None:
        """默认配置含 whitelist_paths=C:\\Windows\\；不得因此把 golden 恶意样本判成 clean。"""
        from tianti.core.config import Config

        engine_cfg = Config.load()
        trace = load(TRACES / "golden_ransom_sim.json")
        detailed = run_detectors_detailed(trace, self.loaded)
        verdict = evaluate(trace, [], detailed.hits, cfg=engine_cfg.scoring)
        self.assertEqual(verdict.verdict, "malicious")
        self.assertGreaterEqual(verdict.score, engine_cfg.scoring.malicious_at)

    def test_ransom_beats_benign(self) -> None:
        _, _, ransom = self.results["golden_ransom_sim.json"]
        _, _, injection = self.results["golden_injection.json"]
        _, _, benign = self.results["golden_benign_installer.json"]
        self.assertGreater(ransom.score, benign.score)
        self.assertGreater(injection.score, benign.score)
        self.assertEqual(benign.verdict, "clean")


if __name__ == "__main__":
    unittest.main()
