# -*- coding: utf-8 -*-
"""M5 单元测试：评分模型 / 战术权重 / critical 硬规则 / 阈值 / 抑制 / 证据链。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tianti.core.config import ScoringConfig
from tianti.core.verdict import Verdict
from tianti.detect.base import DetectorHit
from tianti.detect.detectors import load_detectors, run_detectors_detailed
from tianti.detect.scoring import SIGNATURE_PLACEHOLDER_NOTE, evaluate, score
from tianti.rules.base import RuleMatch
from tianti.trace.schema import load

ROOT = Path(__file__).resolve().parents[2]
TRACES = ROOT / "tests" / "fixtures" / "traces"


def make_hit(
    detector_id: str = "unit_hit",
    severity: str = "high",
    score_value: float = 18.0,
    tactic: str = "",
    technique: str = "",
    evidence: list[str] | None = None,
    suppressed: bool = False,
    reason: str = "",
    detail: str = "",
) -> DetectorHit:
    return DetectorHit(
        detector_id=detector_id,
        name=detector_id,
        severity=severity,
        tactic=tactic,
        technique=technique,
        score=score_value,
        evidence=list(evidence or []),
        detail=detail,
        suppressed=suppressed,
        suppress_reason=reason,
    )


def make_match(
    name: str = "unit_rule",
    attack: list[str] | None = None,
    evidence: dict[str, list[str]] | None = None,
    confidence: str = "high",
) -> RuleMatch:
    return RuleMatch(
        name=name,
        namespace="test/unit",
        attack=list(attack or []),
        evidence=dict(evidence or {}),
        confidence=confidence,
    )


class TestScoringBasics(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = ScoringConfig()

    def test_empty_is_clean(self) -> None:
        verdict = score([], [], cfg=self.cfg)
        self.assertEqual(verdict.verdict, "clean")
        self.assertEqual(verdict.score, 0.0)
        self.assertEqual(verdict.items, [])

    def test_score_monotonic_for_detectors(self) -> None:
        scores = [
            score([], [make_hit(score_value=8)], cfg=self.cfg).score,
            score([], [make_hit(score_value=8), make_hit(score_value=8)], cfg=self.cfg).score,
            score(
                [],
                [make_hit(score_value=8), make_hit(score_value=8), make_hit(score_value=8)],
                cfg=self.cfg,
            ).score,
        ]
        self.assertEqual(scores, sorted(scores))
        self.assertLess(scores[0], scores[1])

    def test_capability_monotonic_with_diminishing(self) -> None:
        one = score([make_match(attack=["Persistence::Registry Run Keys [T1547.001]"])], [], cfg=self.cfg)
        two = score(
            [
                make_match(attack=["Persistence::Registry Run Keys [T1547.001]"]),
                make_match(attack=["Persistence::Startup Folder [T1547.001]"]),
            ],
            [],
            cfg=self.cfg,
        )
        self.assertEqual(two.tactics, ["TA0003"])
        self.assertGreater(two.score, one.score)
        self.assertLess(two.score - one.score, one.score)

    def test_match_order_independence(self) -> None:
        """同命中集合、不同输入顺序必须得到完全相同的 Verdict（递减权重顺序稳定）。"""
        from itertools import permutations

        matches = [
            make_match(
                name="rule_b",
                attack=["Persistence::Registry Run Keys [T1547.001]"],
                evidence={"events": ["e00002"]},
            ),
            make_match(
                name="rule_a",
                attack=["Persistence::Registry Run Keys [T1547.001]"],
                evidence={"events": ["e00001"]},
            ),
            make_match(
                name="rule_c",
                attack=["Persistence::Startup Folder [T1547.001]"],
                evidence={"events": ["e00003"]},
            ),
        ]
        hits = [make_hit(score_value=8)]
        baseline = score(matches, hits, cfg=self.cfg).to_dict()
        for order in permutations(matches):
            self.assertEqual(score(list(order), hits, cfg=self.cfg).to_dict(), baseline)
        self.assertEqual(score(list(reversed(matches)), hits, cfg=self.cfg).to_dict(), baseline)

    def test_capability_tactic_weight_ordering(self) -> None:
        impact = score([make_match(attack=["Impact::Data Encrypted for Impact [T1486]"])], [], cfg=self.cfg)
        discovery = score([make_match(attack=["Discovery::System Information Discovery [T1082]"])], [], cfg=self.cfg)
        self.assertGreater(impact.score, discovery.score)
        self.assertGreaterEqual(impact.score, 20.0)
        self.assertLessEqual(discovery.score, 6.0)

    def test_static_signal_contributes(self) -> None:
        verdict = score([], [], [{"name": "pe_entropy_high", "score": 6, "detail": "section entropy 7.9"}], cfg=self.cfg)
        self.assertEqual(len(verdict.items), 1)
        self.assertEqual(verdict.items[0].kind, "static")
        self.assertEqual(verdict.score, 6.0)
        self.assertEqual(verdict.verdict, "clean")

    def test_static_signal_without_name_ignored(self) -> None:
        verdict = score([], [], [{"score": 99}], cfg=self.cfg)
        self.assertEqual(verdict.items, [])


class TestCriticalAndThresholds(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = ScoringConfig()

    def test_critical_escalates_to_malicious(self) -> None:
        verdict = score([], [make_hit(severity="critical", score_value=26)], cfg=self.cfg)
        self.assertEqual(verdict.verdict, "malicious")
        self.assertGreaterEqual(verdict.score, self.cfg.malicious_at)
        self.assertTrue(any("critical" in note for note in verdict.notes))

    def test_critical_suppressed_keeps_half_score_and_escalates(self) -> None:
        hit = make_hit(severity="critical", score_value=26, suppressed=True, reason="trusted image downgrade")
        verdict = score([], [hit], cfg=self.cfg)
        self.assertEqual(len(verdict.items), 1)
        self.assertTrue(verdict.items[0].suppressed)
        self.assertAlmostEqual(verdict.items[0].score, 13.0)
        self.assertEqual(verdict.verdict, "malicious")
        self.assertGreaterEqual(verdict.score, self.cfg.malicious_at)
        self.assertTrue(verdict.suppressed)

    def test_critical_floor_with_zero_factor(self) -> None:
        hit = make_hit(detector_id="crit_floor", severity="critical", score_value=26, suppressed=True)
        verdict = score([], [hit], cfg=self.cfg, suppress_factors={"crit_floor": 0.0})
        self.assertAlmostEqual(verdict.items[0].score, 13.0)

    def test_benign_thresholds(self) -> None:
        self.assertEqual(score([], [make_hit(score_value=8)], cfg=self.cfg).verdict, "clean")
        self.assertEqual(score([], [make_hit(score_value=10)], cfg=self.cfg).verdict, "suspicious")
        self.assertEqual(score([], [make_hit(score_value=40)], cfg=self.cfg).verdict, "malicious")
        self.assertEqual(score([], [], cfg=self.cfg).verdict, "clean")

    def test_non_critical_suppressed_does_not_escalate(self) -> None:
        verdict = score([], [make_hit(severity="high", score_value=18, suppressed=True)], cfg=self.cfg)
        self.assertNotEqual(verdict.verdict, "malicious")
        self.assertLess(verdict.score, self.cfg.malicious_at)

    def test_whitelist_sha256_returns_clean(self) -> None:
        cfg = ScoringConfig(whitelist_sha256=["A" * 64])
        verdict = score(
            [make_match(attack=["Impact::Data Encrypted [T1486]"])],
            [make_hit(severity="critical", score_value=26)],
            cfg=cfg,
            sample_sha256="a" * 64,
        )
        self.assertEqual(verdict.verdict, "clean")
        self.assertEqual(verdict.score, 0.0)
        self.assertTrue(verdict.suppressed)
        self.assertTrue(any("白名单" in note for note in verdict.notes))


class TestSuppressionAndConfidence(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = ScoringConfig()

    def test_suppression_lowers_score_and_confidence(self) -> None:
        normal = [make_hit(detector_id=f"d{index}", score_value=20, evidence=["e00001"]) for index in range(4)]
        suppressed = [
            make_hit(detector_id=f"d{index}", score_value=20, evidence=["e00001"], suppressed=True)
            for index in range(4)
        ]
        normal_verdict = score([], normal, cfg=self.cfg)
        suppressed_verdict = score([], suppressed, cfg=self.cfg)
        self.assertGreater(normal_verdict.score, suppressed_verdict.score)
        self.assertGreater(normal_verdict.confidence, suppressed_verdict.confidence)
        self.assertGreater(len(suppressed_verdict.suppressed), 0)

    def test_event_path_whitelist_downgrades_not_full(self) -> None:
        trace = load(TRACES / "golden_benign_installer.json")
        hit = make_hit(severity="high", score_value=18, evidence=["e00002"])
        cfg = ScoringConfig(whitelist_paths=["C:\\Program Files\\"])
        verdict = evaluate(trace, [], [hit], cfg=cfg)
        self.assertTrue(hit.suppressed)
        self.assertAlmostEqual(verdict.items[0].score, 9.0)
        self.assertLess(verdict.score, cfg.malicious_at)
        self.assertNotEqual(verdict.verdict, "malicious")

    def test_sample_path_whitelist_full_suppression(self) -> None:
        trace = load(TRACES / "golden_benign_installer.json")
        trace.sample.name = r"C:\Program Files\Acme\app.exe"
        hit = make_hit(severity="high", score_value=18, evidence=["e00002"])
        cfg = ScoringConfig(whitelist_paths=["C:\\Program Files\\"])
        verdict = evaluate(trace, [], [hit], cfg=cfg)
        self.assertTrue(hit.suppressed)
        self.assertAlmostEqual(verdict.items[0].score, 0.0)
        self.assertEqual(verdict.verdict, "clean")

    def test_path_trust_adds_signature_placeholder_note(self) -> None:
        """Lead 决策：使用 path-based trust 时必须标注“签名占位”。"""
        hit = make_hit(
            severity="high",
            score_value=18,
            suppressed=True,
            reason="证据事件路径命中白名单（事件级，降权 50%）",
        )
        verdict = score([], [hit], cfg=self.cfg)
        self.assertIn(SIGNATURE_PLACEHOLDER_NOTE, verdict.notes)

        clean = score([], [make_hit(score_value=18)], cfg=self.cfg)
        self.assertNotIn(SIGNATURE_PLACEHOLDER_NOTE, clean.notes)

    def test_confidence_in_range_and_deterministic(self) -> None:
        first = score([], [make_hit(score_value=18, evidence=["e00001"])], cfg=self.cfg)
        second = score([], [make_hit(score_value=18, evidence=["e00001"])], cfg=self.cfg)
        self.assertGreaterEqual(first.confidence, 0.0)
        self.assertLessEqual(first.confidence, 1.0)
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_more_evidence_raises_confidence(self) -> None:
        few = score([], [make_hit(score_value=18, evidence=["e00001"])], cfg=self.cfg)
        many = score(
            [],
            [make_hit(score_value=18, evidence=[f"e{index:05d}" for index in range(1, 8)])],
            cfg=self.cfg,
        )
        self.assertGreater(many.confidence, few.confidence)


class TestEvidenceChainAndVerdict(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cfg = ScoringConfig()
        cls.loaded = load_detectors()

    def test_evidence_chain_complete(self) -> None:
        trace = load(TRACES / "golden_ransom_sim.json")
        detailed = run_detectors_detailed(trace, self.loaded)
        match = make_match(
            name="unit_run_key",
            attack=["Persistence::Registry Run Keys [T1547.001]"],
            evidence={"events": ["e00003"]},
        )
        verdict = evaluate(trace, [match], detailed.hits, cfg=self.cfg)
        trace_ids = {event.id for event in trace.events}
        self.assertTrue(verdict.items)
        self.assertTrue(all(set(item.evidence) <= trace_ids for item in verdict.items))
        for hit in detailed.hits:
            self.assertTrue(set(hit.evidence) <= trace_ids)
        item_evidence = {event_id for item in verdict.items for event_id in item.evidence}
        self.assertTrue(set(match.evidence["events"]) <= item_evidence)
        self.assertEqual(verdict.verdict, "malicious")

    def test_tactics_and_techniques_aggregation(self) -> None:
        match = make_match(attack=["Persistence::Registry Run Keys [T1547.001]"])
        hit = make_hit(tactic="TA0006", technique="T1003.001")
        verdict = score([match], [hit], cfg=self.cfg)
        self.assertEqual(verdict.tactics, ["TA0003", "TA0006"])
        self.assertEqual(verdict.techniques, ["T1003.001", "T1547.001"])

    def test_verdict_roundtrip(self) -> None:
        original = score([], [make_hit(severity="critical", score_value=26)], cfg=self.cfg)
        restored = Verdict.from_dict(json.loads(json.dumps(original.to_dict(), ensure_ascii=False)))
        self.assertEqual(restored.verdict, original.verdict)
        self.assertEqual(restored.score, original.score)
        self.assertEqual(restored.confidence, original.confidence)
        self.assertEqual(restored.tactics, original.tactics)
        self.assertEqual(len(restored.items), len(original.items))
        self.assertEqual(restored.notes, original.notes)

    def test_multiple_golden_verdicts_have_valid_evidence(self) -> None:
        for name in ("golden_ransom_sim.json", "golden_injection.json", "golden_benign_installer.json"):
            trace = load(TRACES / name)
            detailed = run_detectors_detailed(trace, self.loaded)
            verdict = evaluate(trace, [], detailed.hits, cfg=self.cfg)
            trace_ids = {event.id for event in trace.events}
            for item in verdict.items:
                self.assertTrue(set(item.evidence) <= trace_ids, f"{name}: {item.ref}")
            for hit in detailed.hits:
                self.assertTrue(set(hit.evidence) <= trace_ids, f"{name}: {hit.detector_id}")


if __name__ == "__main__":
    unittest.main()