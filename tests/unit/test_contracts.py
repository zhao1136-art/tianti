"""契约与基础设施测试：样本模型、哈希、配置、样本库、评分、规则/检测器数据结构。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tianti.core.config import Config, PolicyConfig
from tianti.core.errors import ConfigError
from tianti.core.hashing import hash_bytes, hash_file
from tianti.core.model import Sample, SampleType, guess_type
from tianti.core.sample_store import SampleStore
from tianti.core.verdict import ScoreItem, Verdict, confidence_from, decide
from tianti.detect.base import DetectorHit, DetectorSpec
from tianti.rules.base import RuleMeta, RuleMatch
from tianti.sandbox.base import SandboxPolicy
from tianti.trace.normalize import EventBuilder


def make_pe64() -> bytes:
    head = bytearray(0x100)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x40).to_bytes(4, "little")
    head[0x40:0x44] = b"PE\x00\x00"
    head[0x44:0x46] = (0x8664).to_bytes(2, "little")
    return bytes(head)


class ModelTests(unittest.TestCase):
    def test_guess_pe64(self):
        self.assertEqual(guess_type("sample.exe", make_pe64()), SampleType.PE64)

    def test_guess_script(self):
        self.assertEqual(guess_type("a.ps1", b"Write-Host hi"), SampleType.SCRIPT_POWERSHELL)

    def test_guess_text(self):
        self.assertEqual(guess_type("readme", b"hello world\n"), SampleType.TEXT)

    def test_sample_from_bytes(self):
        sample = Sample.from_bytes(b"abc", "a.bin")
        self.assertEqual(sample.sha256, hash_bytes(b"abc")["sha256"])
        self.assertEqual(sample.size, 3)
        self.assertEqual(sample.to_dict()["name"], "a.bin")

    def test_sample_roundtrip(self):
        sample = Sample.from_bytes(make_pe64(), "x.exe")
        restored = Sample.from_dict(sample.to_dict())
        self.assertEqual(restored.type, SampleType.PE64)
        self.assertEqual(restored.sha256, sample.sha256)


class HashTests(unittest.TestCase):
    def test_known_sha256(self):
        self.assertEqual(
            hash_bytes(b"abc")["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_hash_file_matches_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.bin"
            path.write_bytes(b"tianti" * 1000)
            self.assertEqual(hash_file(path)["sha256"], hash_bytes(b"tianti" * 1000)["sha256"])


class SampleStoreTests(unittest.TestCase):
    def test_put_read_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SampleStore(Path(tmp))
            sample = store.put_bytes(b"payload-bytes", "demo.bin")
            self.assertTrue(store.has(sample.sha256))
            self.assertEqual(store.read(sample.sha256), b"payload-bytes")
            meta = store.meta(sample.sha256)
            self.assertEqual(meta["name"], "demo.bin")
            self.assertEqual(store.sample(sample.sha256).name, "demo.bin")

    def test_put_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "in.ps1"
            source.write_text("Write-Host hi", encoding="utf-8")
            store = SampleStore(Path(tmp) / "store")
            sample = store.put_file(source)
            self.assertEqual(sample.type, SampleType.SCRIPT_POWERSHELL)


class ConfigTests(unittest.TestCase):
    def test_default_policies(self):
        cfg = Config.default()
        self.assertIn("deep", cfg.policies)
        self.assertEqual(cfg.policy().name, "deep")
        self.assertEqual(cfg.policy("fast").timeout_s, 10)

    def test_unknown_policy(self):
        with self.assertRaises(ConfigError):
            Config.default().policy("nope")

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config.default()
            path = Path(tmp) / "engine.json"
            cfg.save(path)
            loaded = Config.load(path)
            self.assertEqual(loaded.default_policy, cfg.default_policy)
            self.assertEqual(loaded.scoring.malicious_at, cfg.scoring.malicious_at)

    def test_policy_factory(self):
        policy = SandboxPolicy.from_config(PolicyConfig(name="x", timeout_s=7))
        self.assertEqual(policy.timeout_s, 7)
        self.assertEqual(policy.limits().network, "blocked")


class VerdictTests(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(decide(0, critical_hit=False, clean_below=10, malicious_at=40), "clean")
        self.assertEqual(decide(20, critical_hit=False, clean_below=10, malicious_at=40), "suspicious")
        self.assertEqual(decide(50, critical_hit=False, clean_below=10, malicious_at=40), "malicious")
        self.assertEqual(decide(20, critical_hit=True, clean_below=10, malicious_at=40), "malicious")

    def test_confidence_range(self):
        value = confidence_from(50, evidence_count=4, source_quality=0.9, suppressed_ratio=0.0)
        self.assertGreaterEqual(value, 0.0)
        self.assertLessEqual(value, 1.0)

    def test_roundtrip(self):
        verdict = Verdict(
            verdict="malicious",
            score=72.5,
            confidence=0.83,
            tactics=["TA0003"],
            techniques=["T1547.001"],
            items=[ScoreItem(kind="capability", ref="persistence/run-key", score=10.0, evidence=["e00003"])],
        )
        self.assertEqual(Verdict.from_dict(verdict.to_dict()).to_dict(), verdict.to_dict())


class RuleAndDetectorTests(unittest.TestCase):
    def test_rule_meta_mapping(self):
        meta = RuleMeta(
            name="x",
            attack=["Persistence::Registry Run Keys / Startup Folder [T1547.001]"],
        )
        self.assertEqual(meta.techniques(), ["T1547.001"])
        self.assertEqual(meta.tactics(), ["TA0003"])

    def test_rule_match_roundtrip(self):
        match = RuleMatch(
            name="x",
            namespace="persistence/x",
            instance={"pid": 1},
            attack=["Persistence::Registry Run Keys [T1547.001]"],
            evidence={"registry set: HKCU\\...\\Run": ["e00003"]},
        )
        self.assertEqual(RuleMatch.from_dict(match.to_dict()).to_dict(), match.to_dict())

    def test_detector_hit_roundtrip(self):
        hit = DetectorHit(
            detector_id="run_key_persistence",
            name="Run 键自启动",
            severity="high",
            tactic="TA0003",
            technique="T1547.001",
            score=20.0,
            evidence=["e00003"],
        )
        self.assertEqual(DetectorHit.from_dict(hit.to_dict()).to_dict(), hit.to_dict())
        self.assertEqual(DetectorSpec(id="x", severity="critical").to_dict()["severity"], "critical")


class EventBuilderTests(unittest.TestCase):
    def test_event_ids_and_cap(self):
        builder = EventBuilder(max_events=2, source="test")
        builder.start()
        self.assertIsNotNone(builder.emit("process", "create", pid=1, source="test", confidence="high"))
        self.assertIsNotNone(builder.emit("file", "write", pid=1))
        self.assertIsNone(builder.emit("file", "delete", pid=1))
        self.assertEqual(builder.dropped, 1)
        self.assertEqual([e.id for e in builder.events], ["e00001", "e00002"])

    def test_invalid_category(self):
        builder = EventBuilder()
        with self.assertRaises(ValueError):
            builder.emit("nope", "create")
        with self.assertRaises(ValueError):
            builder.emit("file", "explode")
