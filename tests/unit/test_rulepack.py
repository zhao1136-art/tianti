"""规则包 lint 测试：数量、命名空间、ATT&CK 格式、重名、未知特征上报。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tianti.core.errors import RuleError
from tianti.rules.packs import (
    DEFAULT_RULES_DIR,
    default_rule_dirs,
    lint_rules,
    load_rulepack,
)

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules"
ATTACK = "Execution::Command and Scripting Interpreter [T1059]"
CRITICAL_PREFIXES = (
    "persistence/",
    "credential-access/",
    "defense-evasion/",
    "injection/",
    "impact/",
    "lateral-movement/",
    "command-and-control/",
)


def rule_yaml(
    name: str,
    *,
    namespace: str = "test/demo",
    scope: str = "process",
    feature_lines: str = "    - amsi\n",
    attack: str | None = ATTACK,
) -> str:
    attack_block = f"    att&ck:\n      - '{attack}'\n" if attack else ""
    return (
        "rule:\n"
        "  meta:\n"
        f"    name: '{name}'\n"
        f"    namespace: '{namespace}'\n"
        f"    scope: '{scope}'\n"
        "    authors: [tianti]\n"
        "    description: 测试规则\n" + attack_block +
        "  features:\n" + feature_lines
    )


def write_rule(directory: Path, filename: str, text: str) -> Path:
    path = directory / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class DefaultRulePackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.load = load_rulepack([RULES_DIR])

    def test_default_dir_exists(self):
        self.assertTrue(DEFAULT_RULES_DIR.is_dir())
        dirs = default_rule_dirs()
        self.assertGreaterEqual(len(dirs), 1)
        for path in dirs:
            self.assertTrue(path.exists())

    def test_rule_count_at_least_40(self):
        self.assertGreaterEqual(len(self.load.rules), 40)
        self.assertGreaterEqual(len(self.load.files), 40)

    def test_lint_passes(self):
        self.assertTrue(self.load.lint.ok, self.load.lint.errors[:5])
        self.assertEqual(self.load.rule_set.errors, [])
        self.assertEqual(self.load.lint.errors, [])
        self.assertEqual(self.load.unsupported, [])

    def test_namespaces_non_empty_and_valid(self):
        for rule in self.load.rules:
            self.assertTrue(rule.meta.namespace, f"{rule.name} 缺少 namespace")
            self.assertRegex(rule.meta.namespace, r"^[a-z0-9][a-z0-9_./-]*$")
        self.assertGreaterEqual(len(self.load.lint.stats["namespaces"]), 10)

    def test_names_unique(self):
        names = [rule.name for rule in self.load.rules]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(self.load.lint.stats["duplicate_names"], [])

    def test_attack_format(self):
        for rule in self.load.rules:
            self.assertTrue(rule.meta.attack, f"{rule.name} 缺少 att&ck")
            for entry in rule.meta.attack:
                self.assertRegex(entry, r"^[^:]+::.+\[T\d{4}(?:\.\d{3})?\]$")
            self.assertTrue(rule.meta.techniques(), f"{rule.name} att&ck 未包含技术编号")

    def test_scopes_and_features(self):
        for rule in self.load.rules:
            self.assertIn(rule.meta.scope, ("process", "thread", "call", "span", "file"))
            self.assertTrue(rule.features, f"{rule.name} 没有 features")

    def test_capability_coverage(self):
        namespaces = " ".join(self.load.lint.stats["namespaces"].keys())
        for expected in (
            "persistence/registry/run-key",
            "defense-evasion/amsi-patch",
            "injection/remote-thread",
            "credential-access/lsass-access",
            "impact/ransomware/high-entropy-writes",
            "command-and-control/network/non-standard-port",
            "discovery/host/whoami",
            "collection/staging/archive-utility",
        ):
            self.assertIn(expected, namespaces)

    def test_stats_consistent(self):
        stats = self.load.lint.stats
        self.assertEqual(stats["rules"], len(self.load.rules))
        self.assertEqual(sum(stats["namespaces"].values()), len(self.load.rules))
        self.assertEqual(stats["files"], len(self.load.files))

    def test_to_dict_serializable(self):
        import json

        payload = self.load.to_dict()
        json.dumps(payload, ensure_ascii=False)
        self.assertEqual(payload["rules"], len(self.load.rules))


class RulePackLoaderRobustnessTests(unittest.TestCase):
    def test_unsupported_feature_reported_and_rule_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            write_rule(
                directory,
                "unsupported.yml",
                rule_yaml(
                    "不支持的规则",
                    feature_lines="    - characteristic: 'executable memory'\n",
                ),
            )
            write_rule(directory, "valid.yml", rule_yaml("正常规则"))
            load = load_rulepack([directory])
            self.assertEqual(len(load.rules), 1)
            self.assertEqual(load.rules[0].name, "正常规则")
            self.assertEqual(len(load.unsupported), 1)
            self.assertIn("characteristic", load.unsupported[0])
            self.assertTrue(load.lint.ok, load.lint.errors)
            self.assertTrue(load.lint.stats["unsupported"])

    def test_parse_error_reported_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            write_rule(directory, "bad.yml", "rule: [unclosed\n")
            write_rule(directory, "valid.yml", rule_yaml("正常规则"))
            load = load_rulepack([directory])
            self.assertEqual(len(load.rules), 1)
            self.assertEqual(len(load.rule_set.errors), 1)
            self.assertFalse(load.lint.ok)
            self.assertIn("bad.yml", load.rule_set.errors[0])

    def test_duplicate_rule_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            write_rule(directory, "a.yml", rule_yaml("重名规则"))
            write_rule(directory, "b.yml", rule_yaml("重名规则"))
            load = load_rulepack([directory])
            self.assertEqual(len(load.rules), 1)
            self.assertTrue(any("重名" in error for error in load.rule_set.errors))
            self.assertFalse(load.lint.ok)

    def test_missing_path_raises(self):
        with self.assertRaises(RuleError):
            load_rulepack([Path(tempfile.gettempdir()) / "tianti-missing-rules-dir"])
        with self.assertRaises(RuleError):
            load_rulepack([])

    def test_empty_directory_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuleError):
                load_rulepack([Path(tmp)])

    def test_lint_detects_bad_namespace_and_scope(self):
        from tianti.rules.base import Rule, RuleMeta
        from tianti.rules.parser import FeatureNode
        from tianti.rules.base import RuleSet

        rule_set = RuleSet(
            rules=[
                Rule(
                    meta=RuleMeta(
                        name="坏规则",
                        namespace="Bad Namespace!",
                        scope="nope",
                        attack=["broken"],
                    ),
                    features=[FeatureNode(kind="amsi", action="amsi")],
                )
            ]
        )
        report = lint_rules(rule_set)
        self.assertFalse(report.ok)
        joined = " ".join(report.errors)
        self.assertIn("namespace", joined)
        self.assertIn("scope", joined)
        self.assertIn("att&ck", joined)


if __name__ == "__main__":
    unittest.main()
