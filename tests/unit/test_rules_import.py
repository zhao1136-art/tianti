"""上游 capa-rules 兼容性、导入工具与 include_upstream 隔离测试。"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tianti.core.errors import RuleError
from tianti.rules.engine import RuleEngine, clear_engine_cache
from tianti.rules.features import FeatureIndex
from tianti.rules.matcher import Matcher
from tianti.rules.packs import is_rule_yaml, iter_rule_files, load_rulepack
from tianti.rules.parser import (
    AtLeastNode,
    FeatureNode,
    MatchNode,
    UnsupportedFeature,
    parse_rule_text,
)
from tests.unit.test_rules import event, features, make_trace

ROOT = Path(__file__).resolve().parents[2]


def _load_import_tool():
    spec = importlib.util.spec_from_file_location(
        "import_capa_rules", ROOT / "tools" / "import_capa_rules.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


import_capa_rules = _load_import_tool()


def scoped_text(feature_block: str, *, dynamic: str = "call", static: str = "function",
                name: str = "上游规则") -> str:
    return (
        "rule:\n"
        "  meta:\n"
        f"    name: '{name}'\n"
        "    namespace: 'anti-analysis/test'\n"
        "    authors: [tianti]\n"
        "    scopes:\n"
        f"      static: '{static}'\n"
        f"      dynamic: '{dynamic}'\n"
        "  features:\n" + feature_block + "\n"
    )


def upstream_rule_text(name: str, *, ref: str = "", api_name: str = "CreateFileW") -> str:
    feature = f"    - match: '{ref}'\n" if ref else f"    - api: {api_name}\n"
    return (
        "rule:\n"
        "  meta:\n"
        f"    name: '{name}'\n"
        "    namespace: 'upstream/test'\n"
        "    scopes:\n"
        "      static: function\n"
        "      dynamic: call\n"
        "  features:\n" + feature
    )


class UpstreamParserCompatTests(unittest.TestCase):
    def test_number_symbol_annotation(self):
        rule = parse_rule_text(scoped_text(features(
            "- and:",
            "  - api: SetProcessMitigationPolicy",
            "  - number: 0x20007 = PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY",
        )))
        number_node = rule.features[0].children[1]
        self.assertIsInstance(number_node, FeatureNode)
        self.assertEqual(number_node.kind, "number")
        self.assertEqual(number_node.value, 0x20007)

    def test_api_module_function_forms(self):
        rule = parse_rule_text(scoped_text(features("- api(kernel32.GetTickCount)")))
        node = rule.features[0]
        self.assertIsInstance(node, FeatureNode)
        self.assertEqual((node.kind, node.value), ("api", "GetTickCount"))
        rule2 = parse_rule_text(scoped_text(features("- api(GetForegroundWindow)")))
        self.assertEqual(rule2.features[0].value, "GetForegroundWindow")

        # 匹配时按 function 名
        trace = make_trace([event("e00001", 0.1, "api", "call", pid=1, args={"api": "GetTickCount"})])
        self.assertEqual([m.name for m in Matcher([rule]).match(trace)], ["上游规则"])

    def test_description_key_ignored(self):
        rule = parse_rule_text(scoped_text(features(
            "- string: 'hello'",
            "  description: note about feature",
        )))
        self.assertIsInstance(rule.features[0], FeatureNode)
        # 逻辑节点里的 description-only 注释子节点被忽略
        rule2 = parse_rule_text(scoped_text(features(
            "- or:",
            "  - description: 只是注释",
            "  - api: CreateFileW",
        )))
        self.assertEqual(len(rule2.features[0].children), 1)

    def test_substring_feature(self):
        rule = parse_rule_text(scoped_text(features("- substring: '.dll'")))
        self.assertEqual((rule.features[0].kind, rule.features[0].value), ("substring", ".dll"))
        trace = make_trace([
            event("e00001", 0.1, "api", "call", pid=1,
                  args={"api": "LoadLibraryA", "module": "amsi.dll"}),
        ])
        index = FeatureIndex.build(trace)
        self.assertEqual(index.match_feature(rule.features[0]), ["e00001"])

    def test_os_windows_true_and_linux_unsupported(self):
        rule = parse_rule_text(scoped_text(features(
            "- and:",
            "  - os: windows",
            "  - api: CreateFileW",
        )))
        trace = make_trace([event("e00001", 0.1, "api", "call", pid=1, args={"api": "CreateFileW"})])
        self.assertEqual([m.name for m in Matcher([rule]).match(trace)], ["上游规则"])
        with self.assertRaises(UnsupportedFeature):
            parse_rule_text(scoped_text(features("- os: linux")))

    def test_scopes_mapping_and_original_scope(self):
        for dynamic, expected in (
            ("call", "call"),
            ("span of calls", "span"),
            ("file", "file"),
            ("process", "process"),
        ):
            rule = parse_rule_text(scoped_text(features("- api: CreateFileW"), dynamic=dynamic))
            self.assertEqual(rule.meta.scope, expected)
            self.assertEqual(rule.original_scope, dynamic)
        # 旧格式 meta.scope 兼容
        legacy = parse_rule_text(
            "rule:\n"
            "  meta:\n"
            "    name: 'legacy'\n"
            "    namespace: 'legacy/test'\n"
            "    scope: 'process'\n"
            "  features:\n"
            "    - api: CreateFileW\n"
        )
        self.assertEqual(legacy.meta.scope, "process")
        self.assertEqual(legacy.original_scope, "process")

    def test_unsupported_dynamic_scope(self):
        with self.assertRaises(UnsupportedFeature):
            parse_rule_text(scoped_text(features("- api: CreateFileW"), dynamic="unsupported"))
        # static-only（没有 dynamic 键）也跳过，不默认成 process
        text = (
            "rule:\n"
            "  meta:\n"
            "    name: 'static only'\n"
            "    namespace: 'static/test'\n"
            "    scopes:\n"
            "      static: function\n"
            "  features:\n"
            "    - api: CreateFileW\n"
        )
        with self.assertRaises(UnsupportedFeature):
            parse_rule_text(text)

    def test_count_inline_forms(self):
        rule = parse_rule_text(scoped_text(
            features("- count(api(kernel32.GetTickCount)): 2 or more"),
        ))
        node = rule.features[0]
        self.assertEqual((node.minimum, node.maximum), (2, None))
        self.assertEqual((node.child.kind, node.child.value), ("api", "GetTickCount"))

        number_rule = parse_rule_text(scoped_text(features("- count(number(2)): 2 or more")))
        self.assertEqual(number_rule.features[0].child.kind, "number")
        self.assertEqual(number_rule.features[0].child.value, 2)

        match_rule = parse_rule_text(scoped_text(features("- count(match(open file)): 3 or more")))
        self.assertIsInstance(match_rule.features[0].child, MatchNode)
        self.assertEqual(match_rule.features[0].child.rule_name, "open file")

    def test_n_or_more_node(self):
        rule = parse_rule_text(scoped_text(features(
            "- 2 or more:",
            "  - api: A",
            "  - api: B",
            "  - api: C",
        )))
        node = rule.features[0]
        self.assertIsInstance(node, AtLeastNode)
        self.assertEqual(node.minimum, 2)
        self.assertEqual(len(node.children), 3)


class ImportToolTests(unittest.TestCase):
    def _make_source(self, directory: Path) -> Path:
        source = directory / "capa-rules-master"
        (source / "anti-analysis").mkdir(parents=True)
        (source / ".github" / "workflows").mkdir(parents=True)
        (source / "anti-analysis" / "good.yml").write_text(
            upstream_rule_text("good rule"), encoding="utf-8"
        )
        (source / "anti-analysis" / "static.yml").write_text(
            "rule:\n"
            "  meta:\n"
            "    name: 'static rule'\n"
            "    namespace: 'anti-analysis/static'\n"
            "    scopes:\n"
            "      static: function\n"
            "      dynamic: call\n"
            "  features:\n"
            "    - offset: 0x10\n",
            encoding="utf-8",
        )
        (source / "anti-analysis" / "broken.yml").write_text("rule: [unclosed\n", encoding="utf-8")
        (source / "README.yml").write_text("name: ci\non: push\n", encoding="utf-8")
        (source / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
        (source / "LICENSE.txt").write_text("Apache License 2.0\n", encoding="utf-8")
        return source

    def test_classify_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self._make_source(Path(tmp))
            result = import_capa_rules.classify(source)
            self.assertEqual(result.rule_files, 3)
            self.assertEqual(len(result.ok), 1)
            self.assertEqual(len(result.unsupported), 1)
            self.assertEqual(len(result.errors), 1)
            self.assertEqual(len(result.non_rule), 1)  # README.yml；.github 已被排除
            self.assertEqual(dict(result.scope_distribution), {"call": 1})
            report = result.to_dict()
            self.assertEqual(report["counts"]["ok"], 1)
            self.assertGreaterEqual(report["counts"]["compat_rate"], 0.0)

    def test_copy_and_prune(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = self._make_source(base)
            dest = base / "rules" / "upstream"
            dest.mkdir(parents=True)
            stale = dest / "stale.yml"
            stale.write_text("rule: {}\n", encoding="utf-8")
            result = import_capa_rules.classify(source)
            summary = import_capa_rules.copy_rules(result, dest, prune=True)
            self.assertEqual(summary["copied"], 1)
            self.assertEqual(summary["pruned"], 1)
            self.assertFalse(stale.exists())
            self.assertTrue((dest / "anti-analysis" / "good.yml").is_file())
            self.assertTrue((dest / "LICENSE.txt").is_file())
            self.assertTrue((dest / "SOURCE.md").is_file())
            # 幂等：重复执行结果一致
            again = import_capa_rules.copy_rules(result, dest, prune=True)
            self.assertEqual(again["copied"], 1)
            self.assertEqual(again["pruned"], 0)

    def test_main_cli_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = self._make_source(base)
            dest = base / "dest"
            report_path = base / "report.json"
            out = io.StringIO()
            with redirect_stdout(out):
                code = import_capa_rules.main([
                    "--source", str(source), "--dest", str(dest), "--copy", "--prune",
                    "--report", str(report_path),
                ])
            self.assertEqual(code, 0)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["counts"]["ok"], 1)
            self.assertEqual(report["copy"]["copied"], 1)


class IncludeUpstreamTests(unittest.TestCase):
    def _make_tree(self, directory: Path) -> Path:
        root = directory / "rules"
        (root / "capability").mkdir(parents=True)
        (root / "upstream").mkdir()
        (root / "capability" / "a.yml").write_text(
            upstream_rule_text("自研规则", api_name="CreateFileW"), encoding="utf-8"
        )
        (root / "upstream" / "u.yml").write_text(
            upstream_rule_text("上游规则", api_name="VirtualAllocEx"), encoding="utf-8"
        )
        (root / "upstream" / "u2.yml").write_text(
            upstream_rule_text("引用缺失规则", ref="不存在的上游规则"), encoding="utf-8"
        )
        return root

    def test_default_excludes_upstream(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_tree(Path(tmp))
            files = iter_rule_files([root])
            self.assertEqual([path.name for path in files], ["a.yml"])
            default = load_rulepack([root])
            self.assertEqual([rule.name for rule in default.rules], ["自研规则"])
            self.assertEqual(default.lint.stats["upstream_rules"], 0)

            with_up = load_rulepack([root], include_upstream=True)
            names = {rule.name for rule in with_up.rules}
            self.assertEqual(names, {"自研规则", "上游规则"})
            self.assertGreaterEqual(with_up.lint.stats["upstream_rules"], 1)
            # 引用缺失规则的上游规则被剪枝并显式上报
            self.assertTrue(any("u2.yml" in item or "引用未加载" in item for item in with_up.unsupported))

    def test_engine_include_upstream_flag(self):
        clear_engine_cache()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_tree(Path(tmp))
            self.assertEqual(len(RuleEngine(root)), 1)
            up = RuleEngine(root, include_upstream=True)
            self.assertEqual(len(up), 2)
            self.assertTrue(up.include_upstream)
            self.assertEqual(up.stats()["upstream_rules"], 1)

    def test_is_rule_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            rule_file = directory / "r.yml"
            rule_file.write_text("rule:\n  meta: {}\n", encoding="utf-8")
            other = directory / "o.yml"
            other.write_text("# comment\nname: ci\n", encoding="utf-8")
            self.assertTrue(is_rule_yaml(rule_file))
            self.assertFalse(is_rule_yaml(other))


if __name__ == "__main__":
    unittest.main()
