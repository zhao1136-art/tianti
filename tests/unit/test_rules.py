"""L3 规则引擎单元测试：YAML 子集、规则解析、特征索引、逻辑树、依赖 DAG、scope 实例化。"""

from __future__ import annotations

import unittest

from tianti.core.errors import RuleError
from tianti.rules import parser, yamlmini
from tianti.rules.base import Rule, RuleMeta
from tianti.rules.features import (
    FeatureIndex,
    expand_env,
    match_glob,
    normalize_path,
    normalize_registry_key,
)
from tianti.rules.matcher import Matcher, topological_order
from tianti.rules.parser import FeatureNode, RegexPattern, UnsupportedFeature
from tianti.trace.schema import Trace

ATTACK = "Execution::Command and Scripting Interpreter [T1059]"


# --------------------------------------------------------------------------- helpers


def make_trace(events: list[dict], *, name: str = "test.exe") -> Trace:
    payload = {
        "trace_id": "20261024T103500Z-7f3a9c21",
        "schema": "tianti.trace/1",
        "created_at": "2026-10-24T10:35:00+08:00",
        "sample": {"name": name, "sha256": "a" * 64, "size": 1, "type": "pe32"},
        "engine": {"version": "0.1.0", "backend": "replay", "policy": "deep"},
        "sandbox": {
            "host": "TEST",
            "isolation": [],
            "limits": {},
            "started_at": "",
            "ended_at": "",
            "terminated_by": "exited",
        },
        "events": events,
        "summary": {},
    }
    return Trace.from_dict(payload)


def event(eid: str, ts: float, category: str, action: str, **kwargs) -> dict:
    payload = {
        "id": eid,
        "ts": ts,
        "category": category,
        "action": action,
        "source": kwargs.pop("source", "etw:test"),
        "confidence": kwargs.pop("confidence", "high"),
    }
    payload.update(kwargs)
    return payload


def features(*lines: str) -> str:
    return "\n".join("    " + line for line in lines)


def rule_text(feature_block: str, *, name: str = "测试规则", scope: str = "process") -> str:
    return (
        "rule:\n"
        "  meta:\n"
        f"    name: '{name}'\n"
        f"    namespace: 'test/{name}'\n"
        f"    scope: '{scope}'\n"
        "    authors: [tianti]\n"
        "    att&ck:\n"
        f"      - '{ATTACK}'\n"
        "  features:\n" + feature_block + "\n"
    )


def parse_rule(feature_block: str, *, name: str = "测试规则", scope: str = "process") -> Rule:
    return parser.parse_rule_text(rule_text(feature_block, name=name, scope=scope), path="<test>")


# --------------------------------------------------------------------------- YAML


class YamlMiniTests(unittest.TestCase):
    def test_nested_mapping_and_sequence(self):
        text = (
            "rule:\n"
            "  meta:\n"
            "    name: demo\n"
            "    authors: [a, b]\n"
            "  features:\n"
            "    - and:\n"
            "      - file write: '*.locked'\n"
            "      - optional:\n"
            "        - registry set: '*\\run*'\n"
        )
        value = yamlmini.loads(text)
        self.assertEqual(value["rule"]["meta"]["name"], "demo")
        self.assertEqual(value["rule"]["meta"]["authors"], ["a", "b"])
        self.assertEqual(
            value["rule"]["features"],
            [{"and": [{"file write": "*.locked"}, {"optional": [{"registry set": "*\\run*"}]}]}],
        )

    def test_scalar_types(self):
        value = yamlmini.loads(
            "i: 42\n"
            "hex: 0x40\n"
            "f: 1.5\n"
            "t: true\n"
            "n: null\n"
            "s: 'hi there'\n"
            "d: \"line\\nnext\"\n"
            "bare: hello world\n"
        )
        self.assertEqual(value["i"], 42)
        self.assertEqual(value["hex"], 64)
        self.assertEqual(value["f"], 1.5)
        self.assertIs(value["t"], True)
        self.assertIsNone(value["n"])
        self.assertEqual(value["s"], "hi there")
        self.assertEqual(value["d"], "line\nnext")
        self.assertEqual(value["bare"], "hello world")

    def test_flow_collections(self):
        value = yamlmini.loads("a: [1, 2, 'x']\nb: {k: v, n: 3}\n")
        self.assertEqual(value["a"], [1, 2, "x"])
        self.assertEqual(value["b"], {"k": "v", "n": 3})

    def test_block_scalars(self):
        literal = yamlmini.loads("desc: |\n  a\n  b\n")
        folded = yamlmini.loads("desc: >-\n  a\n  b\n")
        self.assertEqual(literal["desc"], "a\nb\n")
        self.assertEqual(folded["desc"], "a b")

    def test_comments_and_quoted_hash(self):
        value = yamlmini.loads("a: 1  # tail\nb: 'x#y'\nc: \"#z\"\n")
        self.assertEqual(value, {"a": 1, "b": "x#y", "c": "#z"})

    def test_error_has_line_number(self):
        with self.assertRaises(yamlmini.YamlError) as caught:
            yamlmini.loads("a: 1\nb: 2\nb: 3\n")
        self.assertEqual(caught.exception.line, 3)
        with self.assertRaises(yamlmini.YamlError) as caught:
            yamlmini.loads("a:\n  - x\n   - y\n")
        self.assertGreaterEqual(caught.exception.line, 1)

    def test_unclosed_quote(self):
        with self.assertRaises(yamlmini.YamlError) as caught:
            yamlmini.loads("a: 'oops\n")
        self.assertEqual(caught.exception.line, 1)

    def test_anchor_unsupported(self):
        with self.assertRaises(yamlmini.YamlError):
            yamlmini.loads("a: &x 1\n")
        self.assertTrue(yamlmini.loads("") is None)


# --------------------------------------------------------------------------- parser


class RuleParserTests(unittest.TestCase):
    def test_full_meta_and_feature_tree(self):
        text = (
            "rule:\n"
            "  meta:\n"
            "    name: 写入 Run 键实现自启动\n"
            "    namespace: persistence/registry/run-key\n"
            "    scope: process\n"
            "    authors: [tianti]\n"
            "    description: demo\n"
            "    att&ck:\n"
            "      - 'Persistence::Registry Run Keys / Startup Folder [T1547.001]'\n"
            "    mbc:\n"
            "      - 'Persistence::Write Autostart [B0001]'\n"
            "    examples: [abc.exe]\n"
            "  features:\n"
            "    - and:\n"
            "      - registry set: '*\\CurrentVersion\\Run*'\n"
            "      - optional:\n"
            "        - process create: '*\\cmd.exe'\n"
        )
        rule = parser.parse_rule_text(text, path="mem.yml")
        self.assertEqual(rule.name, "写入 Run 键实现自启动")
        self.assertEqual(rule.meta.namespace, "persistence/registry/run-key")
        self.assertEqual(rule.meta.techniques(), ["T1547.001"])
        self.assertEqual(rule.meta.tactics(), ["TA0003"])
        self.assertEqual(rule.meta.mbc, ["Persistence::Write Autostart [B0001]"])
        root = rule.features[0]
        self.assertIsInstance(root, parser.AndNode)
        self.assertEqual(len(root.children), 2)
        registry = root.children[0]
        self.assertIsInstance(registry, FeatureNode)
        self.assertEqual((registry.kind, registry.action), ("registry", "set"))
        self.assertIsInstance(root.children[1], parser.OptionalNode)

    def test_scalar_shorthand_feature(self):
        rule = parse_rule(features("- and:", "  - allocate memory", "  - remote thread"))
        and_node = rule.features[0]
        kinds = [(node.kind, node.action) for node in and_node.children]
        self.assertEqual(kinds, [("memory", "alloc"), ("thread", "remote_create")])

    def test_count_specs(self):
        rule = parse_rule(features("- count(api(call, name=\"VirtualAllocEx\")): 3 or more"))
        node = rule.features[0]
        self.assertIsInstance(node, parser.CountNode)
        self.assertEqual(node.minimum, 3)
        self.assertIsNone(node.maximum)
        self.assertIsInstance(node.child, FeatureNode)
        self.assertEqual(node.child.kind, "api")
        self.assertEqual(node.child.value, "VirtualAllocEx")

        exact = parse_rule(features("- count(delete file): exactly 2")).features[0]
        self.assertEqual((exact.minimum, exact.maximum), (2, 2))

    def test_match_node(self):
        rule = parse_rule(features("- match: '其它规则'"))
        self.assertIsInstance(rule.features[0], parser.MatchNode)
        self.assertEqual(rule.features[0].rule_name, "其它规则")

    def test_string_regex(self):
        rule = parse_rule(features("- string: '/-enc/i'"))
        pattern = rule.features[0].value
        self.assertIsInstance(pattern, RegexPattern)
        self.assertTrue(pattern.compile().search("-ENC abc"))
        self.assertFalse(pattern.compile().search("plain"))

    def test_unsupported_feature_is_explicit(self):
        with self.assertRaises(UnsupportedFeature) as caught:
            parse_rule(features("- characteristic: 'does something'"))
        self.assertIn("characteristic", caught.exception.message)
        with self.assertRaises(UnsupportedFeature):
            parse_rule(features("- totally unknown feature: x"))

    def test_invalid_meta(self):
        with self.assertRaises(RuleError):
            parser.parse_rule_text(
                "rule:\n  meta:\n    name: x\n    scope: process\n  features:\n    - and:\n      - amsi\n"
            )
        with self.assertRaises(RuleError):
            parser.parse_rule_text(
                "rule:\n"
                "  meta:\n"
                "    name: x\n"
                "    namespace: n\n"
                "    scope: nope\n"
                "  features:\n"
                "    - amsi\n"
            )
        with self.assertRaises(RuleError):
            parser.parse_rule_text(
                "rule:\n"
                "  meta:\n"
                "    name: x\n"
                "    namespace: n\n"
                "    scope: process\n"
                "    att&ck: [broken-format]\n"
                "  features:\n"
                "    - amsi\n"
            )

    def test_yaml_syntax_error_is_wrapped(self):
        with self.assertRaises(RuleError) as caught:
            parser.parse_rule_text("rule: [unclosed\n", path="bad.yml")
        self.assertTrue(caught.exception.message.startswith("YAML 解析失败"))


# --------------------------------------------------------------------------- features


class FeatureIndexTests(unittest.TestCase):
    def test_path_normalization(self):
        self.assertEqual(
            normalize_path("%SystemRoot%\\System32\\CMD.EXE"),
            r"c:\windows\system32\cmd.exe",
        )
        self.assertEqual(normalize_path("C:/Temp//a.TXT"), r"c:\temp\a.txt")
        self.assertEqual(normalize_path('"C:\\Program Files\\X\\"'), r"c:\program files\x")
        self.assertEqual(expand_env("%windir%\\x"), r"C:\Windows\x")
        self.assertEqual(normalize_registry_key("HKEY_CURRENT_USER\\Software\\Run"),
                         r"hkcu\software\run")

    def test_glob_matching(self):
        self.assertTrue(match_glob(r"*\currentversion\run*", r"hkcu\software\microsoft\windows\currentversion\run\updater"))
        self.assertFalse(match_glob(r"*\currentversion\run*", r"hklm\software\uninstall\x"))
        self.assertTrue(match_glob(r"c:\windows\system32\svchost.exe", r"C:\Windows\System32\svchost.exe"))

    def test_index_tokens(self):
        trace = make_trace([
            event("e00001", 0.1, "file", "write", pid=1, target=r"C:\work\a.docx.locked",
                  args={"size": 4096, "entropy": 7.6}),
            event("e00002", 0.2, "registry", "set", pid=1,
                  target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X"),
            event("e00003", 0.3, "process", "create", pid=1, target=r"C:\Windows\System32\cmd.exe",
                  args={"command_line": "cmd.exe /c vssadmin delete shadows"}),
            event("e00004", 0.4, "network", "connect", pid=1,
                  target="45.148.10.82:8443", args={"proto": "tcp"}),
            event("e00005", 0.5, "api", "call", pid=1,
                  args={"api": "VirtualAllocEx", "ret": "0x1F0000"}),
            event("e00006", 0.6, "security", "amsi", pid=1, target="amsi.dll"),
            event("e00007", 0.7, "memory", "protect", pid=1,
                  args={"protect": "PAGE_EXECUTE_READWRITE"}),
        ])
        index = FeatureIndex.build(trace)
        self.assertEqual(index.token_events(r"file:write:c:\work\a.docx.locked"), ["e00001"])
        self.assertEqual(index.token_events(r"registry:set:hkcu\software\microsoft\windows\currentversion\run\x"), ["e00002"])
        self.assertEqual(index.token_events("process:c:\\windows\\system32\\cmd.exe"), ["e00003"])
        self.assertEqual(index.token_events("ip:45.148.10.82"), ["e00004"])
        self.assertEqual(index.token_events("port:8443"), ["e00004"])
        self.assertEqual(index.token_events("api:virtualallocex"), ["e00005"])
        self.assertEqual(index.token_events("security:amsi"), ["e00006"])
        self.assertEqual(index.nets["e00004"], {"ip": "45.148.10.82", "port": 8443, "host": None})
        self.assertIn(0x40, index.numbers["e00007"])

    def test_feature_matching(self):
        trace = make_trace([
            event("e00001", 0.1, "file", "write", pid=1,
                  target=r"C:\docs\a.docx.locked", args={"entropy": 7.8}),
            event("e00002", 0.2, "file", "write", pid=1, target=r"C:\docs\b.txt"),
            event("e00003", 0.3, "network", "connect", pid=1, target="1.2.3.4:8443"),
            event("e00004", 0.4, "network", "connect", pid=2, target="1.2.3.5:443"),
        ])
        index = FeatureIndex.build(trace)
        ids = index.match_feature(FeatureNode(kind="file", action="write", value=r"*\docs\*.locked"))
        self.assertEqual(ids, ["e00001"])
        entropy = index.match_feature(
            FeatureNode(kind="file", action="write", value="*", entropy_min=7.0)
        )
        self.assertEqual(entropy, ["e00001"])
        port = index.match_feature(FeatureNode(kind="network", action="port", value=8443))
        self.assertEqual(port, ["e00003"])
        not_443 = index.match_feature(FeatureNode(kind="network", action="port", value=443))
        self.assertEqual(not_443, ["e00004"])
        self.assertEqual(
            index.match_feature(FeatureNode(kind="string", value=RegexPattern("1\\.2\\.3\\.4"))),
            ["e00003"],
        )

    def test_network_ip_port_host_features(self):
        """回归：network 扩展特征 ip/port/host 必须能命中（含 args.domain 与 target 解析）。"""
        trace = make_trace([
            event("e00001", 0.1, "network", "connect", pid=1,
                  target="45.148.10.82:8443", args={"proto": "tcp", "domain": "evil.example.com"}),
            event("e00002", 0.2, "network", "connect", pid=1,
                  target="104.18.32.7:443", args={"domain": "update.example.com"}),
            event("e00003", 0.3, "network", "dns", pid=1, target="long-subdomain.example.com"),
        ])
        index = FeatureIndex.build(trace)
        self.assertEqual(
            index.match_feature(FeatureNode(kind="network", action="ip", value="45.148.10.82")),
            ["e00001"],
        )
        self.assertEqual(
            index.match_feature(FeatureNode(kind="network", action="port", value=8443)),
            ["e00001"],
        )
        self.assertEqual(
            index.match_feature(FeatureNode(kind="network", action="port", value=[80, 443, 53])),
            ["e00002"],
        )
        self.assertEqual(
            index.match_feature(FeatureNode(kind="network", action="host", value="evil.example.com")),
            ["e00001"],
        )
        self.assertEqual(
            index.match_feature(FeatureNode(kind="network", action="host", value="*example.com")),
            ["e00001", "e00002", "e00003"],
        )
        self.assertEqual(
            index.match_feature(FeatureNode(kind="network", action="host", value="evil.example.com")),
            ["e00001"],
        )

    def test_empty_trace(self):
        index = FeatureIndex.build(make_trace([]))
        self.assertEqual(index.all_ids, frozenset())
        self.assertEqual(index.match_feature(FeatureNode(kind="file", action="write", value="*")), [])


# --------------------------------------------------------------------------- matcher


class MatcherLogicTests(unittest.TestCase):
    def _match(self, rules: list[Rule], records: list[dict], **kwargs) -> list:
        matcher = Matcher(rules, **kwargs)
        self.matches = matcher.match(make_trace(records))
        return self.matches

    def test_and_or_not(self):
        trace_events = [
            event("e00001", 0.1, "registry", "set", pid=1,
                  target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X"),
            event("e00002", 0.2, "file", "write", pid=1, target=r"C:\docs\a.locked"),
            event("e00003", 0.3, "network", "connect", pid=1, target="1.2.3.4:8443"),
        ]
        and_rule = parse_rule(features(
            "- and:",
            "  - registry set: '*\\currentversion\\run*'",
            "  - file write: '*.locked'",
        ), name="and_rule")
        self.assertEqual([m.name for m in self._match([and_rule], trace_events)], ["and_rule"])

        or_rule = parse_rule(features(
            "- or:",
            "  - file write: '*.docx'",
            "  - network connect",
        ), name="or_rule")
        self.assertEqual([m.name for m in self._match([or_rule], trace_events)], ["or_rule"])

        not_rule = parse_rule(features(
            "- and:",
            "  - network connect",
            "  - not:",
            "    - port: [80, 443, 53]",
        ), name="not_rule")
        self.assertEqual([m.name for m in self._match([not_rule], trace_events)], ["not_rule"])
        self.assertEqual(
            self._match([not_rule], [event("e00001", 0.1, "network", "connect", pid=1, target="1.2.3.4:443")]),
            [],
        )

    def test_network_connect_and_anchored_string_regex(self):
        """回归：/^...$/ 锚定正则与 network connect 组合（裸 IP 直连规则）。"""
        rule = parse_rule(features(
            "- and:",
            "  - network connect",
            "  - string: '/^\\d{1,3}(\\.\\d{1,3}){3}(:\\d+)?$/'",
        ), name="raw_ip_rule")
        raw_ip = [event("e00001", 0.1, "network", "connect", pid=1, target="45.148.10.82:8443")]
        domain = [event("e00001", 0.1, "network", "connect", pid=1,
                        target="update.example.com:443", args={"domain": "update.example.com"})]
        self.assertEqual([m.name for m in self._match([rule], raw_ip)], ["raw_ip_rule"])
        self.assertEqual(self._match([rule], domain), [])

    def test_optional(self):
        rule = parse_rule(features(
            "- and:",
            "  - registry set: '*\\run*'",
            "  - optional:",
            "    - process create: '*\\cmd.exe'",
            "    - process create: '*\\powershell.exe'",
        ), name="optional_rule")
        base = event("e00001", 0.1, "registry", "set", pid=1, target=r"HKCU\Software\Run\X")
        cmd = event("e00002", 0.2, "process", "create", pid=1, target=r"C:\Windows\System32\cmd.exe")
        self.assertEqual([m.name for m in self._match([rule], [base, cmd])], ["optional_rule"])
        self.assertEqual(self._match([rule], [base]), [])

    def test_count_exact_and_or_more(self):
        events = [
            event(f"e0000{i}", i * 0.1, "file", "write", pid=1, target=rf"C:\x\{i}.locked")
            for i in range(1, 4)
        ]
        exact2 = parse_rule(features("- count(file write): 2"), name="exact2")
        exact3 = parse_rule(features("- count(file write): 3"), name="exact3")
        atleast2 = parse_rule(features("- count(file write): 2 or more"), name="atleast2")
        names = {m.name for m in self._match([exact2, exact3, atleast2], events)}
        self.assertEqual(names, {"exact3", "atleast2"})

    def test_match_dependency(self):
        dependency = parse_rule(features("- file write: '*.locked'"), name="加密文件写入")
        parent = parse_rule(features(
            "- and:",
            "  - match: '加密文件写入'",
            "  - registry set: '*\\run*'",
        ), name="组合行为")
        events = [
            event("e00001", 0.1, "file", "write", pid=1, target=r"C:\x\a.locked"),
            event("e00002", 0.2, "registry", "set", pid=1, target=r"HKCU\Software\Run\X"),
        ]
        matched_names = {m.name for m in self._match([parent, dependency], events)}
        self.assertIn("组合行为", matched_names)
        self.assertIn("加密文件写入", matched_names)
        only_registry = [events[1]]
        self.assertEqual(self._match([parent, dependency], only_registry), [])

    def test_cycle_detection(self):
        first = parse_rule(features("- match: 'B'"), name="A")
        second = parse_rule(features("- match: 'A'"), name="B")
        with self.assertRaises(RuleError) as caught:
            topological_order([first, second])
        self.assertIn("环", caught.exception.message)

    def test_unknown_reference(self):
        rule = parse_rule(features("- match: '不存在'"), name="A")
        with self.assertRaises(RuleError):
            Matcher([rule])

    def test_process_scope_instances(self):
        rule = parse_rule(features("- file write: '*.locked'"), name="per_process")
        events = [
            event("e00001", 0.1, "file", "write", pid=1, target=r"C:\x\a.locked"),
            event("e00002", 0.2, "file", "write", pid=2, target=r"C:\y\b.txt"),
            event("e00003", 0.3, "file", "write", pid=2, target=r"C:\y\c.locked"),
        ]
        matches = self._match([rule], events)
        self.assertEqual(sorted(m.instance["pid"] for m in matches), [1, 2])

    def test_call_scope(self):
        rule = parse_rule(features("- api: VirtualAllocEx"), name="per_call", scope="call")
        events = [
            event("e00001", 0.1, "api", "call", pid=1, args={"api": "VirtualAllocEx"}),
            event("e00002", 0.2, "api", "call", pid=1, args={"api": "Sleep"}),
        ]
        matches = self._match([rule], events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].instance["event_id"], "e00001")

    def test_span_scope(self):
        rule = parse_rule(features("- registry set: '*\\run*'"), name="per_span", scope="span")
        events = [
            event("e00001", 0.5, "registry", "set", pid=1, target=r"HKCU\Software\Run\A"),
            event("e00002", 11.0, "registry", "set", pid=1, target=r"HKCU\Software\Run\B"),
        ]
        matches = self._match([rule], events, span_width=10.0)
        self.assertEqual(sorted(m.instance["window_start"] for m in matches), [0.0, 10.0])

    def test_file_scope(self):
        rule = parse_rule(features("- or:", "  - file write: '*.locked'"), name="per_sample", scope="file")
        matches = self._match([rule], [
            event("e00001", 0.1, "file", "write", pid=1, target=r"C:\x\a.locked"),
            event("e00002", 0.2, "file", "write", pid=2, target=r"C:\y\b.locked"),
        ])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].instance["sample"], "test.exe")

    def test_error_isolation(self):
        good = parse_rule(features("- file write: '*.locked'"), name="好规则")
        bad = Rule(
            meta=RuleMeta(name="坏规则", namespace="test/bad", scope="process", attack=[ATTACK]),
            features=[FeatureNode(kind="bogus", label="bogus")],
        )
        matcher = Matcher([bad, good])
        matches = matcher.match(make_trace([
            event("e00001", 0.1, "file", "write", pid=1, target=r"C:\x\a.locked")
        ]))
        self.assertEqual([m.name for m in matches], ["好规则"])
        self.assertEqual(len(matcher.errors), 1)
        self.assertIn("坏规则", matcher.errors[0])

    def test_evidence_ids_and_confidence(self):
        rule = parse_rule(features("- file write: '*.locked'"), name="证据规则")
        matches = self._match([rule], [
            event("e00001", 0.1, "file", "write", pid=1, target=r"C:\x\a.locked",
                  source="snapshot:file", confidence="medium"),
        ])
        self.assertEqual(len(matches), 1)
        evidence = matches[0].evidence
        self.assertTrue(evidence)
        self.assertTrue(all(ids for ids in evidence.values()))
        self.assertEqual(matches[0].confidence, "medium")
        self.assertEqual(matches[0].to_dict()["name"], "证据规则")


if __name__ == "__main__":
    unittest.main()
