"""规则匹配器：逻辑树求值、规则依赖 DAG、scope 实例化与命中缓存。

设计：
  - 规则依赖图（match 引用）先拓扑排序，保证被引用规则先求值；
  - 每个规则按 scope 实例化（process 按 pid / thread 按 tid / call 按 api 事件 /
    span 按时间窗 / file 按样本），实例内求值 features 逻辑树；
  - 单规则求值异常被隔离记录到 Matcher.errors，不影响其它规则；
  - 证据只记录事件 id，可回溯到 Trace。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ..core.errors import RuleError
from ..trace.schema import Trace
from .base import Rule, RuleMatch
from .features import FeatureIndex
from .parser import (
    AndNode,
    CountNode,
    FeatureNode,
    MatchNode,
    NotNode,
    OptionalNode,
    OrNode,
    SubscopeNode,
)

__all__ = ["Instance", "NodeResult", "Matcher", "topological_order", "build_dependencies"]

MAX_EVIDENCE_PER_FEATURE = 25


@dataclass(frozen=True)
class Instance:
    """一个 scope 实例（pid / tid / call / span / sample）。"""

    key: str
    meta: dict[str, Any]
    allowed: frozenset[str]
    ids: tuple[str, ...] = ()


@dataclass
class NodeResult:
    matched: bool = False
    count: int = 0
    evidence: dict[str, list[str]] = field(default_factory=dict)


def _merge_evidence(target: dict[str, list[str]], extra: dict[str, list[str]]) -> None:
    for label, ids in extra.items():
        if not ids:
            continue
        bucket = target.setdefault(label, [])
        for event_id in ids:
            if event_id not in bucket:
                bucket.append(event_id)


def _capped(ids: Iterable[str]) -> list[str]:
    return list(ids)[:MAX_EVIDENCE_PER_FEATURE]


def _flatten_ids(evidence: dict[str, list[str]]) -> list[str]:
    out: list[str] = []
    for ids in evidence.values():
        for event_id in ids:
            if event_id not in out:
                out.append(event_id)
    return out


def _iter_match_refs(node: Any, out: set[str]) -> None:
    if isinstance(node, MatchNode):
        out.add(node.rule_name)
        return
    if isinstance(node, (AndNode, OrNode, NotNode, OptionalNode, SubscopeNode)):
        for child in node.children:
            _iter_match_refs(child, out)
        return
    if isinstance(node, CountNode):
        _iter_match_refs(node.child, out)


def build_dependencies(rules: Iterable[Rule]) -> dict[str, list[str]]:
    """收集每条规则通过 match 引用到的其它规则名。"""
    dependencies: dict[str, list[str]] = {}
    for rule in rules:
        refs: set[str] = set()
        for node in rule.features:
            _iter_match_refs(node, refs)
        dependencies[rule.name] = sorted(refs)
    return dependencies


def topological_order(rules: Iterable[Rule]) -> list[Rule]:
    """依赖优先的拓扑序；未知引用/环抛 RuleError。"""
    rule_list = list(rules)
    by_name: dict[str, Rule] = {}
    for rule in rule_list:
        if rule.name in by_name:
            raise RuleError(f"规则重名: {rule.name!r}")
        by_name[rule.name] = rule
    dependencies = build_dependencies(rule_list)
    for name, refs in dependencies.items():
        for ref in refs:
            if ref not in by_name:
                raise RuleError(f"规则 {name!r} 引用了不存在的规则: {ref!r}", rule=name)
    state: dict[str, int] = {}
    order: list[str] = []

    def visit(name: str, stack: list[str]) -> None:
        status = state.get(name, 0)
        if status == 2:
            return
        if status == 1:
            cycle = " -> ".join(stack + [name])
            raise RuleError(f"规则 match 引用存在环: {cycle}", rule=name)
        state[name] = 1
        for ref in dependencies.get(name, ()):
            visit(ref, stack + [name])
        state[name] = 2
        order.append(name)

    for rule in rule_list:
        visit(rule.name, [])
    return [by_name[name] for name in order]


class Matcher:
    """对一批已解析规则做匹配；同一 FeatureIndex 可复用。"""

    def __init__(self, rules: Iterable[Rule], *, span_width: float = 10.0) -> None:
        self.rules = list(rules)
        if not self.rules:
            raise RuleError("没有可用的规则")
        self.by_name: dict[str, Rule] = {rule.name: rule for rule in self.rules}
        self.dependencies = build_dependencies(self.rules)
        self.order = topological_order(self.rules)
        self.span_width = max(0.001, float(span_width))
        self.errors: list[str] = []

    # ------------------------------------------------------------------ 对外
    def match(self, trace_or_index: Trace | FeatureIndex) -> list[RuleMatch]:
        index = (
            trace_or_index
            if isinstance(trace_or_index, FeatureIndex)
            else FeatureIndex.build(trace_or_index)
        )
        self.errors = []
        cache: dict[tuple[str, str], NodeResult] = {}
        matches: list[RuleMatch] = []
        # 同 scope 的实例只构建一次（54 条规则只会有 1~5 次实例化）
        instance_cache: dict[str, list[Instance]] = {}
        for rule in self.order:
            scope = rule.meta.scope
            try:
                instances = instance_cache.get(scope)
                if instances is None:
                    instances = self._instances(scope, index)
                    instance_cache[scope] = instances
            except Exception as exc:  # pragma: no cover - 防御性
                self.errors.append(f"{rule.name}: scope 实例化失败: {exc}")
                continue
            for instance in instances:
                try:
                    result = self._evaluate_rule(rule.name, index, instance, cache)
                except Exception as exc:
                    self.errors.append(f"{rule.name}[{instance.key}]: {exc}")
                    continue
                if result.matched:
                    matches.append(self._to_match(rule, instance, result, index))
        return matches

    # ------------------------------------------------------------------ scope
    def _instances(self, scope: str, index: FeatureIndex) -> list[Instance]:
        trace = index.trace
        sample_meta = {
            "sample": trace.sample.name,
            "sha256": trace.sample.sha256,
        }
        all_ids = index.all_ids
        all_ordered = tuple(event.id for event in index.events)
        if scope == "file":
            return [Instance(key="sample", meta=dict(sample_meta), allowed=all_ids, ids=all_ordered)]
        if scope == "call":
            instances: list[Instance] = []
            for event in index.events:
                if event.category == "api" and event.action == "call":
                    api_name = str(event.args.get("api") or "")
                    instances.append(
                        Instance(
                            key=f"call:{event.id}",
                            meta={"event_id": event.id, "api": api_name, "pid": event.pid},
                            allowed=frozenset([event.id]),
                            ids=(event.id,),
                        )
                    )
            return instances
        if scope == "span":
            buckets: dict[int, list[str]] = {}
            for event in index.events:
                bucket = int(event.ts // self.span_width)
                buckets.setdefault(bucket, []).append(event.id)
            instances = []
            for bucket in sorted(buckets):
                start = round(bucket * self.span_width, 6)
                end = round(start + self.span_width, 6)
                instances.append(
                    Instance(
                        key=f"span:{bucket}",
                        meta={"window_start": start, "window_end": end},
                        allowed=frozenset(buckets[bucket]),
                        ids=tuple(buckets[bucket]),
                    )
                )
            return instances
        if scope == "thread":
            groups: dict[int, list[str]] = {}
            for event in index.events:
                if event.tid is not None:
                    groups.setdefault(int(event.tid), []).append(event.id)
            if not groups:
                return [Instance(key="sample", meta=dict(sample_meta), allowed=all_ids, ids=all_ordered)]
            orphans = [event.id for event in index.events if event.tid is None]
            instances = []
            for tid in sorted(groups):
                ids = tuple(groups[tid] + orphans)
                instances.append(
                    Instance(key=f"thread:{tid}", meta={"tid": tid}, allowed=frozenset(ids), ids=ids)
                )
            return instances
        # 默认 process scope：按 pid 实例化
        groups = {}
        for event in index.events:
            if event.pid is not None:
                groups.setdefault(int(event.pid), []).append(event.id)
        if not groups:
            return [Instance(key="sample", meta=dict(sample_meta), allowed=all_ids, ids=all_ordered)]
        orphans = [event.id for event in index.events if event.pid is None]
        instances = []
        for pid in sorted(groups):
            ids = tuple(groups[pid] + orphans)
            instances.append(
                Instance(key=f"process:{pid}", meta={"pid": pid}, allowed=frozenset(ids), ids=ids)
            )
        return instances

    # ------------------------------------------------------------------ 求值
    def _evaluate_rule(
        self,
        name: str,
        index: FeatureIndex,
        instance: Instance,
        cache: dict[tuple[str, str], NodeResult],
    ) -> NodeResult:
        cache_key = (name, instance.key)
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        rule = self.by_name.get(name)
        if rule is None:
            raise RuleError(f"规则引用不存在: {name!r}", rule=name)
        evidence: dict[str, list[str]] = {}
        for node in rule.features:
            result = self._evaluate(node, index, instance, cache)
            if not result.matched:
                cached = NodeResult(matched=False)
                cache[cache_key] = cached
                return cached
            _merge_evidence(evidence, result.evidence)
        cached = NodeResult(matched=True, count=1, evidence=evidence)
        cache[cache_key] = cached
        return cached

    def _evaluate(
        self,
        node: Any,
        index: FeatureIndex,
        instance: Instance,
        cache: dict[tuple[str, str], NodeResult],
    ) -> NodeResult:
        if isinstance(node, FeatureNode):
            ids = index.match_feature(node, instance.allowed, instance.ids)
            if not ids:
                return NodeResult(matched=False)
            return NodeResult(
                matched=True,
                count=len(ids),
                evidence={node.label: _capped(ids)},
            )
        if isinstance(node, AndNode):
            evidence: dict[str, list[str]] = {}
            for child in node.children:
                result = self._evaluate(child, index, instance, cache)
                if not result.matched:
                    return NodeResult(matched=False)
                _merge_evidence(evidence, result.evidence)
            return NodeResult(matched=True, evidence=evidence)
        if isinstance(node, OrNode):
            for child in node.children:
                result = self._evaluate(child, index, instance, cache)
                if result.matched:
                    return result
            return NodeResult(matched=False)
        if isinstance(node, NotNode):
            for child in node.children:
                if self._evaluate(child, index, instance, cache).matched:
                    return NodeResult(matched=False)
            return NodeResult(matched=True)
        if isinstance(node, OptionalNode):
            evidence = {}
            matched = False
            for child in node.children:
                result = self._evaluate(child, index, instance, cache)
                if result.matched:
                    matched = True
                    _merge_evidence(evidence, result.evidence)
            if not matched:
                return NodeResult(matched=False)
            return NodeResult(matched=True, evidence=evidence)
        if isinstance(node, SubscopeNode):
            # v1：subscope 在同一实例内求值（不重新按子作用域拆分），已记录在 RULES.md
            evidence = {}
            for child in node.children:
                result = self._evaluate(child, index, instance, cache)
                if not result.matched:
                    return NodeResult(matched=False)
                _merge_evidence(evidence, result.evidence)
            return NodeResult(matched=True, evidence=evidence)
        if isinstance(node, CountNode):
            return self._evaluate_count(node, index, instance, cache)
        if isinstance(node, MatchNode):
            result = self._evaluate_rule(node.rule_name, index, instance, cache)
            if not result.matched:
                return NodeResult(matched=False)
            ids = _flatten_ids(result.evidence)
            return NodeResult(
                matched=True,
                count=result.count,
                evidence={node.label: _capped(ids)},
            )
        raise RuleError(f"未知的逻辑节点: {type(node).__name__}")

    def _evaluate_count(
        self,
        node: CountNode,
        index: FeatureIndex,
        instance: Instance,
        cache: dict[tuple[str, str], NodeResult],
    ) -> NodeResult:
        if isinstance(node.child, FeatureNode):
            ids = index.match_feature(node.child, instance.allowed, instance.ids)
            count = len(ids)
            ok = count >= node.minimum and (node.maximum is None or count <= node.maximum)
            if not ok:
                return NodeResult(matched=False)
            return NodeResult(
                matched=True,
                count=count,
                evidence={node.label: _capped(ids)},
            )
        result = self._evaluate(node.child, index, instance, cache)
        count = result.count if result.count else (1 if result.matched else 0)
        ok = result.matched and count >= node.minimum and (
            node.maximum is None or count <= node.maximum
        )
        if not ok:
            return NodeResult(matched=False)
        return NodeResult(matched=True, count=count, evidence=dict(result.evidence))

    # ------------------------------------------------------------------ 结果
    def _to_match(
        self,
        rule: Rule,
        instance: Instance,
        result: NodeResult,
        index: FeatureIndex,
    ) -> RuleMatch:
        evidence = {label: ids for label, ids in result.evidence.items() if ids}
        all_ids = _flatten_ids(evidence)
        confidences = {
            index.by_id[event_id].confidence
            for event_id in all_ids
            if event_id in index.by_id
        }
        if not confidences:
            confidence = "medium"
        elif "low" in confidences:
            confidence = "low"
        elif "medium" in confidences:
            confidence = "medium"
        else:
            confidence = "high"
        return RuleMatch(
            name=rule.name,
            namespace=rule.meta.namespace,
            scope=rule.meta.scope,
            instance=dict(instance.meta),
            attack=list(rule.meta.attack),
            mbc=list(rule.meta.mbc),
            evidence=evidence,
            confidence=confidence,
            source_path=rule.source_path or rule.meta.source_path,
        )
