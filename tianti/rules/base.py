"""规则契约：Rule / RuleMeta / RuleMatch。

capa 10 风格：meta（name/namespace/scope/att&ck/mbc）+ features 逻辑树。
这里只放“数据契约”，解析在 parser.py、匹配在 matcher.py。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


@dataclass
class RuleMeta:
    name: str
    namespace: str = ""
    scope: str = "process"
    authors: list[str] = field(default_factory=list)
    description: str = ""
    attack: list[str] = field(default_factory=list)
    mbc: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    source_path: str = ""

    def techniques(self) -> list[str]:
        found: list[str] = []
        for entry in self.attack:
            found.extend(TECHNIQUE_RE.findall(entry))
        return sorted(set(found))

    def tactics(self) -> list[str]:
        """ATT&CK 条目形如 'Persistence::Registry Run Keys [T1547.001]'，映射到战术矩阵。"""
        mapping = {
            "initial-access": "TA0001",
            "execution": "TA0002",
            "persistence": "TA0003",
            "privilege-escalation": "TA0004",
            "defense-evasion": "TA0005",
            "credential-access": "TA0006",
            "discovery": "TA0007",
            "lateral-movement": "TA0008",
            "collection": "TA0009",
            "exfiltration": "TA0010",
            "command-and-control": "TA0011",
            "impact": "TA0040",
        }
        out: list[str] = []
        for entry in self.attack:
            prefix = entry.split("::", 1)[0].strip().lower().replace(" ", "-").replace("_", "-")
            tactic = mapping.get(prefix)
            if tactic:
                out.append(tactic)
        return sorted(set(out))


@dataclass
class Rule:
    meta: RuleMeta
    features: list[Any] = field(default_factory=list)
    source_path: str = ""

    @property
    def name(self) -> str:
        return self.meta.name


@dataclass
class RuleMatch:
    """一条规则的命中结果。instance 标识命中实例（pid / 事件 id / 时间窗）。"""

    name: str
    namespace: str = ""
    scope: str = "process"
    instance: dict[str, Any] = field(default_factory=dict)
    attack: list[str] = field(default_factory=list)
    mbc: list[str] = field(default_factory=list)
    evidence: dict[str, list[str]] = field(default_factory=dict)
    confidence: str = "medium"
    source_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "scope": self.scope,
            "instance": self.instance,
            "attack": list(self.attack),
            "mbc": list(self.mbc),
            "evidence": {key: list(value) for key, value in self.evidence.items()},
            "confidence": self.confidence,
            "source_path": self.source_path,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RuleMatch":
        return cls(
            name=str(payload.get("name", "")),
            namespace=str(payload.get("namespace", "")),
            scope=str(payload.get("scope", "process")),
            instance=dict(payload.get("instance") or {}),
            attack=[str(x) for x in (payload.get("attack") or [])],
            mbc=[str(x) for x in (payload.get("mbc") or [])],
            evidence={str(k): [str(x) for x in v] for k, v in dict(payload.get("evidence") or {}).items()},
            confidence=str(payload.get("confidence", "medium")),
            source_path=str(payload.get("source_path", "")),
        )


@dataclass
class RuleSet:
    rules: list[Rule] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rules)

    def names(self) -> list[str]:
        return [rule.name for rule in self.rules]

    def by_scope(self, scope: str) -> list[Rule]:
        return [rule for rule in self.rules if rule.meta.scope == scope]
