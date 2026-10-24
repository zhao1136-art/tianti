"""规则包加载与 lint（重名、缺 meta、未知特征统计、命名空间/ATT&CK 校验）。"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..core.errors import RuleError
from .base import Rule, RuleSet
from .parser import ATTACK_RE, SCOPES, parse_rule_file, UnsupportedFeature

__all__ = [
    "DEFAULT_RULES_DIR",
    "NAMESPACE_RE",
    "LintReport",
    "LoadResult",
    "default_rule_dirs",
    "iter_rule_files",
    "lint_rules",
    "load_rulepack",
]

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9_./-]*$")


def default_rule_dirs() -> list[Path]:
    root = DEFAULT_RULES_DIR
    dirs = [root / "capability", root / "attack"]
    existing = [path for path in dirs if path.is_dir()]
    if existing:
        return existing
    return [root]


def iter_rule_files(paths: Iterable[str | Path]) -> list[Path]:
    """递归收集 .yml/.yaml 规则文件；路径不存在时抛 RuleError（不静默）。"""
    files: list[Path] = []
    for path in paths:
        candidate = Path(path)
        if candidate.is_dir():
            for pattern in ("*.yml", "*.yaml"):
                files.extend(sorted(candidate.rglob(pattern)))
        elif candidate.is_file():
            files.append(candidate)
        else:
            raise RuleError(f"规则路径不存在: {candidate}", path=str(candidate))
    seen: set[str] = set()
    unique: list[Path] = []
    for item in files:
        key = str(item.resolve()).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


@dataclass
class LintReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "stats": dict(self.stats),
        }


@dataclass
class LoadResult:
    rule_set: RuleSet
    lint: LintReport
    files: list[str] = field(default_factory=list)

    @property
    def rules(self) -> list[Rule]:
        return self.rule_set.rules

    @property
    def ok(self) -> bool:
        return self.lint.ok

    @property
    def unsupported(self) -> list[str]:
        return list(self.rule_set.unsupported)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": list(self.files),
            "rules": len(self.rule_set.rules),
            "namespaces": sorted({rule.meta.namespace for rule in self.rule_set.rules}),
            "lint": self.lint.to_dict(),
            "unsupported": list(self.rule_set.unsupported),
        }


def lint_rules(rule_set: RuleSet, *, files: int | None = None) -> LintReport:
    """对规则包做静态检查；加载期错误/不支持项也一并汇总。"""
    report = LintReport()
    report.errors.extend(rule_set.errors)
    names = Counter(rule.name for rule in rule_set.rules)
    for name, count in sorted(names.items()):
        if count > 1:
            report.errors.append(f"规则名重复: {name!r} 出现 {count} 次")
    if not rule_set.rules:
        report.errors.append("规则包为空（没有成功加载任何规则）")
    namespaces: Counter[str] = Counter()
    scopes: Counter[str] = Counter()
    attacks = 0
    for rule in rule_set.rules:
        namespace = rule.meta.namespace
        if not namespace:
            report.errors.append(f"规则 {rule.name!r} 缺少 namespace")
        elif not NAMESPACE_RE.match(namespace):
            report.errors.append(f"规则 {rule.name!r} 的 namespace 格式非法: {namespace!r}")
        else:
            namespaces[namespace] += 1
        if rule.meta.scope not in SCOPES:
            report.errors.append(f"规则 {rule.name!r} 的 scope 非法: {rule.meta.scope!r}")
        scopes[rule.meta.scope] += 1
        if not rule.features:
            report.errors.append(f"规则 {rule.name!r} 没有 features")
        for entry in rule.meta.attack:
            if not ATTACK_RE.match(entry):
                report.errors.append(
                    f"规则 {rule.name!r} 的 att&ck 格式非法: {entry!r}"
                )
            else:
                attacks += 1
        if not rule.meta.attack:
            report.warnings.append(f"规则 {rule.name!r} 未声明 att&ck（评分拿不到战术权重）")
    report.stats = {
        "rules": len(rule_set.rules),
        "files": int(files or 0),
        "namespaces": dict(sorted(namespaces.items())),
        "scopes": dict(sorted(scopes.items())),
        "attack_entries": attacks,
        "unsupported": list(rule_set.unsupported),
        "load_errors": list(rule_set.errors),
        "duplicate_names": [name for name, count in names.items() if count > 1],
    }
    return report


def load_rulepack(paths: Iterable[str | Path] | None = None) -> LoadResult:
    """加载规则包（目录或文件列表）。解析失败/不支持项记录后继续，绝不静默。"""
    selected = list(paths) if paths is not None else default_rule_dirs()
    if not selected:
        raise RuleError("未提供规则路径")
    files = iter_rule_files(selected)
    if not files:
        raise RuleError(f"规则路径下没有 .yml/.yaml 文件: {[str(p) for p in selected]}")
    rule_set = RuleSet()
    seen: dict[str, str] = {}
    for path in files:
        try:
            rule = parse_rule_file(path)
        except UnsupportedFeature as exc:
            rule_set.unsupported.append(f"{path}: {exc.message}")
            continue
        except RuleError as exc:
            rule_set.errors.append(f"{path}: {exc.message}")
            continue
        if rule.name in seen:
            rule_set.errors.append(
                f"规则重名: {rule.name!r}（{seen[rule.name]} 与 {path}）"
            )
            continue
        seen[rule.name] = str(path)
        rule_set.rules.append(rule)
    lint = lint_rules(rule_set, files=len(files))
    return LoadResult(rule_set=rule_set, lint=lint, files=[str(path) for path in files])
