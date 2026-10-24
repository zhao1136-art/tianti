"""规则包加载与 lint（重名、缺 meta、未知特征统计、命名空间/ATT&CK 校验）。"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..core.errors import RuleError
from .base import Rule, RuleSet
from .matcher import build_dependencies
from .parser import ATTACK_RE, SCOPES, parse_rule_file, UnsupportedFeature

__all__ = [
    "DEFAULT_RULES_DIR",
    "NAMESPACE_RE",
    "UPSTREAM_DIRNAME",
    "EXCLUDED_RULE_DIRS",
    "LintReport",
    "LoadResult",
    "default_rule_dirs",
    "is_rule_yaml",
    "iter_rule_files",
    "lint_rules",
    "load_rulepack",
]

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9_./-]*$")
# 官方 capa-rules 仓库里混有 CI/文档 YAML，扫描时排除
EXCLUDED_RULE_DIRS = {".github", "doc", "docs", "tests"}
UPSTREAM_DIRNAME = "upstream"


def is_rule_yaml(path: str | Path) -> bool:
    """首个有效行必须是 "rule:"（用于区分官方仓库里的非规则 YAML）。"""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped in ("---", "..."):
            continue
        return stripped.startswith("rule:")
    return False


def default_rule_dirs() -> list[Path]:
    root = DEFAULT_RULES_DIR
    dirs = [root / "capability", root / "attack"]
    existing = [path for path in dirs if path.is_dir()]
    if existing:
        return existing
    return [root]


def iter_rule_files(
    paths: Iterable[str | Path], *, include_upstream: bool = False
) -> list[Path]:
    """递归收集 .yml/.yaml 规则文件；路径不存在时抛 RuleError（不静默）。

    默认排除 <rules_dir>/upstream/**（上游可选规则包），并排除 .github/doc 等非规则目录；
    include_upstream=True 时才加载 upstream 子包。
    """
    files: list[Path] = []
    for path in paths:
        candidate = Path(path)
        if candidate.is_dir():
            for pattern in ("*.yml", "*.yaml"):
                for item in sorted(candidate.rglob(pattern)):
                    parts = item.relative_to(candidate).parts[:-1]
                    if any(part in EXCLUDED_RULE_DIRS for part in parts):
                        continue
                    if not include_upstream and UPSTREAM_DIRNAME in parts:
                        continue
                    files.append(item)
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


def _prune_unresolved_matches(rule_set: RuleSet) -> None:
    """丢弃 match 引用了未加载规则的规则（上游包会因 unsupported 规则缺位）。

    上游规则大量使用 match 引用；被引用的规则若因静态特征不支持而跳过，
    引用方也必须跳过，否则 Matcher 会因未知引用报错导致整个规则包不可用。
    """
    rules = list(rule_set.rules)
    names = {rule.name for rule in rules}
    changed = True
    while changed:
        changed = False
        for rule in list(rules):
            refs = build_dependencies([rule]).get(rule.name, [])
            missing = [ref for ref in refs if ref not in names]
            if not missing:
                continue
            rule_set.unsupported.append(
                f"{rule.source_path or rule.name}: match 引用未加载规则 {missing}，已跳过该规则"
            )
            rules.remove(rule)
            names.discard(rule.name)
            changed = True
    rule_set.rules = rules


def load_rulepack(
    paths: Iterable[str | Path] | None = None, *, include_upstream: bool = False
) -> LoadResult:
    """加载规则包（目录或文件列表）。解析失败/不支持项记录后继续，绝不静默。

    默认不加载 <rules_dir>/upstream/**；include_upstream=True 时递归加载上游可选包。
    """
    selected = list(paths) if paths is not None else default_rule_dirs()
    if not selected:
        raise RuleError("未提供规则路径")
    files = iter_rule_files(selected, include_upstream=include_upstream)
    if not files:
        raise RuleError(f"规则路径下没有 .yml/.yaml 文件: {[str(p) for p in selected]}")
    rule_set = RuleSet()
    seen: dict[str, str] = {}
    non_rule = 0
    for path in files:
        if not is_rule_yaml(path):
            non_rule += 1
            continue
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
    _prune_unresolved_matches(rule_set)
    lint = lint_rules(rule_set, files=len(files))
    lint.stats["non_rule_files"] = non_rule
    lint.stats["upstream_rules"] = sum(
        1 for rule in rule_set.rules if UPSTREAM_DIRNAME in Path(rule.source_path).parts
    )
    lint.stats["include_upstream"] = bool(include_upstream)
    return LoadResult(rule_set=rule_set, lint=lint, files=[str(path) for path in files])
