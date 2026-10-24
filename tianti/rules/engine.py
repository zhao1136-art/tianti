"""规则引擎门面：加载规则包 + 匹配 Trace + 单规则错误隔离。

对外接口（交付层约定）：
    RuleEngine(rules_dir: str | Path | None = None, *, span_width: float = 10.0,
               strict: bool = True)
    engine.match(trace: Trace) -> list[RuleMatch]
    match_trace(trace, rules_dir=None) -> list[RuleMatch]   # 模块级，内部缓存引擎

默认规则目录为仓库根 rules/（capability + attack）。显式传入不存在的目录或
规则包加载失败时抛 RuleError，绝不静默返回空结果。

TODO(v2 / 待办，Lead 已确认):
  - 官方 flare-capa 差分（tools/capa_diff.py）因本机网络不可达推迟，记录为 v2 质量项；
  - 内置规则当前全部 process scope；thread/call/span/file 已实现且有单测，按需再补规则；
  - RuleMeta 契约不加 severity/score，能力权重继续由 ATT&CK 战术推导。
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Iterable

from ..core.errors import RuleError
from ..trace.schema import Trace
from .base import RuleMatch
from .matcher import Matcher
from .packs import DEFAULT_RULES_DIR, LoadResult, default_rule_dirs, load_rulepack

__all__ = ["RuleEngine", "match_trace", "clear_engine_cache", "DEFAULT_RULES_DIR"]

_ENGINE_CACHE: dict[tuple[str, float, bool], "RuleEngine"] = {}
_ENGINE_LOCK = threading.Lock()


class RuleEngine:
    """一次加载、多次匹配。匹配阶段线程安全（Matcher 每次 match 内部状态独立）。"""

    def __init__(
        self,
        rules_dir: str | Path | None = None,
        *,
        paths: Iterable[str | Path] | None = None,
        span_width: float = 10.0,
        strict: bool = True,
    ) -> None:
        if paths is not None:
            selected: list[str | Path] = list(paths)
        elif rules_dir is not None:
            selected = [rules_dir]
        else:
            selected = default_rule_dirs()
        self.rules_dir = str(rules_dir) if rules_dir is not None else str(DEFAULT_RULES_DIR)
        self.load: LoadResult = load_rulepack(selected)
        self.ruleset = self.load.rule_set
        self.lint = self.load.lint
        if strict and not self.lint.ok:
            summary = "; ".join(self.lint.errors[:5])
            raise RuleError(f"规则包加载失败: {summary}", path=self.rules_dir)
        if not self.ruleset.rules:
            raise RuleError(f"规则包没有可用规则: {self.rules_dir}", path=self.rules_dir)
        self.matcher = Matcher(self.ruleset.rules, span_width=span_width)
        self._last_errors: list[str] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 匹配
    def match(self, trace: Trace) -> list[RuleMatch]:
        matches = self.matcher.match(trace)
        with self._lock:
            self._last_errors = list(self.matcher.errors)
        return matches

    def match_payload(self, payload: dict) -> list[RuleMatch]:
        return self.match(Trace.from_dict(payload))

    @property
    def errors(self) -> list[str]:
        """上一次匹配中被隔离的规则异常（单规则失败不影响其它规则）。"""
        return list(self._last_errors)

    @property
    def unsupported(self) -> list[str]:
        return list(self.ruleset.unsupported)

    @property
    def rules(self):
        return list(self.ruleset.rules)

    def stats(self) -> dict:
        return {
            "rules": len(self.ruleset.rules),
            "files": len(self.load.files),
            "namespaces": sorted({rule.meta.namespace for rule in self.ruleset.rules}),
            "unsupported": list(self.ruleset.unsupported),
            "lint": self.lint.to_dict(),
            "last_errors": list(self._last_errors),
        }

    def __len__(self) -> int:
        return len(self.ruleset.rules)


def _cache_key(rules_dir: str | Path | None, span_width: float, strict: bool) -> tuple[str, float, bool]:
    if rules_dir is None:
        resolved = str(DEFAULT_RULES_DIR.resolve())
    else:
        resolved = str(Path(rules_dir).resolve())
    return (resolved, float(span_width), bool(strict))


def match_trace(
    trace: Trace,
    rules_dir: str | Path | None = None,
    *,
    span_width: float = 10.0,
    strict: bool = True,
) -> list[RuleMatch]:
    """模块级便捷入口：内部缓存 RuleEngine，供 CLI/API/检测层直接调用。"""
    key = _cache_key(rules_dir, span_width, strict)
    with _ENGINE_LOCK:
        engine = _ENGINE_CACHE.get(key)
        if engine is None:
            engine = RuleEngine(rules_dir, span_width=span_width, strict=strict)
            _ENGINE_CACHE[key] = engine
    return engine.match(trace)


def clear_engine_cache() -> None:
    with _ENGINE_LOCK:
        _ENGINE_CACHE.clear()
