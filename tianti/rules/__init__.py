"""capa 兼容规则引擎：YAML 子集解析、规则包、特征索引、匹配与门面。

对外常用入口：
    from tianti.rules import RuleEngine, match_trace
    matches = match_trace(trace)                 # 内部缓存默认 rules/ 规则包
    engine = RuleEngine("rules")                 # 显式目录
    matches = engine.match(trace)                # list[RuleMatch]
"""

from .base import Rule, RuleMatch, RuleMeta, RuleSet
from .engine import DEFAULT_RULES_DIR, RuleEngine, clear_engine_cache, match_trace
from .features import FeatureIndex
from .packs import lint_rules, load_rulepack

__all__ = [
    "Rule",
    "RuleMatch",
    "RuleMeta",
    "RuleSet",
    "RuleEngine",
    "match_trace",
    "clear_engine_cache",
    "DEFAULT_RULES_DIR",
    "FeatureIndex",
    "lint_rules",
    "load_rulepack",
]
