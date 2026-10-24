"""capa 10 风格规则解析：YAML -> Rule（features 逻辑树 AST）。

支持逻辑：and / or / not / optional / count(...) / match 规则引用 / subscope。
支持特征：文件、注册表、进程、映像、网络（ip/port/host 自研扩展）、内存、线程、
安全组件、api、string、number、target（扩展）。
不支持的特征（characteristic/operand/property/instruction 等）显式抛
UnsupportedFeature，由 packs 记录到 RuleSet.unsupported 并跳过该规则，绝不静默。

仅依赖标准库与自研 yamlmini（运行时零第三方依赖）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.errors import RuleError
from . import yamlmini
from .base import Rule, RuleMeta

__all__ = [
    "SCOPES",
    "ATTACK_RE",
    "RegexPattern",
    "FeatureNode",
    "AndNode",
    "OrNode",
    "NotNode",
    "OptionalNode",
    "CountNode",
    "MatchNode",
    "SubscopeNode",
    "UnsupportedFeature",
    "RuleParser",
    "parse_rule_file",
    "parse_rule_payload",
    "parse_rule_text",
]

SCOPES = ("process", "thread", "call", "span", "file")

# "Persistence::Registry Run Keys / Startup Folder [T1547.001]"
ATTACK_RE = re.compile(r"^[^:]+::.+\[T\d{4}(?:\.\d{3})?\]$")


class UnsupportedFeature(RuleError):
    """规则使用了当前引擎不支持的特征/语法；该规则应被跳过并计数。"""

    code = "tianti.rule.unsupported"


# --------------------------------------------------------------------------- AST


@dataclass
class RegexPattern:
    """string 特征的正则形式：/pattern/flags。"""

    source: str
    flags: int = 0
    literal: str = ""
    _compiled: re.Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)

    def compile(self) -> re.Pattern[str]:
        compiled = self._compiled
        if compiled is None:
            compiled = re.compile(self.source, self.flags)
            self._compiled = compiled
        return compiled


@dataclass
class FeatureNode:
    """单个叶子特征。kind 对应 features.FeatureIndex 的查询维度。"""

    kind: str
    action: str | None = None
    value: Any = None
    label: str = ""
    entropy_min: float | None = None


@dataclass
class AndNode:
    children: list[Any] = field(default_factory=list)
    label: str = "and"


@dataclass
class OrNode:
    children: list[Any] = field(default_factory=list)
    label: str = "or"


@dataclass
class NotNode:
    children: list[Any] = field(default_factory=list)
    label: str = "not"


@dataclass
class OptionalNode:
    children: list[Any] = field(default_factory=list)
    label: str = "optional"


@dataclass
class CountNode:
    child: Any = None
    minimum: int = 1
    maximum: int | None = None
    label: str = "count"


@dataclass
class MatchNode:
    rule_name: str = ""
    label: str = "match"


@dataclass
class SubscopeNode:
    scope: str = "process"
    children: list[Any] = field(default_factory=list)
    label: str = "subscope"


# --------------------------------------------------------------------------- 特征表

_FEATURE_TABLE: dict[str, tuple[str, str | None]] = {
    # file
    "file": ("file", None),
    "write file": ("file", "write"),
    "file write": ("file", "write"),
    "create file": ("file", "create"),
    "file create": ("file", "create"),
    "delete file": ("file", "delete"),
    "file delete": ("file", "delete"),
    "read file": ("file", "read"),
    "file read": ("file", "read"),
    "open file": ("file", "open"),
    "file open": ("file", "open"),
    "rename file": ("file", "rename"),
    "file rename": ("file", "rename"),
    "set file attribute": ("file", "set_attr"),
    "file set attribute": ("file", "set_attr"),
    # registry
    "registry": ("registry", None),
    "registry set": ("registry", "set"),
    "set registry": ("registry", "set"),
    "registry create": ("registry", "create"),
    "create registry": ("registry", "create"),
    "registry delete": ("registry", "delete"),
    "delete registry": ("registry", "delete"),
    "registry query": ("registry", "query"),
    "query registry": ("registry", "query"),
    "registry rename": ("registry", "rename"),
    "rename registry": ("registry", "rename"),
    # process / image
    "process": ("process", "create"),
    "process create": ("process", "create"),
    "create process": ("process", "create"),
    "image": ("image", "load"),
    "load image": ("image", "load"),
    "image load": ("image", "load"),
    # network（ip/port/host 为自研扩展）
    "network": ("network", None),
    "network connect": ("network", "connect"),
    "connect": ("network", "connect"),
    "network dns": ("network", "dns"),
    "dns query": ("network", "dns"),
    "dns": ("network", "dns"),
    "network listen": ("network", "listen"),
    "listen": ("network", "listen"),
    "ip": ("network", "ip"),
    "ip address": ("network", "ip"),
    "port": ("network", "port"),
    "host": ("network", "host"),
    "hostname": ("network", "host"),
    "domain": ("network", "host"),
    # memory
    "allocate memory": ("memory", "alloc"),
    "memory alloc": ("memory", "alloc"),
    "alloc memory": ("memory", "alloc"),
    "protect memory": ("memory", "protect"),
    "memory protect": ("memory", "protect"),
    "write memory": ("memory", "write"),
    "memory write": ("memory", "write"),
    "map memory": ("memory", "map"),
    "memory map": ("memory", "map"),
    "free memory": ("memory", "free"),
    "memory free": ("memory", "free"),
    # thread
    "create thread": ("thread", "create"),
    "thread create": ("thread", "create"),
    "remote thread": ("thread", "remote_create"),
    "create remote thread": ("thread", "remote_create"),
    "thread remote create": ("thread", "remote_create"),
    # service / scheduled task / token
    "service": ("service", None),
    "create service": ("service", "create"),
    "service create": ("service", "create"),
    "start service": ("service", "start"),
    "service start": ("service", "start"),
    "delete service": ("service", "delete"),
    "service delete": ("service", "delete"),
    "scheduled task": ("scheduled_task", None),
    "create scheduled task": ("scheduled_task", "create"),
    "scheduled task create": ("scheduled_task", "create"),
    "create schedule task": ("scheduled_task", "create"),
    "run scheduled task": ("scheduled_task", "run"),
    "scheduled task run": ("scheduled_task", "run"),
    "token": ("token", None),
    "token impersonate": ("token", "impersonate"),
    "impersonate token": ("token", "impersonate"),
    # security
    "security": ("security", None),
    "amsi": ("security", "amsi"),
    "etw": ("security", "etw"),
    "defender": ("security", "defender"),
    # 通用
    "api": ("api", "call"),
    "string": ("string", None),
    "number": ("number", None),
    "target": ("target", None),
}

_ENTROPY_KEYS: dict[str, tuple[str, str | None]] = {
    "high entropy file": ("file", None),
    "write high entropy file": ("file", "write"),
    "file write high entropy": ("file", "write"),
    "high entropy write file": ("file", "write"),
    "encrypted file": ("file", "write"),
    "write encrypted file": ("file", "write"),
    "write encrypted data": ("file", "write"),
}

_UNSUPPORTED_KEYS = {
    "characteristic",
    "operand",
    "property",
    "offset",
    "mnemonic",
    "basic block",
    "instruction",
    "export",
    "import",
    "section",
    "function",
    "function name",
    "class",
    "com class",
    "com/class",
    "namespace",
    "bytes",
    "number of sections",
    "section characteristic",
    "entropy",
    "matcher",
    "os",
    "arch",
    "format",
    "call",
    "static string",
    "substring",
    "regex",
}

_STR_FLAG_MAP = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


def _normalize_key(key: Any) -> str:
    text = str(key).strip().lower()
    text = text.replace("_", " ").replace("-", " ")
    return " ".join(text.split())


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _split_inner(text: str) -> tuple[str, str | None]:
    """把 count 内部文本拆成 key / 可选 value，例如 'api: X' / 'registry set: Y'。"""
    index = text.find(": ")
    if index >= 0:
        return text[:index].strip(), text[index + 2 :].strip()
    if text.endswith(":"):
        return text[:-1].strip(), None
    return text.strip(), None


class RuleParser:
    """把一份 YAML 规则 payload 解析为 Rule。语义错误抛 RuleError / UnsupportedFeature。"""

    def __init__(self, *, path: str = "") -> None:
        self.path = path

    # ------------------------------------------------------------------ 入口
    def parse_payload(self, payload: Any) -> Rule:
        if not isinstance(payload, dict):
            raise RuleError("规则文件顶层必须是 mapping", path=self.path)
        body = payload.get("rule")
        if not isinstance(body, dict):
            if "meta" in payload and "features" in payload:
                body = payload
            else:
                raise RuleError("规则文件必须包含 rule: {meta, features}", path=self.path)
        meta = self._parse_meta(body.get("meta"))
        features_payload = body.get("features")
        if not isinstance(features_payload, list) or not features_payload:
            raise RuleError(
                f"规则 {meta.name!r} 的 features 必须是非空数组",
                path=self.path,
                rule=meta.name,
            )
        features = [self._parse_feature(item) for item in features_payload]
        return Rule(meta=meta, features=features, source_path=self.path)

    def parse_text(self, text: str) -> Rule:
        try:
            payload = yamlmini.loads(text, path=self.path)
        except yamlmini.YamlError as exc:
            raise RuleError(f"YAML 解析失败: {exc.message}", path=self.path, line=exc.line) from exc
        return self.parse_payload(payload)

    # ------------------------------------------------------------------ meta
    def _parse_meta(self, meta: Any) -> RuleMeta:
        if not isinstance(meta, dict):
            raise RuleError("缺少 meta 段（mapping）", path=self.path)
        name = meta.get("name")
        if not isinstance(name, str) or not name.strip():
            raise RuleError("meta.name 必须是非空字符串", path=self.path)
        name = name.strip()
        namespace = meta.get("namespace")
        if not isinstance(namespace, str) or not namespace.strip():
            raise RuleError(f"规则 {name!r} 缺少非空 meta.namespace", path=self.path, rule=name)
        scope = str(meta.get("scope", "process")).strip().lower()
        if scope not in SCOPES:
            raise RuleError(
                f"规则 {name!r} 的 scope 非法: {scope!r}（可选 {', '.join(SCOPES)}）",
                path=self.path,
                rule=name,
            )
        attack = _as_str_list(meta.get("att&ck", meta.get("attack")))
        for entry in attack:
            if not ATTACK_RE.match(entry):
                raise RuleError(
                    f"规则 {name!r} 的 att&ck 格式非法（需 'Tactic::Technique [Txxxx.xxx]'）: {entry!r}",
                    path=self.path,
                    rule=name,
                )
        return RuleMeta(
            name=name,
            namespace=namespace.strip(),
            scope=scope,
            authors=_as_str_list(meta.get("authors")),
            description=str(meta.get("description") or ""),
            attack=attack,
            mbc=_as_str_list(meta.get("mbc")),
            examples=_as_str_list(meta.get("examples")),
            source_path=self.path,
        )

    # ------------------------------------------------------------------ 逻辑节点
    def _parse_feature(self, item: Any) -> Any:
        # 便捷写法：list 中直接写 "- create service" 等价于 {create service: None}
        if isinstance(item, str):
            key = _normalize_key(item)
            if key in ("and", "or", "not", "optional", "match", "subscope") or key.startswith("count("):
                raise RuleError(f"逻辑节点 {item!r} 必须写成 mapping 形式", path=self.path)
            return self._parse_feature_key(item, key, None)
        if not isinstance(item, dict):
            raise RuleError(f"特征节点必须是 mapping，实际 {type(item).__name__}", path=self.path)
        if len(item) != 1:
            raise RuleError(
                f"特征节点必须恰好包含一个键，实际 {list(item.keys())!r}",
                path=self.path,
            )
        original_key, value = next(iter(item.items()))
        key = _normalize_key(original_key)

        if key in ("and", "or", "optional"):
            children = self._parse_children(value, key)
            classes = {"and": AndNode, "or": OrNode, "optional": OptionalNode}
            return classes[key](children=children, label=f"{key}({len(children)})")
        if key == "not":
            children = self._parse_children(value, "not")
            return NotNode(children=children, label=f"not({len(children)})")
        if key.startswith("count(") and key.endswith(")"):
            return self._parse_count(original_key, key, value)
        if key == "match":
            target = str(value or "").strip()
            if not target:
                raise RuleError("match 规则引用必须给出规则名", path=self.path)
            return MatchNode(rule_name=target, label=f"match: {target}")
        if key == "subscope":
            return self._parse_subscope(value)
        if key.startswith("api(") and key.endswith(")"):
            name = self._parse_api_args(original_key)
            return FeatureNode(kind="api", action="call", value=name, label=f"api: {name}")
        return self._parse_feature_key(original_key, key, value)

    def _parse_children(self, value: Any, label: str) -> list[Any]:
        if isinstance(value, list):
            if not value:
                raise RuleError(f"{label} 的子特征列表不能为空", path=self.path)
            return [self._parse_feature(child) for child in value]
        if isinstance(value, dict):
            return [self._parse_feature(value)]
        raise RuleError(f"{label} 需要 mapping 列表作为子特征", path=self.path)

    def _parse_subscope(self, value: Any) -> SubscopeNode:
        if not isinstance(value, dict) or len(value) != 1:
            raise RuleError("subscope 需要 {scope: [features]} 形式的 mapping", path=self.path)
        scope_raw, children_raw = next(iter(value.items()))
        scope = str(scope_raw).strip().lower()
        if scope not in SCOPES:
            raise UnsupportedFeature(
                f"不支持的 subscope: {scope!r}（可选 {', '.join(SCOPES)}）", path=self.path
            )
        return SubscopeNode(
            scope=scope,
            children=self._parse_children(children_raw, f"subscope {scope}"),
            label=f"subscope: {scope}",
        )

    # ------------------------------------------------------------------ count
    def _parse_count(self, original_key: str, key: str, value: Any) -> CountNode:
        inner_text = original_key[original_key.index("(") + 1 : original_key.rindex(")")].strip()
        if not inner_text:
            raise RuleError("count(...) 内部必须包含一个特征", path=self.path)
        minimum, maximum = self._parse_count_spec(value, original_key)
        child = self._parse_inner_feature(inner_text)
        rendered = f"{minimum}..{maximum if maximum is not None else 'n'}"
        return CountNode(
            child=child,
            minimum=minimum,
            maximum=maximum,
            label=f"count({inner_text}): {rendered}",
        )

    def _parse_count_spec(self, value: Any, original_key: str) -> tuple[int, int | None]:
        if isinstance(value, bool):
            raise RuleError(f"{original_key} 的计数非法: {value!r}", path=self.path)
        if isinstance(value, int):
            return int(value), int(value)
        text = str(value or "").strip().lower()
        match = re.match(r"^(?:exactly\s+)?(\d+)$", text)
        if match:
            return int(match.group(1)), int(match.group(1))
        match = re.match(r"^(\d+)\s+or\s+more$", text)
        if match:
            return int(match.group(1)), None
        match = re.match(r"^(?:at\s+least\s+)(\d+)$", text)
        if match:
            return int(match.group(1)), None
        match = re.match(r"^(\d+)\s+or\s+(?:fewer|less)$", text)
        if match:
            return 0, int(match.group(1))
        match = re.match(r"^(?:at\s+most\s+)(\d+)$", text)
        if match:
            return 0, int(match.group(1))
        raise RuleError(f"{original_key} 的计数非法: {value!r}", path=self.path)

    def _parse_inner_feature(self, inner_text: str) -> Any:
        key_part, value_part = _split_inner(inner_text)
        normalized = _normalize_key(key_part)
        if normalized.startswith("api(") and normalized.endswith(")"):
            name = self._parse_api_args(key_part)
            return FeatureNode(kind="api", action="call", value=name, label=f"api: {name}")
        return self._parse_feature_key(key_part, normalized, value_part)

    def _parse_api_args(self, key_text: str) -> str:
        match = re.search(r"""name\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s,)]+))""", key_text, re.IGNORECASE)
        if not match:
            raise RuleError(f"api(...) 缺少 name= 参数: {key_text!r}", path=self.path)
        return (match.group(1) or match.group(2) or match.group(3)).strip()

    # ------------------------------------------------------------------ 叶子特征
    def _parse_feature_key(self, original_key: str, key: str, value: Any) -> FeatureNode:
        entropy_min: float | None = None
        if key in _ENTROPY_KEYS:
            kind, action = _ENTROPY_KEYS[key]
            entropy_min = 7.0
        elif key in _FEATURE_TABLE:
            kind, action = _FEATURE_TABLE[key]
        elif key in _UNSUPPORTED_KEYS:
            raise UnsupportedFeature(
                f"不支持的特征: {str(original_key).strip()!r}", path=self.path
            )
        else:
            raise UnsupportedFeature(
                f"未知特征: {str(original_key).strip()!r}", path=self.path
            )
        converted = self._convert_value(kind, action, value, original_key)
        rendered = self._render_value(converted)
        label = f"{str(original_key).strip()}: {rendered}" if converted is not None else str(original_key).strip()
        return FeatureNode(
            kind=kind,
            action=action,
            value=converted,
            label=label,
            entropy_min=entropy_min,
        )

    def _convert_value(self, kind: str, action: str | None, value: Any, label: str) -> Any:
        if value is None:
            return None
        raw_items = value if isinstance(value, list) else [value]
        converted: list[Any] = []
        for item in raw_items:
            if kind == "string":
                converted.append(self._string_pattern(item, label))
            elif kind == "number":
                converted.append(self._number_value(item, label))
            elif kind == "network" and action == "port":
                try:
                    converted.append(int(item))
                except (TypeError, ValueError):
                    raise RuleError(f"{label} 的端口必须是整数: {item!r}", path=self.path)
            elif kind == "network" and action == "ip":
                converted.append(str(item).strip().lower())
            elif kind == "network" and action == "host":
                converted.append(str(item).strip().lower())
            elif kind == "api":
                converted.append(str(item).strip())
            else:
                converted.append(str(item))
        return converted[0] if not isinstance(value, list) else converted

    def _string_pattern(self, item: Any, label: str) -> Any:
        text = str(item)
        if len(text) >= 2 and text.startswith("/") and "/" in text[1:]:
            last = text.rfind("/")
            body = text[1:last]
            flags_text = text[last + 1 :].strip()
            flags = 0
            for char in flags_text:
                if char not in _STR_FLAG_MAP:
                    raise RuleError(f"{label} 的正则标志非法: {text!r}", path=self.path)
                flags |= _STR_FLAG_MAP[char]
            try:
                re.compile(body, flags)
            except re.error as exc:
                raise RuleError(f"{label} 的正则非法: {text!r}: {exc}", path=self.path) from exc
            return RegexPattern(source=body, flags=flags, literal=text)
        return text

    def _number_value(self, item: Any, label: str) -> int | float:
        if isinstance(item, bool):
            raise RuleError(f"{label} 的数值非法: {item!r}", path=self.path)
        if isinstance(item, int):
            return item
        if isinstance(item, float):
            return item
        text = str(item).strip()
        try:
            return int(text, 0)
        except ValueError:
            pass
        try:
            return float(text)
        except ValueError as exc:
            raise RuleError(f"{label} 的数值非法: {item!r}", path=self.path) from exc

    def _render_value(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return ", ".join(self._render_value(item) for item in value)
        if isinstance(value, RegexPattern):
            return value.literal
        return str(value)


# --------------------------------------------------------------------------- 函数式入口


def parse_rule_payload(payload: Any, *, path: str = "") -> Rule:
    return RuleParser(path=path).parse_payload(payload)


def parse_rule_text(text: str, *, path: str = "") -> Rule:
    return RuleParser(path=path).parse_text(text)


def parse_rule_file(path: str | Path) -> Rule:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleError(f"规则读取失败: {p}: {exc}", path=str(p)) from exc
    return RuleParser(path=str(p)).parse_text(text)
