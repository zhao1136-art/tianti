"""Trace -> 特征倒排索引 + 路径/注册表归一化（capa 动态特征映射）。

事件映射（对照 docs/TRACE_SCHEMA.md §3.1）：
  file:*        -> file / write file / delete file / create file / open file
  registry:*    -> registry set / registry query / registry delete
  process:create-> process / create process
  image:load    -> load image
  network:connect/dns/listen -> ip / port / host（自研扩展）
  memory:*-     -> allocate memory / protect memory / write memory / map memory
  thread:*      -> create thread / remote thread
  security:*    -> amsi / etw / defender
  api:call      -> api / number / string
  service / scheduled_task / token -> 对应特征

索引结构：
  tokens: feature token -> [event id]（倒排，精确特征 O(1) 命中）
  by_action: (category, action) -> [event id]（通配/正则特征的回退候选集）
索引构建一次，规则匹配可反复使用。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable

from ..core.errors import RuleError
from ..trace.schema import Event, Trace
from .parser import FeatureNode, RegexPattern

__all__ = [
    "expand_env",
    "normalize_path",
    "normalize_registry_key",
    "match_glob",
    "match_string",
    "match_numbers",
    "event_strings",
    "event_numbers",
    "event_network",
    "FeatureIndex",
]

# 常见 Windows 环境变量在离线匹配时的展开值（大小写不敏感）。
_DEFAULT_ENV = {
    "systemroot": "C:\\Windows",
    "windir": "C:\\Windows",
    "systemdrive": "C:",
    "programfiles": "C:\\Program Files",
    "programfiles(x86)": "C:\\Program Files (x86)",
    "programdata": "C:\\ProgramData",
    "public": "C:\\Users\\Public",
    "temp": "C:\\Users\\Public\\AppData\\Local\\Temp",
    "tmp": "C:\\Users\\Public\\AppData\\Local\\Temp",
    "appdata": "C:\\Users\\Public\\AppData\\Roaming",
    "localappdata": "C:\\Users\\Public\\AppData\\Local",
    "userprofile": "C:\\Users\\Public",
    "username": "Public",
    "computername": "SANDBOX",
}

_ENV_RE = re.compile(r"%([A-Za-z_][A-Za-z0-9_()]*)%")


def expand_env(text: str) -> str:
    """展开 %VAR% 形式的环境变量；未知变量保持原样。"""

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        return _DEFAULT_ENV.get(name.lower(), match.group(0))

    return _ENV_RE.sub(repl, str(text))


@lru_cache(maxsize=4096)
def normalize_path(value: str) -> str:
    """文件/进程/映像路径归一化：展开变量、统一分隔符、去重、小写。"""
    text = str(value or "").strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    text = expand_env(text)
    text = text.replace("/", "\\")
    text = re.sub(r"\\{2,}", r"\\", text)
    # 去掉 \\?\ 前缀
    if text.startswith("\\\\?\\"):
        text = text[4:]
    if len(text) > 3 and text.endswith("\\"):
        text = text[:-1]
    return text.lower()


@lru_cache(maxsize=4096)
def normalize_registry_key(value: str) -> str:
    """注册表键归一化：大小写不敏感、环境变量展开、分隔符统一。"""
    text = normalize_path(value)
    # 常见根键缩写统一，便于规则书写 HKCU / HKEY_CURRENT_USER 均可
    aliases = (
        ("hkey_current_user", "hkcu"),
        ("hkey_local_machine", "hklm"),
        ("hkey_classes_root", "hkcr"),
        ("hkey_users", "hku"),
        ("hkey_current_config", "hkcc"),
    )
    for long_name, short_name in aliases:
        if text == long_name or text.startswith(long_name + "\\"):
            text = short_name + text[len(long_name) :]
            break
    return text


@lru_cache(maxsize=8192)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    out = ["^"]
    for char in pattern:
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
    out.append("$")
    return re.compile("".join(out), re.IGNORECASE)


def match_glob(pattern: str, text: str) -> bool:
    """大小写不敏感的通配符匹配（* 可跨分隔符）。"""
    return bool(_glob_regex(pattern).match(str(text or "")))


def match_string(pattern: Any, text: str) -> bool:
    """string 特征：/regex/flags 用正则，裸值按大小写不敏感子串。"""
    if pattern is None:
        return True
    text = str(text or "")
    if isinstance(pattern, RegexPattern):
        return bool(pattern.compile().search(text))
    if isinstance(pattern, list):
        return any(match_string(item, text) for item in pattern)
    return str(pattern).lower() in text.lower()


def match_numbers(pattern: Any, numbers: list[float]) -> bool:
    if pattern is None:
        return True
    if isinstance(pattern, list):
        return any(match_numbers(item, numbers) for item in pattern)
    for number in numbers:
        if isinstance(pattern, float) or isinstance(number, float):
            if abs(float(number) - float(pattern)) < 1e-9:
                return True
        elif int(number) == int(pattern):
            return True
    return False


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def event_strings(event: Event) -> list[str]:
    """事件里可用于 string 特征的文本：target、命令行与 args 中的字符串值。"""
    out: list[str] = []
    if event.target:
        out.append(str(event.target))
    args = event.args or {}
    command_line = args.get("command_line")
    if isinstance(command_line, str) and command_line:
        out.append(command_line)
    for value in args.values():
        if isinstance(value, str) and value not in out:
            out.append(value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str) and item not in out:
                    out.append(item)
    return out


_PROTECT_FLAGS = {
    "page_execute_readwrite": 0x40,
    "page_execute_writecopy": 0x80,
    "page_execute_read": 0x20,
    "page_execute": 0x10,
    "page_readwrite": 0x04,
    "page_readonly": 0x02,
    "page_noaccess": 0x01,
}
_NUMERIC_RE = re.compile(r"^[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)$")


def event_numbers(event: Event) -> list[float]:
    """事件数值特征：args 中的整数/浮点/十六进制字符串 + 内存保护标志。"""
    out: list[float] = []
    args = event.args or {}
    for value in args.values():
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            out.append(value)
        elif isinstance(value, float):
            out.append(value)
        elif isinstance(value, str) and _NUMERIC_RE.match(value.strip()):
            try:
                out.append(int(value, 0))
            except ValueError:
                continue
    protect = args.get("protect")
    if isinstance(protect, str):
        lowered = protect.lower()
        for name, flag in _PROTECT_FLAGS.items():
            if name in lowered:
                out.append(flag)
    return out


_IP_PORT_RE = re.compile(r"^\[?([0-9a-fA-F:.]+)\]?:([0-9]{1,5})$")
_DOMAIN_PORT_RE = re.compile(r"^([A-Za-z0-9._-]+):([0-9]{1,5})$")


def event_network(event: Event) -> dict[str, Any]:
    """解析网络事件的 ip / port / host（扩展特征）。"""
    info: dict[str, Any] = {"ip": None, "port": None, "host": None}
    if event.category != "network":
        return info
    args = event.args or {}
    for key in ("ip", "remote_ip", "destination_ip", "dst_ip", "address"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            info["ip"] = value.strip().lower()
            break
    for key in ("port", "remote_port", "destination_port", "dst_port"):
        value = args.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            info["port"] = int(value)
            break
        if isinstance(value, str) and value.strip().isdigit():
            info["port"] = int(value.strip())
            break
    for key in ("domain", "host", "hostname", "query_name", "server_name"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            info["host"] = value.strip().lower()
            break
    target = str(event.target or "").strip()
    host_part = target
    port_part: str | None = None
    if target.startswith("["):
        match = re.match(r"^\[([^\]]+)\](?::([0-9]{1,5}))?$", target)
        if match:
            host_part = match.group(1)
            port_part = match.group(2)
    elif target.count(":") == 1:
        left, right = target.split(":", 1)
        if right.isdigit():
            host_part = left
            port_part = right
    if info["ip"] is None and host_part and _is_ip(host_part):
        info["ip"] = host_part.lower()
    if info["port"] is None and port_part and port_part.isdigit():
        info["port"] = int(port_part)
    if info["host"] is None and host_part and not _is_ip(host_part):
        if event.action == "dns":
            info["host"] = host_part.lower()
        elif "." in host_part and re.match(r"^[A-Za-z0-9._-]+$", host_part):
            info["host"] = host_part.lower()
    return info


@dataclass
class FeatureIndex:
    """一次 Trace 的特征倒排索引；匹配阶段只读。"""

    trace: Trace
    events: list[Event] = field(default_factory=list)
    by_id: dict[str, Event] = field(default_factory=dict)
    by_category: dict[str, list[str]] = field(default_factory=dict)
    by_action: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    tokens: dict[str, list[str]] = field(default_factory=dict)
    strings: dict[str, list[str]] = field(default_factory=dict)
    text_blob: dict[str, str] = field(default_factory=dict)
    text_blob_lower: dict[str, str] = field(default_factory=dict)
    normalized_targets: dict[str, str] = field(default_factory=dict)
    numbers: dict[str, list[float]] = field(default_factory=dict)
    nets: dict[str, dict[str, Any]] = field(default_factory=dict)
    _all_ids: frozenset[str] = frozenset()
    _blob_cache: dict[tuple, str] = field(default_factory=dict)
    _text_candidates_cache: dict[tuple, tuple[str, ...]] = field(default_factory=dict)
    _number_candidates_cache: dict[tuple, tuple[str, ...]] = field(default_factory=dict)

    # ------------------------------------------------------------------ 构建
    @classmethod
    def build(cls, trace: Trace) -> "FeatureIndex":
        index = cls(trace=trace, events=list(trace.events))
        for event in index.events:
            index._add(event)
        index._all_ids = frozenset(index.by_id.keys())
        return index

    def _add(self, event: Event) -> None:
        eid = event.id
        category = event.category
        action = event.action
        self.by_id[eid] = event
        self.by_category.setdefault(category, []).append(eid)
        self.by_action.setdefault((category, action), []).append(eid)
        raw_strings = event_strings(event)
        blob = "\n".join(raw_strings)
        self.strings[eid] = raw_strings
        self.text_blob[eid] = blob
        self.text_blob_lower[eid] = blob.lower()
        self.normalized_targets[eid] = _normalize_target(category, event.target)
        self.numbers[eid] = event_numbers(event)
        self.nets[eid] = event_network(event)

        def token(name: str) -> None:
            self.tokens.setdefault(name, []).append(eid)

        target = event.target
        if category == "file" and target:
            normalized = normalize_path(str(target))
            token(f"file:{normalized}")
            token(f"file:{action}:{normalized}")
        elif category == "registry" and target:
            normalized = normalize_registry_key(str(target))
            token(f"registry:{normalized}")
            token(f"registry:{action}:{normalized}")
        elif category == "process" and target:
            normalized = normalize_path(str(target))
            token(f"process:{normalized}")
            token(f"process:{action}:{normalized}")
        elif category == "image" and target:
            normalized = normalize_path(str(target))
            token(f"image:{normalized}")
            token(f"image:{action}:{normalized}")
        elif category == "api":
            api_name = str(event.args.get("api") or "").strip()
            if api_name:
                token(f"api:{api_name.lower()}")
        elif category == "network":
            info = self.nets[eid]
            if info["ip"]:
                token(f"ip:{info['ip']}")
            if info["port"] is not None:
                token(f"port:{int(info['port'])}")
            if info["host"]:
                token(f"host:{info['host']}")
        elif category in ("service", "scheduled_task", "token", "memory", "thread", "security"):
            token(f"{category}:{action}")

    # ------------------------------------------------------------------ 查询
    def candidates(self, category: str, action: str | None = None) -> list[str]:
        if action is None:
            return self.by_category.get(category, [])
        return self.by_action.get((category, action), [])

    def token_events(self, token: str) -> list[str]:
        return self.tokens.get(token, [])

    @property
    def all_ids(self) -> frozenset[str]:
        return self._all_ids

    def _scan(self, category: str, action: str | None, allowed: frozenset[str] | set[str]) -> list[str]:
        return [eid for eid in self.candidates(category, action) if eid in allowed]

    def _exact(self, token: str, allowed: frozenset[str] | set[str]) -> list[str]:
        ids = self.tokens.get(token)
        if not ids:
            return []
        return [eid for eid in ids if eid in allowed]

    def _ordered_filter(self, ids: Iterable[str], allowed: frozenset[str] | set[str]) -> list[str]:
        """按整体 token 顺序过滤并按首次出现去重（token 列表本身按事件顺序构建）。"""
        out: list[str] = []
        seen: set[str] = set()
        for event_id in ids:
            if event_id in allowed and event_id not in seen:
                seen.add(event_id)
                out.append(event_id)
        return out

    def _ordered_ids(self, allowed: frozenset[str] | set[str]) -> tuple[str, ...]:
        """实例内按事件顺序排列的 id 备选（供 string/number/target 线性特征使用）。"""
        if len(allowed) == len(self._all_ids):
            return tuple(event.id for event in self.events)
        return tuple(event.id for event in self.events if event.id in allowed)

    # ------------------------------------------------------------------ 叶子特征求值
    def match_feature(
        self,
        node: FeatureNode,
        allowed: frozenset[str] | set[str] | None = None,
        ordered_ids: tuple[str, ...] | None = None,
    ) -> list[str]:
        """返回命中该叶子特征的事件 id 列表（按 trace 顺序、去重）。

        ordered_ids 为实例内已按事件顺序排好的候选 id，避免线性特征全量扫描。
        """
        allowed_ids = self._all_ids if allowed is None else allowed
        kind = node.kind
        action = node.action
        value = node.value
        # call 等小实例（单事件）直接逐事件判断，避免拿全局候选集做 O(全部事件) 过滤
        if ordered_ids is not None and len(ordered_ids) <= 8:
            return [event_id for event_id in ordered_ids if self._event_matches(node, event_id)]
        if kind in ("string", "substring"):
            base = ordered_ids if ordered_ids is not None else self._ordered_ids(allowed_ids)
            key = (len(base), base[0] if base else "", base[-1] if base else "")
            candidates = self._text_candidates_cache.get(key)
            if candidates is None:
                candidates = tuple(
                    event_id
                    for event_id in base
                    if self.by_id[event_id].category in _TEXT_CATEGORIES
                )
                self._text_candidates_cache[key] = candidates
        elif kind == "number":
            base = ordered_ids if ordered_ids is not None else self._ordered_ids(allowed_ids)
            key = (len(base), base[0] if base else "", base[-1] if base else "")
            candidates = self._number_candidates_cache.get(key)
            if candidates is None:
                candidates = tuple(
                    event_id
                    for event_id in base
                    if self.by_id[event_id].category in _NUMBER_CATEGORIES
                )
                self._number_candidates_cache[key] = candidates
        elif kind == "target":
            candidates = ordered_ids if ordered_ids is not None else self._ordered_ids(allowed_ids)
        try:
            if kind == "api":
                return self._match_api(value, allowed_ids)
            if kind == "file":
                return self._match_target(kind, action, value, allowed_ids, node.entropy_min)
            if kind == "registry":
                return self._match_target(kind, action, value, allowed_ids, None)
            if kind == "process":
                return self._match_target("process", "create", value, allowed_ids, None)
            if kind == "image":
                return self._match_target("image", "load", value, allowed_ids, None)
            if kind == "network":
                return self._match_network(action, value, allowed_ids)
            if kind in ("memory", "thread", "security", "service", "scheduled_task", "token"):
                return self._match_generic(kind, action, value, allowed_ids)
            if kind == "string":
                return self._match_strings(value, candidates)
            if kind == "substring":
                return self._match_substrings(value, candidates)
            if kind == "number":
                return self._match_numbers(value, candidates)
            if kind == "target":
                return self._match_targets(value, candidates)
        except RuleError:
            raise
        except Exception as exc:  # pragma: no cover - 防御性
            raise RuleError(f"特征求值失败 {node.label!r}: {exc}", rule=node.label) from exc
        raise RuleError(f"未知特征类型: {kind!r}")

    def _event_matches(self, node: FeatureNode, event_id: str) -> bool:
        """单事件特征判定：用于 call/thread 等小实例，避免全局候选扫描。"""
        event = self.by_id[event_id]
        category = event.category
        act = event.action
        kind = node.kind
        action = node.action
        value = node.value
        normalized = self.normalized_targets[event_id]
        if kind == "api":
            if category != "api" or act != "call":
                return False
            if value is None:
                return True
            api_name = str(event.args.get("api") or "").lower()
            values = value if isinstance(value, list) else [value]
            return any(match_glob(str(item).lower(), api_name) for item in values)
        if kind in ("file", "registry", "process", "image"):
            wanted_action = action
            if kind == "process":
                wanted_action = "create"
            elif kind == "image":
                wanted_action = "load"
            if category != kind:
                return False
            if wanted_action and act != wanted_action:
                return False
            if node.entropy_min is not None:
                entropy = event.args.get("entropy")
                if not (isinstance(entropy, (int, float)) and float(entropy) >= node.entropy_min):
                    return False
            return _target_matches_norm(kind, value, normalized)
        if kind == "network":
            if category != "network":
                return False
            info = self.nets[event_id]
            if action in ("ip", "port", "host"):
                field = info[action]
                if field is None:
                    return value is None
                if value is None:
                    return True
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if action == "port":
                        if int(item) == int(field):
                            return True
                    elif match_glob(str(item).lower(), str(field)):
                        return True
                return False
            if action and act != action:
                return False
            if value is None:
                return True
            values = value if isinstance(value, list) else [value]
            return any(
                match_glob(_pattern_text("network", str(item)), normalized) for item in values
            )
        if kind in ("memory", "thread", "security", "service", "scheduled_task", "token"):
            if category != kind:
                return False
            if action and act != action:
                return False
            if value is None:
                return True
            values = value if isinstance(value, list) else [value]
            return any(
                match_glob(_pattern_text(kind, str(item)), normalized) for item in values
            )
        if kind == "string":
            return self._string_matches_event(value, event_id)
        if kind == "substring":
            blob = self.text_blob_lower[event_id]
            values = value if isinstance(value, list) else ([value] if value is not None else [])
            return any(str(item).lower() in blob for item in values)
        if kind == "number":
            return match_numbers(value, self.numbers[event_id])
        if kind == "target":
            values = value if isinstance(value, list) else [value]
            return any(match_glob(_pattern_text("target", str(item)), normalized) for item in values)
        if kind == "os":
            return True
        raise RuleError(f"未知特征类型: {kind!r}")

    # -- 各类型实现 --------------------------------------------------------
    def _match_api(self, value: Any, allowed: Any) -> list[str]:
        if value is None:
            return self._scan("api", "call", allowed)
        values = value if isinstance(value, list) else [value]
        plain = all(not _has_wildcard(str(item)) for item in values)
        if plain:
            found: list[str] = []
            for item in values:
                found.extend(self._exact(f"api:{str(item).lower()}", allowed))
            return self._ordered_filter(found, allowed)
        out: list[str] = []
        for eid in self._scan("api", "call", allowed):
            api_name = str(self.by_id[eid].args.get("api") or "").lower()
            if any(match_glob(str(item).lower(), api_name) for item in values):
                out.append(eid)
        return out

    def _match_target(
        self,
        kind: str,
        action: str | None,
        value: Any,
        allowed: Any,
        entropy_min: float | None,
    ) -> list[str]:
        category = kind
        if kind == "process":
            action = "create"
        if kind == "image":
            action = "load"
        if entropy_min is not None:
            out: list[str] = []
            for eid in self._scan(category, action, allowed):
                if not _target_matches_norm(kind, value, self.normalized_targets[eid]):
                    continue
                entropy = self.by_id[eid].args.get("entropy")
                if isinstance(entropy, (int, float)) and float(entropy) >= entropy_min:
                    out.append(eid)
            return out
        values = value if isinstance(value, list) else ([value] if value is not None else [None])
        # 全为精确（无通配/正则）的值才用倒排 token 精确查询，否则回退候选扫描。
        if value is None:
            return self._scan(category, action, allowed)
        if _is_plain_patterns(value):
            found: list[str] = []
            for item in values:
                normalized = (
                    normalize_registry_key(str(item)) if category == "registry" else normalize_path(str(item))
                )
                token = f"{category}:{action}:{normalized}" if action else f"{category}:{normalized}"
                found.extend(self._exact(token, allowed))
            return self._ordered_filter(found, allowed)
        out: list[str] = []
        normalized_targets = self.normalized_targets
        for eid in self._scan(category, action, allowed):
            if _target_matches_norm(kind, value, normalized_targets[eid]):
                out.append(eid)
        return out

    def _match_network(self, action: str | None, value: Any, allowed: Any) -> list[str]:
        if action in ("ip", "port", "host"):
            if value is None:
                return [
                    eid
                    for eid in self._scan("network", None, allowed)
                    if self.nets[eid][action] is not None
                ]
            values = value if isinstance(value, list) else [value]
            if action == "port":
                found: list[str] = []
                for item in values:
                    if item is not None:
                        found.extend(self._exact(f"port:{int(item)}", allowed))
                return self._ordered_filter(found, allowed)
            if all(not _has_wildcard(str(item)) for item in values):
                found = []
                for item in values:
                    found.extend(self._exact(f"{action}:{str(item).lower()}", allowed))
                return self._ordered_filter(found, allowed)
            out: list[str] = []
            for eid in self._scan("network", None, allowed):
                field_value = self.nets[eid][action]
                if field_value is None:
                    continue
                if any(match_glob(str(item).lower(), str(field_value)) for item in values):
                    out.append(eid)
            return out
        category_action = action if action in ("connect", "dns", "listen", "send", "recv", "close") else None
        if value is None:
            return self._scan("network", category_action, allowed)
        out = []
        pattern = _pattern_text("network", str(value))
        normalized_targets = self.normalized_targets
        for eid in self._scan("network", category_action, allowed):
            if match_glob(pattern, normalized_targets[eid]):
                out.append(eid)
        return out

    def _match_generic(self, kind: str, action: str | None, value: Any, allowed: Any) -> list[str]:
        if value is None:
            return self._scan(kind, action, allowed)
        values = value if isinstance(value, list) else [value]
        out = []
        normalized_targets = self.normalized_targets
        for eid in self._scan(kind, action, allowed):
            target = normalized_targets[eid]
            if any(match_glob(_pattern_text(kind, str(item)), target) for item in values):
                out.append(eid)
        return out

    def _string_matches_event(self, value: Any, event_id: str) -> bool:
        """单事件 string 匹配：锚定正则逐字符串校验，其余走事件合并 blob。"""
        patterns = value if isinstance(value, list) else [value]
        blob = self.text_blob[event_id]
        for pattern in patterns:
            if isinstance(pattern, RegexPattern):
                source = pattern.source
                if source.startswith("^") or source.endswith("$"):
                    if any(match_string(pattern, text) for text in self.strings[event_id]):
                        return True
                    continue
            if match_string(pattern, blob):
                return True
        return False

    def _instance_blob(self, candidates: tuple[str, ...], *, lower: bool) -> str:
        key = (
            len(candidates),
            candidates[0] if candidates else "",
            candidates[-1] if candidates else "",
            lower,
        )
        cached = self._blob_cache.get(key)
        if cached is not None:
            return cached
        source = self.text_blob_lower if lower else self.text_blob
        blob = "\x01".join(source[event_id] for event_id in candidates)
        self._blob_cache[key] = blob
        return blob

    def _match_strings(self, value: Any, candidates: tuple[str, ...]) -> list[str]:
        if value is None:
            return []
        patterns = value if isinstance(value, list) else [value]
        # 性能优化：普通子串/非锚定正则用每事件合并 blob 一次匹配；
        # 但锚定正则（^ 开头 / $ 结尾）语义依赖单条字符串边界，必须逐字符串匹配，
        # 否则多段文本拼接后的 blob 会让 ^...$ 锚定正则失败，导致 raw-ip 规则回归。
        blob_needles: list[str] = []
        blob_regexes: list[RegexPattern] = []
        per_string_patterns: list[Any] = []
        for pattern in patterns:
            if isinstance(pattern, RegexPattern):
                source = pattern.source
                if source.startswith("^") or source.endswith("$"):
                    per_string_patterns.append(pattern)
                else:
                    blob_regexes.append(pattern)
            elif isinstance(pattern, str):
                blob_needles.append(pattern.lower())
            else:
                per_string_patterns.append(pattern)
        # 先用实例合并 blob 做一次「快速否定」：整条规则的特征不可能命中时直接返回，
        # 避免 span/file scope 下每条规则都逐事件扫描上万 blob（绝大多数规则在此被剪枝）。
        if blob_needles:
            combined_lower = self._instance_blob(candidates, lower=True)
            blob_needles = [needle for needle in blob_needles if needle in combined_lower]
        if blob_regexes:
            combined = self._instance_blob(candidates, lower=False)
            blob_regexes = [
                pattern for pattern in blob_regexes if pattern.compile().search(combined)
            ]
        if not blob_needles and not blob_regexes and not per_string_patterns:
            return []
        out: list[str] = []
        blobs = self.text_blob
        lower_blobs = self.text_blob_lower
        all_strings = self.strings
        for event_id in candidates:
            matched = False
            if blob_needles:
                lower_blob = lower_blobs[event_id]
                for needle in blob_needles:
                    if needle in lower_blob:
                        matched = True
                        break
            if not matched and blob_regexes:
                blob = blobs[event_id]
                for pattern in blob_regexes:
                    if pattern.compile().search(blob):
                        matched = True
                        break
            if not matched and per_string_patterns:
                for text in all_strings[event_id]:
                    for pattern in per_string_patterns:
                        if match_string(pattern, text):
                            matched = True
                            break
                    if matched:
                        break
            if matched:
                out.append(event_id)
        return out

    def _match_substrings(self, value: Any, candidates: tuple[str, ...]) -> list[str]:
        """官方 capa substring 特征：事件文本子串匹配（大小写不敏感，近似实现）。"""
        if value is None:
            return []
        needles = value if isinstance(value, list) else [value]
        lowered = [str(item).lower() for item in needles]
        lower_blobs = self.text_blob_lower
        if not candidates:
            return []
        combined = self._instance_blob(candidates, lower=True)
        active = [needle for needle in lowered if needle in combined]
        if not active:
            return []
        out: list[str] = []
        for event_id in candidates:
            blob = lower_blobs[event_id]
            for needle in active:
                if needle in blob:
                    out.append(event_id)
                    break
        return out

    def _match_numbers(self, value: Any, candidates: tuple[str, ...]) -> list[str]:
        if value is None:
            return []
        out: list[str] = []
        for event_id in candidates:
            if match_numbers(value, self.numbers[event_id]):
                out.append(event_id)
        return out

    def _match_targets(self, value: Any, candidates: tuple[str, ...]) -> list[str]:
        out: list[str] = []
        values = value if isinstance(value, list) else [value]
        patterns = [_pattern_text("target", str(item)) for item in values]
        normalized_targets = self.normalized_targets
        for event_id in candidates:
            target = normalized_targets[event_id]
            for pattern in patterns:
                if match_glob(pattern, target):
                    out.append(event_id)
                    break
        return out


_PATH_KINDS = ("file", "process", "image")
# string/substring 特征只扫描可能携带文本参数的事件类别（动态 capa 中主要是 API 参数，
# 本引擎额外支持进程命令行与网络 target），显著降低 span/file scope 的线性扫描量。
_TEXT_CATEGORIES = frozenset({"api", "process", "network", "memory"})
# number 特征主要对应 API 参数数值（外加内存保护标志）
_NUMBER_CATEGORIES = frozenset({"api", "memory"})


def _normalize_target(category: str, target: Any) -> str:
    """构建期把事件 target 归一化一次，避免逐规则重复归一化。"""
    if target is None:
        return ""
    text = str(target)
    if category in _PATH_KINDS:
        return normalize_path(text)
    if category == "registry":
        return normalize_registry_key(text)
    return text.lower()


@lru_cache(maxsize=4096)
def _pattern_text(kind: str, text: str) -> str:
    """特征模式归一化（按特征类型），带缓存。"""
    if kind in _PATH_KINDS:
        return normalize_path(text)
    if kind == "registry":
        return normalize_registry_key(text)
    return text.lower()


def _target_matches_norm(kind: str, pattern: Any, normalized: str) -> bool:
    """用已归一化的 target 做匹配（pattern 侧归一化结果缓存）。"""
    if pattern is None:
        return True
    values = pattern if isinstance(pattern, list) else [pattern]
    for item in values:
        if isinstance(item, RegexPattern):
            if item.compile().search(normalized):
                return True
            continue
        if match_glob(_pattern_text(kind, str(item)), normalized):
            return True
    return False


def _has_wildcard(text: str) -> bool:
    return "*" in text or "?" in text


def _is_plain_patterns(value: Any) -> bool:
    items = value if isinstance(value, list) else [value]
    for item in items:
        if item is None:
            continue
        if isinstance(item, RegexPattern):
            return False
        if _has_wildcard(str(item)):
            return False
    return True


def _target_matches(kind: str, pattern: Any, target: Any) -> bool:
    if pattern is None:
        return True
    values = pattern if isinstance(pattern, list) else [pattern]
    text = str(target or "")
    if kind == "file":
        normalized = normalize_path(text)
        return any(
            match_glob(normalize_path(str(item)), normalized)
            if not isinstance(item, RegexPattern)
            else bool(item.compile().search(text))
            for item in values
        )
    if kind == "registry":
        normalized = normalize_registry_key(text)
        return any(
            match_glob(normalize_registry_key(str(item)), normalized)
            if not isinstance(item, RegexPattern)
            else bool(item.compile().search(text))
            for item in values
        )
    if kind in ("process", "image"):
        normalized = normalize_path(text)
        return any(
            match_glob(normalize_path(str(item)), normalized)
            if not isinstance(item, RegexPattern)
            else bool(item.compile().search(text))
            for item in values
        )
    lowered = text.lower()
    return any(
        bool(item.compile().search(text))
        if isinstance(item, RegexPattern)
        else match_glob(str(item).lower(), lowered)
        for item in values
    )
