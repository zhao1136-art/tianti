"""检测器 DSL 编译器：把 detectors/*.yml 编译为对 Trace 的谓词。

DSL（v1）
--------
    detector: <id>                 # 必填
    name/tactic/technique/severity/score/window_s
    match:                         # 必填，逻辑树
      all: [<node>, ...]           # 全部满足
      any: [<node>, ...]           # 任一满足
      not: <node>                  # 子节点不满足
      aggregate:                   # 聚合
        distinct: [target, ...]
        count: ">= 20"
        of: <node>                 # 可选，默认全部事件
      sequence:                    # 多步时序（按时间先后）
        steps: [<node>, ...]       # 或直接写列表
        within_s: 5                # 可选，首末步最大间隔
    suppress: [...]                # 见 suppress.py
    evidence: events|first|none

叶子节点键：category/action/target/image（glob，大小写不敏感）、target_in/contains/
prefix/suffix/regex、image_*、pid/ppid/tid、source/confidence、arg（子串 glob）、
arg_missing、entropy_gt/gte、size_gt/gte、arg_gt/gte/lt/lte、file_ext_in、path_under、
port_in/port_not_in、ip_public、domain_like、target_entropy_gt/target_len_gte/
target_max_label_len_gte。未知字段显式报错（不静默忽略）。

window_s 语义：存在一个长度为 window_s 的滑动时间窗，match 在窗内成立。
window_s=0 表示整条 trace 作为窗口。
"""

from __future__ import annotations

import bisect
import fnmatch
import ipaddress
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..core.errors import DetectorError
from ..trace.schema import Event, Trace
from .base import SEVERITIES, DetectorSpec
from .suppress import SuppressionRule, compile_rules

__all__ = [
    "AggregateNode",
    "AllNode",
    "AnyNode",
    "CompiledDetector",
    "Leaf",
    "Node",
    "NotNode",
    "SequenceNode",
    "compile_detector",
    "compile_node",
    "evaluate_detector",
    "root_process_event_ids",
]

DETECTOR_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
TACTIC_RE = re.compile(r"^TA\d{4}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
COUNT_RE = re.compile(r"^\s*(>=|<=|==|=|>|<)\s*(\d+)\s*$")
COUNT_OR_MORE_RE = re.compile(r"^\s*(\d+)\s*(?:or more|\+)\s*$", re.IGNORECASE)

#: 默认严重度 -> 基础分（YAML 未写 score 时使用，报告可解释）。
SEVERITY_DEFAULT_SCORE = {"low": 4.0, "medium": 8.0, "high": 18.0, "critical": 28.0}

#: 带 window_s 时最多尝试的锚点数（防止最坏情况爆炸；超出则视为未命中并记录）。
WINDOW_ANCHOR_LIMIT = 10000

LEAF_KEYS = {
    "category",
    "action",
    "target",
    "target_in",
    "target_contains",
    "target_prefix",
    "target_suffix",
    "target_regex",
    "image",
    "image_in",
    "image_contains",
    "image_prefix",
    "image_suffix",
    "image_regex",
    "pid",
    "ppid",
    "tid",
    "source",
    "confidence",
    "arg",
    "arg_missing",
    "entropy_gt",
    "entropy_gte",
    "size_gt",
    "size_gte",
    "arg_gt",
    "arg_gte",
    "arg_lt",
    "arg_lte",
    "file_ext_in",
    "path_under",
    "port_in",
    "port_not_in",
    "ip_public",
    "domain_like",
    "target_entropy_gt",
    "target_len_gte",
    "target_max_label_len_gte",
}


# ---------------------------------------------------------------------------
# 匹配工具
# ---------------------------------------------------------------------------


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _norm_path(value: Any) -> str:
    return _lower(value).replace("/", "\\")


def _glob(text: Any, pattern: str) -> bool:
    return fnmatch.fnmatchcase(_lower(text), _lower(pattern))


def _as_patterns(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _as_values(value: Any) -> list[str]:
    return [str(item).lower() for item in _as_patterns(value)]


def _to_float(value: Any, field_name: str, detector_id: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise DetectorError(f"检测器 {detector_id} 的 {field_name} 必须是数字: {value!r}") from exc


def _to_bool(value: Any, field_name: str, detector_id: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise DetectorError(f"检测器 {detector_id} 的 {field_name} 必须是布尔值: {value!r}")


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _split_host_port(target: str) -> tuple[str, int | None]:
    text = target or ""
    if text.startswith("["):
        end = text.find("]")
        if end > 0:
            host = text[1:end]
            rest = text[end + 1 :]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    return host, None
            return host, None
    if ":" not in text:
        return text, None
    host, _, port = text.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return text, None


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _field_value(event: Event, key: str) -> Any:
    if key.startswith("args."):
        return event.args.get(key[5:])
    if key in ("id", "ts", "category", "action", "pid", "tid", "ppid", "image", "target", "source", "confidence"):
        return getattr(event, key)
    return event.args.get(key)


def _flatten_events(groups: Iterable[Iterable[Event]]) -> list[Event]:
    seen: set[str] = set()
    out: list[Event] = []
    for group in groups:
        for event in group:
            if event.id in seen:
                continue
            seen.add(event.id)
            out.append(event)
    out.sort(key=lambda ev: (ev.ts, ev.id))
    return out


# ---------------------------------------------------------------------------
# DSL 节点
# ---------------------------------------------------------------------------


class Node:
    """逻辑树节点：match 返回证据事件列表（空列表也算命中），未命中返回 None。"""

    def match(self, events: list[Event]) -> list[Event] | None:
        raise NotImplementedError

    def anchors(self, events: list[Event]) -> list[Event]:
        return events

    def collect(self, events: list[Event]) -> list[Event]:
        out = [event for event in events if self.match([event]) is not None]
        return out

    def hints(self) -> tuple[set[str] | None, set[str] | None]:
        """事件预过滤提示：(category 集合, action 集合)；None 表示不限制。

        任一证据事件必然匹配某个正向叶子，因此按叶子约束的并集预过滤是保守安全的。
        """
        return None, None

    def monotone(self) -> bool:
        """窗口剪枝用：树对事件集合单调（加事件不会让命中消失）时，全局不命中 => 窗口必不命中。"""
        return True

    def describe(self) -> str:
        return self.__class__.__name__


class Leaf(Node):
    """单事件谓词。"""

    def __init__(self, payload: dict[str, Any], *, detector_id: str = "") -> None:
        unknown = set(payload) - LEAF_KEYS
        if unknown:
            raise DetectorError(
                f"检测器 {detector_id or '?'} 的 match 叶子含未知字段: {', '.join(sorted(unknown))}"
            )
        self.detector_id = detector_id
        self.categories = set(_as_values(payload.get("category")))
        self.actions = set(_as_values(payload.get("action")))
        self.target = _as_patterns(payload.get("target"))
        self.target_in = _as_patterns(payload.get("target_in"))
        self.target_contains = _as_values(payload.get("target_contains"))
        self.target_prefix = _as_values(payload.get("target_prefix"))
        self.target_suffix = _as_values(payload.get("target_suffix"))
        self.target_regex = [re.compile(item, re.IGNORECASE) for item in _as_patterns(payload.get("target_regex"))]
        self.image = _as_patterns(payload.get("image"))
        self.image_in = _as_patterns(payload.get("image_in"))
        self.image_contains = _as_values(payload.get("image_contains"))
        self.image_prefix = _as_values(payload.get("image_prefix"))
        self.image_suffix = _as_values(payload.get("image_suffix"))
        self.image_regex = [re.compile(item, re.IGNORECASE) for item in _as_patterns(payload.get("image_regex"))]
        self.pid = self._int(payload, "pid")
        self.ppid = self._int(payload, "ppid")
        self.tid = self._int(payload, "tid")
        self.source = _as_values(payload.get("source"))
        self.confidence = _as_values(payload.get("confidence"))
        self.arg: dict[str, list[str]] = {}
        for key, value in dict(payload.get("arg") or {}).items():
            self.arg[str(key)] = _as_patterns(value)
        self.arg_missing = _as_values(payload.get("arg_missing"))
        self.entropy_gt = self._num(payload, "entropy_gt")
        self.entropy_gte = self._num(payload, "entropy_gte")
        self.size_gt = self._num(payload, "size_gt")
        self.size_gte = self._num(payload, "size_gte")
        self.arg_gt = self._num_map(payload, "arg_gt")
        self.arg_gte = self._num_map(payload, "arg_gte")
        self.arg_lt = self._num_map(payload, "arg_lt")
        self.arg_lte = self._num_map(payload, "arg_lte")
        self.file_ext_in = _as_values(payload.get("file_ext_in"))
        self.path_under = [_norm_path(item) for item in _as_patterns(payload.get("path_under"))]
        self.port_in = self._int_list(payload, "port_in")
        self.port_not_in = self._int_list(payload, "port_not_in")
        self.ip_public = self._bool(payload, "ip_public")
        self.domain_like = self._bool(payload, "domain_like")
        self.target_entropy_gt = self._num(payload, "target_entropy_gt")
        self.target_len_gte = self._num(payload, "target_len_gte")
        self.target_max_label_len_gte = self._num(payload, "target_max_label_len_gte")
        self._has_target = bool(
            self.target
            or self.target_in
            or self.target_contains
            or self.target_prefix
            or self.target_suffix
            or self.target_regex
        )
        self._has_image = bool(
            self.image
            or self.image_in
            or self.image_contains
            or self.image_prefix
            or self.image_suffix
            or self.image_regex
        )
        if not any(
            [
                self.categories,
                self.actions,
                self.target,
                self.target_in,
                self.target_contains,
                self.target_prefix,
                self.target_suffix,
                self.target_regex,
                self.image,
                self.image_in,
                self.image_contains,
                self.image_prefix,
                self.image_suffix,
                self.image_regex,
                self.pid is not None,
                self.ppid is not None,
                self.tid is not None,
                self.source,
                self.confidence,
                self.arg,
                self.arg_missing,
                self.entropy_gt is not None,
                self.entropy_gte is not None,
                self.size_gt is not None,
                self.size_gte is not None,
                self.arg_gt,
                self.arg_gte,
                self.arg_lt,
                self.arg_lte,
                self.file_ext_in,
                self.path_under,
                self.port_in,
                self.port_not_in,
                self.ip_public is not None,
                self.domain_like is not None,
                self.target_entropy_gt is not None,
                self.target_len_gte is not None,
                self.target_max_label_len_gte is not None,
            ]
        ):
            raise DetectorError(f"检测器 {detector_id or '?'} 的空叶子节点（没有任何约束）")

    # -- 编译期辅助 ---------------------------------------------------------

    def _int(self, payload: dict[str, Any], key: str) -> int | None:
        if key not in payload or payload[key] is None:
            return None
        try:
            return int(payload[key])
        except (TypeError, ValueError) as exc:
            raise DetectorError(f"检测器 {self.detector_id or '?'} 的 {key} 必须是整数: {payload[key]!r}") from exc

    def _num(self, payload: dict[str, Any], key: str) -> float | None:
        if key not in payload or payload[key] is None:
            return None
        return _to_float(payload[key], key, self.detector_id or "?")

    def _bool(self, payload: dict[str, Any], key: str) -> bool | None:
        if key not in payload or payload[key] is None:
            return None
        return _to_bool(payload[key], key, self.detector_id or "?")

    def _num_map(self, payload: dict[str, Any], key: str) -> dict[str, float]:
        value = payload.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise DetectorError(f"检测器 {self.detector_id or '?'} 的 {key} 必须是 mapping")
        return {str(k): float(v) for k, v in value.items()}

    def _int_list(self, payload: dict[str, Any], key: str) -> list[int]:
        value = payload.get(key)
        if value is None:
            return []
        return [int(item) for item in _as_patterns(value)]

    # -- 运行时 -------------------------------------------------------------

    def match(self, events: list[Event]) -> list[Event] | None:
        out = [event for event in events if self._matches_event(event)]
        return out or None

    def collect(self, events: list[Event]) -> list[Event]:
        return [event for event in events if self._matches_event(event)]

    def hints(self) -> tuple[set[str] | None, set[str] | None]:
        return (set(self.categories) if self.categories else None,
                set(self.actions) if self.actions else None)

    def monotone(self) -> bool:
        return True

    def _matches_event(self, event: Event) -> bool:
        if self.categories:
            category = event.category
            if category not in self.categories and category.lower() not in self.categories:
                return False
        if self.actions:
            action = event.action
            if action not in self.actions and action.lower() not in self.actions:
                return False
        if self.pid is not None and event.pid != self.pid:
            return False
        if self.ppid is not None and event.ppid != self.ppid:
            return False
        if self.tid is not None and event.tid != self.tid:
            return False
        if self.source and not any(_glob(event.source, pattern) for pattern in self.source):
            return False
        if self.confidence:
            confidence = event.confidence
            if confidence not in self.confidence and confidence.lower() not in self.confidence:
                return False

        target = event.target or ""
        image = event.image or ""
        if self._has_target and not self._text_matches(
            target, self.target, self.target_in, self.target_contains,
            self.target_prefix, self.target_suffix, self.target_regex,
        ):
            return False
        if self._has_image and not self._text_matches(
            image, self.image, self.image_in, self.image_contains,
            self.image_prefix, self.image_suffix, self.image_regex,
        ):
            return False

        for key, patterns in self.arg.items():
            value = event.args.get(key)
            if value is None:
                return False
            if not any(_glob(value, pattern) for pattern in patterns):
                return False
        for key in self.arg_missing:
            if event.args.get(key) not in (None, ""):
                return False

        if self.entropy_gt is not None:
            value = _number(event.args.get("entropy"))
            if value is None or not value > self.entropy_gt:
                return False
        if self.entropy_gte is not None:
            value = _number(event.args.get("entropy"))
            if value is None or not value >= self.entropy_gte:
                return False
        if self.size_gt is not None:
            value = _number(event.args.get("size"))
            if value is None or not value > self.size_gt:
                return False
        if self.size_gte is not None:
            value = _number(event.args.get("size"))
            if value is None or not value >= self.size_gte:
                return False
        for key, threshold in self.arg_gt.items():
            value = _number(event.args.get(key))
            if value is None or not value > threshold:
                return False
        for key, threshold in self.arg_gte.items():
            value = _number(event.args.get(key))
            if value is None or not value >= threshold:
                return False
        for key, threshold in self.arg_lt.items():
            value = _number(event.args.get(key))
            if value is None or not value < threshold:
                return False
        for key, threshold in self.arg_lte.items():
            value = _number(event.args.get(key))
            if value is None or not value <= threshold:
                return False

        if self.file_ext_in:
            lowered = target.lower()
            if not any(lowered.endswith(ext) for ext in self.file_ext_in):
                return False
        if self.path_under:
            normalized = _norm_path(target)
            if not any(normalized.startswith(prefix) for prefix in self.path_under):
                return False

        if self.port_in or self.port_not_in:
            _, port = _split_host_port(target)
            if port is None:
                return False
            if self.port_in and port not in self.port_in:
                return False
            if self.port_not_in and port in self.port_not_in:
                return False

        if self.ip_public is not None or self.domain_like is not None:
            host, _ = _split_host_port(target)
            is_ip = False
            global_ip = False
            try:
                address = ipaddress.ip_address(host)
                is_ip = True
                global_ip = address.is_global
            except ValueError:
                is_ip = False
            if self.ip_public is not None and bool(global_ip) != self.ip_public:
                return False
            if self.domain_like is not None:
                looks_like_domain = bool(host) and not is_ip and "." in host
                if looks_like_domain != self.domain_like:
                    return False

        if self.target_entropy_gt is not None and not _shannon(target) > self.target_entropy_gt:
            return False
        if self.target_len_gte is not None and not len(target) >= self.target_len_gte:
            return False
        if self.target_max_label_len_gte is not None:
            labels = target.split(".")
            if not labels or max(len(label) for label in labels) < self.target_max_label_len_gte:
                return False
        return True

    @staticmethod
    def _text_matches(
        text: str,
        globs: list[str],
        in_patterns: list[str],
        contains: list[str],
        prefixes: list[str],
        suffixes: list[str],
        regexes: list[re.Pattern[str]],
    ) -> bool:
        if globs and not any(_glob(text, pattern) for pattern in globs):
            return False
        if in_patterns and not any(_glob(text, pattern) for pattern in in_patterns):
            return False
        lowered = _lower(text)
        if contains and not any(item in lowered for item in contains):
            return False
        if prefixes and not any(lowered.startswith(item) for item in prefixes):
            return False
        if suffixes and not any(lowered.endswith(item) for item in suffixes):
            return False
        if regexes and not any(pattern.search(text) for pattern in regexes):
            return False
        return True


class AllNode(Node):
    def __init__(self, children: list[Node]) -> None:
        if not children:
            raise DetectorError("all 节点至少需要一个子节点")
        self.children = children

    def match(self, events: list[Event]) -> list[Event] | None:
        groups: list[list[Event]] = []
        for child in self.children:
            got = child.match(events)
            if got is None:
                return None
            groups.append(got)
        return _flatten_events(groups)

    def anchors(self, events: list[Event]) -> list[Event]:
        return self.children[0].anchors(events)

    def collect(self, events: list[Event]) -> list[Event]:
        groups = [child.collect(events) for child in self.children if not isinstance(child, NotNode)]
        if not groups:
            return []
        common = {event.id for event in groups[0]}
        for group in groups[1:]:
            common &= {event.id for event in group}
        return [event for event in events if event.id in common]

    def hints(self) -> tuple[set[str] | None, set[str] | None]:
        cats: set[str] | None = set()
        acts: set[str] | None = set()
        for child in self.children:
            child_cats, child_acts = child.hints()
            cats = None if cats is None or child_cats is None else cats | child_cats
            acts = None if acts is None or child_acts is None else acts | child_acts
        return cats, acts

    def monotone(self) -> bool:
        return all(child.monotone() for child in self.children)


class AnyNode(Node):
    def __init__(self, children: list[Node]) -> None:
        if not children:
            raise DetectorError("any 节点至少需要一个子节点")
        self.children = children

    def match(self, events: list[Event]) -> list[Event] | None:
        groups: list[list[Event]] = []
        for child in self.children:
            got = child.match(events)
            if got is not None:
                groups.append(got)
        if not groups:
            return None
        return _flatten_events(groups)

    def anchors(self, events: list[Event]) -> list[Event]:
        groups = [child.anchors(events) for child in self.children]
        return _flatten_events(groups)

    def collect(self, events: list[Event]) -> list[Event]:
        groups = [child.collect(events) for child in self.children if not isinstance(child, NotNode)]
        return _flatten_events(groups)

    def hints(self) -> tuple[set[str] | None, set[str] | None]:
        cats: set[str] | None = set()
        acts: set[str] | None = set()
        for child in self.children:
            child_cats, child_acts = child.hints()
            cats = None if cats is None or child_cats is None else cats | child_cats
            acts = None if acts is None or child_acts is None else acts | child_acts
        return cats, acts

    def monotone(self) -> bool:
        return all(child.monotone() for child in self.children)


class NotNode(Node):
    def __init__(self, child: Node) -> None:
        self.child = child

    def match(self, events: list[Event]) -> list[Event] | None:
        if self.child.match(events) is not None:
            return None
        return []

    def anchors(self, events: list[Event]) -> list[Event]:
        return events

    def collect(self, events: list[Event]) -> list[Event]:
        return []

    def hints(self) -> tuple[set[str] | None, set[str] | None]:
        return None, None

    def monotone(self) -> bool:
        return False


class _AllEventsNode(Node):
    """aggregate.of 省略时的隐式节点：匹配全部事件。"""

    def match(self, events: list[Event]) -> list[Event] | None:
        return list(events) or None

    def collect(self, events: list[Event]) -> list[Event]:
        return list(events)

    def hints(self) -> tuple[set[str] | None, set[str] | None]:
        return None, None


class AggregateNode(Node):
    def __init__(self, payload: dict[str, Any], *, detector_id: str = "") -> None:
        if not isinstance(payload, dict):
            raise DetectorError(f"检测器 {detector_id} 的 aggregate 必须是 mapping")
        unknown = set(payload) - {"distinct", "count", "of"}
        if unknown:
            raise DetectorError(f"检测器 {detector_id} 的 aggregate 含未知字段: {', '.join(sorted(unknown))}")
        self.detector_id = detector_id
        self.distinct = [str(item) for item in _as_patterns(payload.get("distinct"))]
        self.count_label, self._compare, self._count_monotone = _parse_count(payload.get("count"), detector_id)
        of_payload = payload.get("of")
        self.of: Node = _AllEventsNode() if of_payload is None else compile_node(of_payload, detector_id=detector_id)

    def collect(self, events: list[Event]) -> list[Event]:
        return self.of.collect(events)

    def anchors(self, events: list[Event]) -> list[Event]:
        return self.collect(events)

    def hints(self) -> tuple[set[str] | None, set[str] | None]:
        return self.of.hints()

    def monotone(self) -> bool:
        return self._count_monotone and self.of.monotone()

    def match(self, events: list[Event]) -> list[Event] | None:
        candidates = self.collect(events)
        if not candidates:
            measured = 0
        elif self.distinct:
            groups: dict[tuple[str, ...], None] = {}
            for event in candidates:
                key = tuple(_lower(_field_value(event, field_name)) for field_name in self.distinct)
                groups[key] = None
            measured = len(groups)
        else:
            measured = len(candidates)
        if not self._compare(measured):
            return None
        return sorted(candidates, key=lambda ev: (ev.ts, ev.id))


class SequenceNode(Node):
    def __init__(self, payload: Any, *, detector_id: str = "") -> None:
        self.detector_id = detector_id
        within_s: Any = None
        if isinstance(payload, dict):
            unknown = set(payload) - {"steps", "within_s"}
            if unknown:
                raise DetectorError(f"检测器 {detector_id} 的 sequence 含未知字段: {', '.join(sorted(unknown))}")
            steps_payload = payload.get("steps")
            within_s = payload.get("within_s")
        else:
            steps_payload = payload
        if not isinstance(steps_payload, list) or len(steps_payload) < 2:
            raise DetectorError(f"检测器 {detector_id} 的 sequence 至少需要 2 步")
        self.steps = [compile_node(step, detector_id=detector_id) for step in steps_payload]
        self.within_s = None if within_s is None else _to_float(within_s, "sequence.within_s", detector_id)

    def anchors(self, events: list[Event]) -> list[Event]:
        return self.steps[0].anchors(events)

    def collect(self, events: list[Event]) -> list[Event]:
        return self.match(events) or []

    def hints(self) -> tuple[set[str] | None, set[str] | None]:
        cats: set[str] | None = set()
        acts: set[str] | None = set()
        for step in self.steps:
            step_cats, step_acts = step.hints()
            cats = None if cats is None or step_cats is None else cats | step_cats
            acts = None if acts is None or step_acts is None else acts | step_acts
        return cats, acts

    def monotone(self) -> bool:
        return all(step.monotone() for step in self.steps)

    def match(self, events: list[Event]) -> list[Event] | None:
        evidence: list[Event] = []
        cursor = 0
        for step in self.steps:
            found: int | None = None
            is_leaf = isinstance(step, Leaf)
            for index in range(cursor, len(events)):
                if (step._matches_event(events[index]) if is_leaf else step.match([events[index]]) is not None):
                    found = index
                    break
            if found is None:
                return None
            evidence.append(events[found])
            cursor = found + 1
        if self.within_s is not None and evidence[-1].ts - evidence[0].ts > self.within_s:
            return None
        return evidence


def _parse_count(value: Any, detector_id: str):
    if value is None:
        raise DetectorError(f"检测器 {detector_id} 的 aggregate 缺少 count")
    if isinstance(value, int) and not isinstance(value, bool):
        threshold = int(value)
        return f"=={threshold}", lambda measured: measured == threshold, False
    text = str(value)
    match = COUNT_RE.match(text)
    if match:
        operator, raw = match.group(1), int(match.group(2))
        comparisons = {
            ">=": lambda measured: measured >= raw,
            "<=": lambda measured: measured <= raw,
            ">": lambda measured: measured > raw,
            "<": lambda measured: measured < raw,
            "==": lambda measured: measured == raw,
            "=": lambda measured: measured == raw,
        }
        return text.strip(), comparisons[operator], operator in (">=", ">")
    match = COUNT_OR_MORE_RE.match(text)
    if match:
        threshold = int(match.group(1))
        return f">={threshold}", lambda measured: measured >= threshold, True
    raise DetectorError(f"检测器 {detector_id} 的 aggregate.count 无法解析: {value!r}")


def compile_node(payload: Any, *, detector_id: str = "") -> Node:
    """把一棵 DSL 子树编译为 Node。"""
    if not isinstance(payload, dict) or not payload:
        raise DetectorError(f"检测器 {detector_id} 的 match 节点必须是非空 mapping: {payload!r}")
    logic = [key for key in ("all", "any", "not", "aggregate", "sequence") if key in payload]
    if len(logic) > 1:
        raise DetectorError(f"检测器 {detector_id} 的 match 节点同时包含多个逻辑算子: {logic}")
    if logic:
        key = logic[0]
        extra = set(payload) - {key}
        if extra:
            raise DetectorError(
                f"检测器 {detector_id} 的 {key} 节点不能混入其它字段: {', '.join(sorted(extra))}"
            )
        value = payload[key]
        if key == "all":
            if not isinstance(value, list) or not value:
                raise DetectorError(f"检测器 {detector_id} 的 all 必须是非空列表")
            return AllNode([compile_node(item, detector_id=detector_id) for item in value])
        if key == "any":
            if not isinstance(value, list) or not value:
                raise DetectorError(f"检测器 {detector_id} 的 any 必须是非空列表")
            return AnyNode([compile_node(item, detector_id=detector_id) for item in value])
        if key == "not":
            return NotNode(compile_node(value, detector_id=detector_id))
        if key == "aggregate":
            return AggregateNode(value, detector_id=detector_id)
        return SequenceNode(value, detector_id=detector_id)
    return Leaf(payload, detector_id=detector_id)


# ---------------------------------------------------------------------------
# 检测器对象
# ---------------------------------------------------------------------------


@dataclass
class CompiledDetector:
    """YAML 检测器编译结果。"""

    spec: DetectorSpec
    root: Node
    suppress_rules: list[SuppressionRule] = field(default_factory=list)
    evidence_mode: str = "events"
    #: (category 集合, action 集合)，编译期算好，运行期用于事件预过滤
    hints: tuple[set[str] | None, set[str] | None] = (None, None)
    #: 是否“加事件不会让命中消失”的单调树（窗口剪枝用）
    monotone: bool = True

    @property
    def id(self) -> str:
        return self.spec.id

    def evaluate(self, trace: Trace) -> list[Event] | None:
        """返回命中证据事件；未命中返回 None。

        根进程创建事件（宿主启动命令行）不参与检测：其命令行属于执行器而非样本行为。
        """
        excluded = root_process_event_ids(trace)
        events = [event for event in trace.events if event.id not in excluded]
        if not events:
            return None

        # 1) 按叶子约束并集预过滤：不相关 category/action 的事件永远不可能成为证据
        categories, actions = self.hints
        if categories is not None or actions is not None:
            events = [
                event
                for event in events
                if (categories is None or event.category in categories)
                and (actions is None or event.action in actions)
            ]
            if not events:
                return None

        window = float(self.spec.window_s or 0.0)
        if window <= 0:
            return self.root.match(events)

        # 2) 窗口剪枝（避免 O(锚点数 × 窗口事件数)）
        span = events[-1].ts - events[0].ts
        if window >= span:
            # 单个窗口即可覆盖整条轨迹，无需逐锚点滑窗
            return self.root.match(events)

        global_match = self.root.match(events)
        if global_match is None:
            if self.monotone:
                # 单调树：整条轨迹不命中 => 任何子窗口都不可能命中
                return None
        elif self.monotone:
            ordered = sorted(global_match, key=lambda ev: (ev.ts, ev.id))
            if ordered[-1].ts - ordered[0].ts <= window:
                # 全局命中的证据链本身已落在窗口内
                return global_match

        timestamps = [event.ts for event in events]
        anchors = self.root.anchors(events)
        # 去重且按时间序，限制锚点数量防止最坏情况爆炸
        unique: list[Event] = []
        seen: set[str] = set()
        for anchor in sorted(anchors, key=lambda ev: (ev.ts, ev.id)):
            if anchor.id in seen:
                continue
            seen.add(anchor.id)
            unique.append(anchor)
        for anchor in unique[:WINDOW_ANCHOR_LIMIT]:
            left = bisect.bisect_left(timestamps, anchor.ts)
            right = bisect.bisect_right(timestamps, anchor.ts + window)
            got = self.root.match(events[left:right])
            if got is not None:
                return got
        return None

    def event_ids(self, events: list[Event] | None) -> list[str]:
        if not events:
            return []
        if self.evidence_mode == "none":
            return []
        ordered = sorted(events, key=lambda ev: (ev.ts, ev.id))
        if self.evidence_mode == "first":
            return [ordered[0].id]
        return [event.id for event in ordered]

    def detail(self, events: list[Event] | None) -> str:
        if not events:
            return "匹配成功"
        first = min(events, key=lambda ev: ev.ts)
        return f"命中 {len(events)} 条事件，首条 {first.id} @ {first.ts:.3f}s"


def _basename(path: Any) -> str:
    return Path(str(path or "").replace("\\", "/")).name.lower()


def root_process_event_ids(trace: Trace) -> set[str]:
    """根进程创建事件 id：其命令行是执行宿主/启动参数，不算样本自身行为。

    定义（Lead 决策）：
    - trace 里第一条 process:create；
    - image 或 target 与样本路径/文件名相同的 process:create（样本自身启动）。
    检测器评估时排除这些事件，但样本自己 spawn 的进程仍参与检测。
    """
    root_ids: set[str] = set()
    sample_base = _basename(trace.sample.name)
    extra = trace.extra or {}
    sample_paths = {
        str(extra[key]).replace("/", "\\").lower()
        for key in ("sample_path", "source_path", "path")
        if extra.get(key)
    }
    first_seen = False
    for event in trace.events:
        if event.category != "process" or event.action != "create":
            continue
        if not first_seen:
            root_ids.add(event.id)
            first_seen = True
        if not sample_base and not sample_paths:
            continue
        for candidate in (event.image, event.target):
            if not candidate:
                continue
            normalized = str(candidate).replace("/", "\\").lower()
            if _basename(candidate) == sample_base or normalized in sample_paths:
                root_ids.add(event.id)
                break
    return root_ids


def evaluate_detector(detector: CompiledDetector, trace: Trace) -> list[Event] | None:
    return detector.evaluate(trace)


# ---------------------------------------------------------------------------
# 编译入口
# ---------------------------------------------------------------------------


def compile_detector(payload: Any, *, source_path: str = "") -> CompiledDetector:
    if not isinstance(payload, dict):
        raise DetectorError(f"检测器文件 {source_path or '?'} 顶层必须是 mapping")
    detector_id = str(payload.get("detector") or payload.get("id") or "").strip()
    if not detector_id:
        raise DetectorError(f"检测器文件 {source_path or '?'} 缺少 detector 字段")
    if not DETECTOR_ID_RE.match(detector_id):
        raise DetectorError(f"检测器 id 非法（应为 lower_snake_case）: {detector_id!r}")

    unknown = set(payload) - {
        "detector",
        "id",
        "name",
        "tactic",
        "technique",
        "severity",
        "score",
        "window_s",
        "match",
        "suppress",
        "evidence",
        "description",
    }
    if unknown:
        raise DetectorError(f"检测器 {detector_id} 含未知顶层字段: {', '.join(sorted(unknown))}")

    severity = str(payload.get("severity", "medium")).lower()
    if severity not in SEVERITIES:
        raise DetectorError(f"检测器 {detector_id} 的 severity 非法: {severity!r}")
    score = _to_float(payload.get("score", SEVERITY_DEFAULT_SCORE[severity]), "score", detector_id)
    if score < 0:
        raise DetectorError(f"检测器 {detector_id} 的 score 不能为负")
    window_s = _to_float(payload.get("window_s", 0.0), "window_s", detector_id)
    if window_s < 0:
        raise DetectorError(f"检测器 {detector_id} 的 window_s 不能为负")
    tactic = str(payload.get("tactic") or "").strip()
    if tactic and not TACTIC_RE.match(tactic):
        raise DetectorError(f"检测器 {detector_id} 的 tactic 非法（应为 TAxxxx）: {tactic!r}")
    technique = str(payload.get("technique") or "").strip()
    if technique and not TECHNIQUE_RE.match(technique):
        raise DetectorError(f"检测器 {detector_id} 的 technique 非法（应为 Txxxx[.xxx]）: {technique!r}")

    match_payload = payload.get("match")
    if match_payload is None:
        raise DetectorError(f"检测器 {detector_id} 缺少 match")
    root = compile_node(match_payload, detector_id=detector_id)

    evidence_mode = str(payload.get("evidence", "events")).lower()
    if evidence_mode not in ("events", "first", "none"):
        raise DetectorError(f"检测器 {detector_id} 的 evidence 非法: {evidence_mode!r}")

    spec = DetectorSpec(
        id=detector_id,
        name=str(payload.get("name") or detector_id),
        tactic=tactic,
        technique=technique,
        severity=severity,
        score=score,
        window_s=window_s,
        source_path=source_path,
        raw=dict(payload),
    )
    return CompiledDetector(
        spec=spec,
        root=root,
        suppress_rules=compile_rules(payload.get("suppress")),
        evidence_mode=evidence_mode,
        hints=root.hints(),
        monotone=root.monotone(),
    )
