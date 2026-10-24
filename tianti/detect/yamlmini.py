"""极简 YAML 子集解析器（零运行时依赖）——仅供 detectors/*.yml 使用。

支持子集：
- 缩进式 mapping / sequence（空格缩进，不支持 Tab）
- 行内 flow sequence [a, b]、flow mapping {a: 1}
- 单引号（字面量，两个单引号转义一个）与双引号（JSON 风格转义）标量
- 裸标量：bool / null / int / float / string
- # 行注释（引号内不生效）；空行忽略

不支持（遇到即显式报错，绝不静默）：
- 块标量（竖线/大于号）、锚点/别名、多文档、Tab 缩进、复杂键。

设计理由：运行时零第三方依赖，且我们需要可定位的错误行号。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

__all__ = ["YamlError", "loads", "load"]


class YamlError(ValueError):
    """YAML 解析错误，带行号。"""

    def __init__(self, message: str, line: int | None = None) -> None:
        self.message = message
        self.line = line
        prefix = f"YAML 第 {line} 行: " if line else "YAML: "
        super().__init__(prefix + message)


_INT_RE = re.compile(r"^[-+]?\d+$")
_FLOAT_RE = re.compile(r"^[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?$")


@dataclass
class _Line:
    indent: int
    content: str
    number: int


def load(path: str) -> Any:
    """读取并解析 YAML 文件。"""
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())


def loads(text: str) -> Any:
    """解析 YAML 文本为 Python 对象。"""
    if not isinstance(text, str):
        raise YamlError("输入必须是字符串")
    lines: list[_Line] = []
    for number, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            continue
        if stripped.lstrip(" ").startswith("\t") or stripped.startswith("\t"):
            raise YamlError("不支持 Tab 缩进，请用空格", number)
        indent = len(stripped) - len(stripped.lstrip(" "))
        content = stripped[indent:]
        if content in ("---", "..."):
            continue
        lines.append(_Line(indent=indent, content=content, number=number))
    if not lines:
        return None
    if lines[0].indent != 0:
        raise YamlError("顶层内容必须从第 0 列开始", lines[0].number)
    value, index = _parse_block(lines, 0, 0)
    if index != len(lines):
        raise YamlError("存在无法解析的多余内容", lines[index].number)
    return value


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------


def _strip_comment(line: str) -> str:
    """去掉引号之外的 # 注释。"""
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote is None:
            if char in ("'", '"'):
                quote = char
            elif char == "#" and (index == 0 or line[index - 1] in " \t"):
                return line[:index]
        elif char == quote:
            if quote == "'" and index + 1 < len(line) and line[index + 1] == "'":
                index += 2
                continue
            if quote == '"' and index > 0 and line[index - 1] == "\\":
                index += 1
                continue
            quote = None
        index += 1
    return line


def _split_key(text: str) -> tuple[str, str] | None:
    """把 key: rest 拆开；找不到顶层冒号返回 None。"""
    quote: str | None = None
    depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == quote:
                if quote == "'" and index + 1 < len(text) and text[index + 1] == "'":
                    index += 2
                    continue
                if quote == '"' and index > 0 and text[index - 1] == "\\":
                    index += 1
                    continue
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == ":" and depth == 0:
            if index + 1 >= len(text) or text[index + 1] in " \t":
                return _unquote(text[:index]).strip(), text[index + 1 :].strip()
        index += 1
    return None


def _split_flow(inner: str) -> list[str]:
    """按顶层逗号拆分 flow 内容。"""
    parts: list[str] = []
    quote: str | None = None
    depth = 0
    current = ""
    index = 0
    while index < len(inner):
        char = inner[index]
        if quote is not None:
            current += char
            if char == quote:
                if quote == "'" and index + 1 < len(inner) and inner[index + 1] == "'":
                    current += "'"
                    index += 2
                    continue
                if quote == '"' and index > 0 and inner[index - 1] == "\\":
                    index += 1
                    continue
                quote = None
        elif char in ("'", '"'):
            quote = char
            current += char
        elif char in "[{":
            depth += 1
            current += char
        elif char in "]}":
            depth -= 1
            current += char
        elif char == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += char
        index += 1
    if current.strip():
        parts.append(current.strip())
    return parts


def _unquote(text: str) -> str:
    value = text.strip()
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        try:
            return str(json.loads(value))
        except ValueError as exc:
            raise YamlError(f"双引号字符串转义非法: {value!r}") from exc
    return value


def _parse_scalar(text: str, line: int) -> Any:
    value = text.strip()
    if value == "":
        return None
    if value.startswith("'"):
        if not value.endswith("'") or len(value) < 2:
            raise YamlError("单引号未闭合", line)
        return value[1:-1].replace("''", "'")
    if value.startswith('"'):
        if not value.endswith('"') or len(value) < 2:
            raise YamlError("双引号未闭合", line)
        try:
            return str(json.loads(value))
        except ValueError as exc:
            raise YamlError(f"双引号字符串转义非法: {value!r}", line) from exc
    lowered = value.lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if lowered in ("null", "~"):
        return None
    if _INT_RE.match(value):
        return int(value)
    if _FLOAT_RE.match(value):
        return float(value)
    return value


def _parse_value(text: str, line: int) -> Any:
    value = text.strip()
    if value.startswith("["):
        if not value.endswith("]"):
            raise YamlError("flow sequence 未闭合", line)
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_value(part, line) for part in _split_flow(inner)]
    if value.startswith("{"):
        if not value.endswith("}"):
            raise YamlError("flow mapping 未闭合", line)
        inner = value[1:-1].strip()
        mapping: dict[str, Any] = {}
        if inner:
            for part in _split_flow(inner):
                split = _split_key(part)
                if split is None:
                    raise YamlError(f"flow mapping 条目不合法: {part!r}", line)
                mapping[split[0]] = _parse_value(split[1], line) if split[1] else None
        return mapping
    if value.startswith("|") or value.startswith(">"):
        raise YamlError("当前检测器 DSL 不支持块标量（竖线/大于号）", line)
    return _parse_scalar(value, line)


def _is_sequence_line(content: str) -> bool:
    return content == "-" or content.startswith("- ")


# ---------------------------------------------------------------------------
# 递归解析
# ---------------------------------------------------------------------------


def _parse_block(lines: list[_Line], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return None, index
    line = lines[index]
    if line.indent < indent:
        return None, index
    if line.indent > indent:
        raise YamlError(f"缩进不一致（期望 {indent} 列）", line.number)
    if _is_sequence_line(line.content):
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_sequence(lines: list[_Line], index: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise YamlError(f"序列缩进不一致（期望 {indent} 列）", line.number)
        if not _is_sequence_line(line.content):
            break
        rest = line.content[1:].strip()
        if not rest:
            index += 1
            if index < len(lines) and lines[index].indent > indent:
                value, index = _parse_block(lines, index, lines[index].indent)
            else:
                value = None
            items.append(value)
            continue

        split = _split_key(rest)
        if split is None:
            items.append(_parse_value(rest, line.number))
            index += 1
            continue

        key, remainder = split
        mapping: dict[str, Any] = {}
        if remainder:
            mapping[key] = _parse_value(remainder, line.number)
            index += 1
        else:
            index += 1
            if index < len(lines) and lines[index].indent > indent:
                value, index = _parse_block(lines, index, lines[index].indent)
                mapping[key] = value
            else:
                mapping[key] = None
        # 同一序列项内的后续键（比 "-" 多缩进）
        if index < len(lines) and lines[index].indent > indent:
            if _is_sequence_line(lines[index].content):
                raise YamlError("序列项不能同时是映射和序列", lines[index].number)
            extra, index = _parse_mapping(lines, index, lines[index].indent)
            mapping.update(extra)
        items.append(mapping)
    return items, index


def _parse_mapping(lines: list[_Line], index: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise YamlError(f"映射缩进不一致（期望 {indent} 列）", line.number)
        if _is_sequence_line(line.content):
            break
        split = _split_key(line.content)
        if split is None:
            raise YamlError(f"缺少冒号: {line.content!r}", line.number)
        key, remainder = split
        if key in mapping:
            raise YamlError(f"重复键: {key!r}", line.number)
        if remainder:
            mapping[key] = _parse_value(remainder, line.number)
            index += 1
        else:
            index += 1
            if index < len(lines) and lines[index].indent > indent:
                value, index = _parse_block(lines, index, lines[index].indent)
                mapping[key] = value
            else:
                mapping[key] = None
    return mapping, index
