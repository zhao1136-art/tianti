"""零依赖 YAML 子集解析器（供 capa 规则包使用）。

覆盖 capa 规则实际用到的语法子集：
  - mapping（缩进嵌套）/ sequence（"- " 列表）
  - scalar：单引号、双引号（含转义）、裸值、null/bool/int/float
  - 块标量：| 与 >（含 -/+ chomping 与缩进指示符）
  - flow 序列 [a, b] 与 flow mapping {a: b}
  - 行注释（# 前须为空白或行首，引号内不生效）
  - 文档标记 --- / ...

明确不支持：锚点 & / 别名 * / 多文档 / 复杂 tag（遇到时报错并带行号）。
解析错误统一抛 YamlError，附带 1-based 行号与可选文件路径。

TODO(M7 技术债): tianti/detect/yamlmini.py 与本模块是两份独立 YAML 子集解析器，
统一推迟到 M7；期间修改语法支持必须同步两处（或让 detect 改为 import 本模块）。
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["YamlError", "load", "loads"]


class YamlError(Exception):
    """YAML 子集解析错误，line 为 1-based 行号。"""

    def __init__(self, message: str, line: int = 0, path: str = "") -> None:
        self.message = message
        self.line = int(line)
        self.path = path or ""
        location = self.path or "<yaml>"
        super().__init__(f"{location}:{self.line}: {message}" if self.line else f"{location}: {message}")


_INT_RE = re.compile(r"^[+-]?[0-9]+$")
_HEX_RE = re.compile(r"^[+-]?0[xX][0-9a-fA-F]+$")
_FLOAT_RE = re.compile(r"^[+-]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$")
_NULLS = {"", "~", "null", "Null", "NULL"}
_TRUES = {"true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"}
_FALSES = {"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"}


def loads(text: str, *, path: str = "") -> Any:
    """解析 YAML 文本；空文档返回 None。"""
    return _Parser(text, path).parse()


load = loads


def _split_key(content: str) -> tuple[str, str] | None:
    """在行内找 mapping 分隔符（顶层、引号外、":" 后为空白或行尾）。"""
    quote: str | None = None
    depth = 0
    index = 0
    length = len(content)
    while index < length:
        char = content[index]
        if quote:
            if quote == '"' and char == "\\":
                index += 2
                continue
            if char == quote:
                if quote == "'" and index + 1 < length and content[index + 1] == "'":
                    index += 2
                    continue
                quote = None
        else:
            if char in "\"'":
                quote = char
            elif char in "[{(":
                depth += 1
            elif char in "]})":
                depth = max(0, depth - 1)
            elif char == ":" and depth == 0:
                if index + 1 == length or content[index + 1] in " \t":
                    return content[:index].strip(), content[index + 1 :].strip()
        index += 1
    return None


def _strip_comment(content: str) -> str:
    quote: str | None = None
    index = 0
    length = len(content)
    while index < length:
        char = content[index]
        if quote:
            if quote == '"' and char == "\\":
                index += 2
                continue
            if char == quote:
                if quote == "'" and index + 1 < length and content[index + 1] == "'":
                    index += 2
                    continue
                quote = None
        else:
            if char in "\"'":
                quote = char
            elif char == "#" and (index == 0 or content[index - 1] in " \t"):
                return content[:index].rstrip()
        index += 1
    return content


def _parse_quoted_at(text: str, start: int, *, line: int, path: str) -> tuple[str, int]:
    """解析从 start 开始的引号字符串，返回 (值, 引号后的位置)。"""
    quote = text[start]
    index = start + 1
    out: list[str] = []
    length = len(text)
    while index < length:
        char = text[index]
        if quote == "'":
            if char == "'":
                if index + 1 < length and text[index + 1] == "'":
                    out.append("'")
                    index += 2
                    continue
                return "".join(out), index + 1
            out.append(char)
            index += 1
            continue
        if char == "\\":
            if index + 1 >= length:
                raise YamlError("双引号字符串以反斜杠结尾", line, path)
            escape = text[index + 1]
            simple = {
                "n": "\n",
                "t": "\t",
                "r": "\r",
                '"': '"',
                "\\": "\\",
                "/": "/",
                "0": "\0",
                "b": "\b",
                "f": "\f",
                " ": " ",
            }
            if escape in simple:
                out.append(simple[escape])
                index += 2
                continue
            if escape in "uU":
                width = 4 if escape == "u" else 8
                digits = text[index + 2 : index + 2 + width]
                if len(digits) != width or not re.fullmatch(r"[0-9a-fA-F]+", digits):
                    raise YamlError("非法的 Unicode 转义", line, path)
                out.append(chr(int(digits, 16)))
                index += 2 + width
                continue
            raise YamlError(f"非法的转义字符: \\{escape}", line, path)
        if char == '"':
            return "".join(out), index + 1
        out.append(char)
        index += 1
    raise YamlError("未闭合的双引号字符串", line, path)


def _parse_plain(text: str) -> Any:
    """裸标量 -> Python 值。"""
    stripped = text.strip()
    if stripped in _NULLS:
        return None
    if stripped in _TRUES:
        return True
    if stripped in _FALSES:
        return False
    if _HEX_RE.match(stripped):
        sign = -1 if stripped.startswith("-") else 1
        body = stripped.lstrip("+-")
        return sign * int(body, 16)
    if _INT_RE.match(stripped):
        return int(stripped)
    if _FLOAT_RE.match(stripped):
        return float(stripped)
    return stripped


def _parse_flow(text: str, start: int, *, line: int, path: str) -> tuple[Any, int]:
    """解析 flow 集合，返回 (值, 结束位置)。"""
    index = start
    length = len(text)

    def skip_ws(pos: int) -> int:
        while pos < length and text[pos] in " \t":
            pos += 1
        return pos

    def parse_value(pos: int) -> tuple[Any, int]:
        pos = skip_ws(pos)
        if pos >= length:
            raise YamlError("flow 集合未闭合", line, path)
        if text[pos] in "[{":
            return parse_flow(pos)
        if text[pos] in "\"'":
            return _parse_quoted_at(text, pos, line=line, path=path)
        begin = pos
        while pos < length and text[pos] not in ",]}":
            pos += 1
        token = text[begin:pos].strip()
        return _parse_plain(token), pos

    def parse_flow(pos: int) -> tuple[Any, int]:
        opener = text[pos]
        closer = "]" if opener == "[" else "}"
        pos += 1
        result: Any = [] if opener == "[" else {}
        while True:
            pos = skip_ws(pos)
            if pos >= length:
                raise YamlError(f"flow 集合缺少 {closer!r}", line, path)
            if text[pos] == closer:
                return result, pos + 1
            if opener == "[":
                value, pos = parse_value(pos)
                result.append(value)
            else:
                if text[pos] in "\"'":
                    key, pos = _parse_quoted_at(text, pos, line=line, path=path)
                else:
                    begin = pos
                    while pos < length and text[pos] not in ":,}":
                        pos += 1
                    key = text[begin:pos].strip()
                pos = skip_ws(pos)
                if pos < length and text[pos] == ":":
                    pos += 1
                    value, pos = parse_value(pos)
                else:
                    value = None
                result[key] = value
            pos = skip_ws(pos)
            if pos < length and text[pos] == ",":
                pos += 1
                continue
            if pos < length and text[pos] == closer:
                return result, pos + 1
            raise YamlError(f"flow 集合中期望 ',' 或 {closer!r}", line, path)

    return parse_flow(index)


class _Parser:
    def __init__(self, text: str, path: str = "") -> None:
        self.lines = text.splitlines()
        self.path = path or ""
        self.index = 0
        self.count = len(self.lines)

    # ------------------------------------------------------------------ 基础设施
    def _error(self, message: str, line: int) -> YamlError:
        return YamlError(message, line, self.path)

    def _info(self, index: int) -> tuple[int, str, int]:
        raw = self.lines[index]
        no = index + 1
        if raw.startswith("\t"):
            raise self._error("缩进不能使用制表符", no)
        indent = len(raw) - len(raw.lstrip(" "))
        prefix = raw[:indent]
        if "\t" in prefix:
            raise self._error("缩进不能使用制表符", no)
        content = _strip_comment(raw[indent:])
        return indent, content.rstrip(), no

    def _skip_ignored(self) -> None:
        while self.index < self.count:
            raw = self.lines[self.index]
            stripped = raw.strip()
            if stripped == "" or stripped.startswith("#") or stripped in ("---", "..."):
                self.index += 1
                continue
            break

    def _peek(self) -> tuple[int, str, int] | None:
        self._skip_ignored()
        if self.index >= self.count:
            return None
        return self._info(self.index)

    # ------------------------------------------------------------------ 主入口
    def parse(self) -> Any:
        info = self._peek()
        if info is None:
            return None
        indent, content, _ = info
        if content.startswith("&") or content.startswith("*"):
            raise self._error("暂不支持锚点/别名", info[2])
        value = self._parse_node(indent)
        trailing = self._peek()
        if trailing is not None:
            raise self._error(f"文档存在无法解析的多余内容: {trailing[1]!r}", trailing[2])
        return value

    def _parse_node(self, indent: int) -> Any:
        info = self._peek()
        if info is None:
            raise self._error("期望节点，但到达文件末尾", self.count)
        _, content, no = info
        if content == "-" or content.startswith("- "):
            return self._parse_sequence(indent)
        return self._parse_mapping(indent)

    # ------------------------------------------------------------------ mapping
    def _parse_mapping(self, indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while True:
            info = self._peek()
            if info is None:
                break
            current_indent, content, no = info
            if current_indent != indent or content == "-" or content.startswith("- "):
                break
            split = _split_key(content)
            if split is None:
                raise self._error(f"期望 'key: value' 形式的映射项，实际 {content!r}", no)
            key, inline = split
            key = self._parse_key(key, no)
            if key in result:
                raise self._error(f"重复的键: {key!r}", no)
            self.index += 1
            result[key] = self._parse_value_after_key(inline, indent, no)
        return result

    def _parse_key(self, key: str, line: int) -> str:
        key = key.strip()
        if not key:
            raise self._error("映射键不能为空", line)
        if key[0] in "\"'":
            value, pos = _parse_quoted_at(key, 0, line=line, path=self.path)
            if key[pos:].strip():
                raise self._error("引号键后存在多余字符", line)
            return str(value)
        return key

    def _parse_value_after_key(self, inline: str, indent: int, line: int) -> Any:
        if inline == "":
            info = self._peek()
            if info is not None and info[0] > indent:
                return self._parse_node(info[0])
            return None
        if inline[0] in "|>":
            return self._collect_block(indent, inline, line)
        return self._parse_scalar(inline, line)

    # ------------------------------------------------------------------ sequence
    def _parse_sequence(self, indent: int) -> list[Any]:
        items: list[Any] = []
        while True:
            info = self._peek()
            if info is None:
                break
            current_indent, content, no = info
            if current_indent != indent:
                break
            if not (content == "-" or content.startswith("- ")):
                break
            self.index += 1
            rest_full = content[1:]
            stripped_leading = rest_full.lstrip(" ")
            content_col = indent + 1 + (len(rest_full) - len(stripped_leading))
            rest = stripped_leading.rstrip()
            if rest == "":
                child = self._peek()
                if child is not None and child[0] > indent:
                    items.append(self._parse_node(child[0]))
                else:
                    items.append(None)
                continue
            split = _split_key(rest)
            if split is None:
                items.append(self._parse_scalar(rest, no))
                continue
            key, inline = split
            key = self._parse_key(key, no)
            item: dict[str, Any] = {}
            item[key] = self._parse_value_after_key(inline, indent, no)
            # 允许同一 sequence 项内后续的映射键（缩进对齐到 "- " 之后的内容列）
            while True:
                info2 = self._peek()
                if info2 is None:
                    break
                indent2, content2, no2 = info2
                if indent2 != content_col or content2 == "-" or content2.startswith("- "):
                    break
                split2 = _split_key(content2)
                if split2 is None:
                    break
                key2, inline2 = split2
                key2 = self._parse_key(key2, no2)
                self.index += 1
                if key2 in item:
                    raise self._error(f"重复的键: {key2!r}", no2)
                item[key2] = self._parse_value_after_key(inline2, content_col, no2)
            items.append(item)
        return items

    # ------------------------------------------------------------------ 标量
    def _parse_scalar(self, text: str, line: int) -> Any:
        value = text.strip()
        if not value:
            return None
        if value[0] == '"' or value[0] == "'":
            parsed, pos = _parse_quoted_at(value, 0, line=line, path=self.path)
            if value[pos:].strip():
                raise self._error("引号字符串后存在多余字符", line)
            return parsed
        if value[0] in "[{":
            parsed, pos = _parse_flow(value, 0, line=line, path=self.path)
            if value[pos:].strip():
                raise self._error("flow 集合后存在多余字符", line)
            return parsed
        if value[0] in "&*":
            raise self._error("暂不支持锚点/别名", line)
        return _parse_plain(value)

    # ------------------------------------------------------------------ 块标量
    def _collect_block(self, parent_indent: int, indicator: str, line: int) -> str:
        style = indicator[0]
        chomp = ""
        explicit: int | None = None
        for char in indicator[1:].strip():
            if char in "+-":
                if chomp:
                    raise self._error(f"非法的块标量指示符: {indicator!r}", line)
                chomp = char
            elif char.isdigit():
                explicit = int(char)
            else:
                raise self._error(f"非法的块标量指示符: {indicator!r}", line)
        block_indent: int | None = None if explicit is None else parent_indent + explicit
        collected: list[str] = []
        while self.index < self.count:
            raw = self.lines[self.index]
            if raw.strip() == "":
                collected.append("")
                self.index += 1
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            if "\t" in raw[:indent]:
                raise self._error("缩进不能使用制表符", self.index + 1)
            if indent <= parent_indent:
                break
            if block_indent is None:
                block_indent = indent
            if indent < block_indent:
                break
            collected.append(raw[block_indent:])
            self.index += 1
        while collected and collected[-1] == "":
            collected.pop()
        if not collected:
            return ""
        if style == "|":
            body = "\n".join(collected)
        else:
            folded: list[str] = []
            for part in collected:
                if part == "":
                    folded.append("\n")
                else:
                    folded.append(part)
            body = " ".join(folded)
            body = re.sub(r" *\n *", "\n", body)
        if chomp == "-":
            return body
        if chomp == "+":
            return body + "\n"
        return body + "\n" if not body.endswith("\n") else body
