"""导入官方 capa-rules（Apache-2.0）为可选规则包。

用法（零第三方依赖，运行时标准库）：
  # 1) 只做分类报告（不复制）
  python tools/import_capa_rules.py --source H:/capa-rules-master --report out/capa_import.json

  # 2) 复制可解析的规则到 rules/upstream，并清理不再存在的文件
  python tools/import_capa_rules.py --source H:/capa-rules-master --dest rules/upstream --copy --prune

分类口径：
  ok          parse_rule_file 成功（动态可匹配，scope 已映射到 process/call/span/file）
  unsupported 规则动态可匹配但含本引擎不支持的特征，或 dynamic scope 为 unsupported/非 Windows
  error       YAML/元数据等硬错误
  non_rule    非规则 YAML（.github/doc 等，首行不是 rule:）

复制内容保持原文件不变（保留 Apache-2.0 头），并写 LICENSE.txt 与 SOURCE.md。
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tianti.core.errors import RuleError  # noqa: E402
from tianti.rules.parser import UnsupportedFeature, parse_rule_file  # noqa: E402
from tianti.rules.packs import EXCLUDED_RULE_DIRS, is_rule_yaml  # noqa: E402

DEFAULT_SOURCE = Path("H:/capa-rules-master")
DEFAULT_DEST = ROOT / "rules" / "upstream"
RULE_SUFFIXES = (".yml", ".yaml")


@dataclass
class ClassifyResult:
    source: Path
    total_files: int = 0
    rule_files: int = 0
    non_rule_files: int = 0
    ok: list[tuple[Path, Any]] = field(default_factory=list)
    unsupported: list[tuple[Path, str]] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)
    non_rule: list[Path] = field(default_factory=list)
    scope_distribution: Counter = field(default_factory=Counter)
    original_scopes: Counter = field(default_factory=Counter)
    unsupported_reasons: Counter = field(default_factory=Counter)

    def to_dict(self, *, examples: int = 15) -> dict[str, Any]:
        total = max(1, len(self.ok) + len(self.unsupported) + len(self.errors))
        return {
            "source": str(self.source),
            "generated_at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "counts": {
                "yml_total": self.total_files,
                "rule_files": self.rule_files,
                "non_rule": len(self.non_rule),
                "ok": len(self.ok),
                "unsupported": len(self.unsupported),
                "error": len(self.errors),
                "compat_rate": round(len(self.ok) / total, 4),
            },
            "scope_distribution": dict(sorted(self.scope_distribution.items())),
            "original_scope_distribution": dict(sorted(self.original_scopes.items())),
            "unsupported_reasons_top": [
                {"reason": reason, "count": count}
                for reason, count in self.unsupported_reasons.most_common(15)
            ],
            "unsupported_examples": [
                {"file": str(path), "reason": message}
                for path, message in self.unsupported[:examples]
            ],
            "error_examples": [
                {"file": str(path), "reason": message} for path, message in self.errors[:examples]
            ],
            "non_rule_examples": [str(path) for path in self.non_rule[:examples]],
            "ok_examples": [str(path) for path, _ in self.ok[:examples]],
        }


def _iter_yaml(source: Path) -> Iterable[Path]:
    for suffix in RULE_SUFFIXES:
        for path in sorted(source.rglob("*" + suffix)):
            relative_parts = path.relative_to(source).parts[:-1]
            if any(part in EXCLUDED_RULE_DIRS for part in relative_parts):
                continue
            yield path


def _normalize_reason(message: str) -> str:
    text = re.sub(r"'[^']*'", "'X'", message)
    text = re.sub(r"（.*?）", "", text)
    text = re.sub(r": .*", "", text)
    return text.strip()[:120]


def classify(source: str | Path) -> ClassifyResult:
    source_path = Path(source)
    if not source_path.is_dir():
        raise SystemExit(f"source 目录不存在: {source_path}")
    result = ClassifyResult(source=source_path)
    for path in _iter_yaml(source_path):
        result.total_files += 1
        if not is_rule_yaml(path):
            result.non_rule_files += 1
            result.non_rule.append(path)
            continue
        result.rule_files += 1
        try:
            rule = parse_rule_file(path)
        except UnsupportedFeature as exc:
            result.unsupported.append((path, exc.message))
            result.unsupported_reasons[_normalize_reason(exc.message)] += 1
            continue
        except RuleError as exc:
            result.errors.append((path, exc.message))
            continue
        result.ok.append((path, rule))
        result.scope_distribution[rule.meta.scope] += 1
        result.original_scopes[str(getattr(rule, "original_scope", rule.meta.scope))] += 1
    return result


def _read_commit(source: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    return (proc.stdout or "").strip() or "unknown"


def copy_rules(
    result: ClassifyResult,
    dest: str | Path,
    *,
    prune: bool = False,
) -> dict[str, Any]:
    dest_path = Path(dest)
    dest_path.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    expected: set[Path] = set()
    for source_file, _rule in result.ok:
        relative = source_file.relative_to(result.source)
        target = dest_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source_file.read_bytes())
        copied.append(target)
        expected.add(target.resolve())

    license_source = result.source / "LICENSE.txt"
    license_target = dest_path / "LICENSE.txt"
    if license_source.is_file():
        shutil.copyfile(license_source, license_target)

    pruned: list[Path] = []
    if prune:
        for suffix in RULE_SUFFIXES:
            for existing in sorted(dest_path.rglob("*" + suffix)):
                if existing.resolve() in expected:
                    continue
                existing.unlink()
                pruned.append(existing)
        for directory in sorted(dest_path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()

    summary = result.to_dict()
    source_md = dest_path / "SOURCE.md"
    lines = [
        "# 上游 capa-rules 规则包（可选）",
        "",
        f"- 来源：`{result.source}`",
        f"- 上游项目：mandiant/capa-rules（Apache-2.0）",
        f"- 导入时间：{_dt.datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"- 上游 commit：{_read_commit(result.source)}",
        f"- 导入规则数：{len(copied)}（分类 ok）",
        f"- 分类统计：ok={summary['counts']['ok']} / unsupported={summary['counts']['unsupported']} "
        f"/ error={summary['counts']['error']} / non_rule={summary['counts']['non_rule']}",
        f"- 规则 scope 分布：{json.dumps(summary['scope_distribution'], ensure_ascii=False)}",
        "",
        "## 说明",
        "- 本目录由 `tools/import_capa_rules.py` 生成，默认不参与规则匹配（`include_upstream=false`）。",
        "- 官方规则为 Apache-2.0，原始文件内容与版权头保持不变，见 LICENSE.txt。",
        "- 上游 `meta.scopes.dynamic` 已映射为本引擎 scope：span of calls→span、call、file、process；",
        "  dynamic=unsupported 与仅静态可匹配的规则未导入。",
        "- match 引用因依赖规则未导入时，加载阶段会跳过引用方并计入 RuleSet.unsupported。",
        "",
    ]
    source_md.write_text("\n".join(lines), encoding="utf-8")

    return {
        "dest": str(dest_path),
        "copied": len(copied),
        "pruned": len(pruned),
        "expected": len(expected),
        "license": license_target.is_file(),
        "source_md": str(source_md),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="导入官方 capa-rules 为可选规则包")
    parser.add_argument("--source", default=str(DEFAULT_SOURCE), help="上游 capa-rules 根目录")
    parser.add_argument("--dest", default=str(DEFAULT_DEST), help="目标规则包目录")
    parser.add_argument("--copy", action="store_true", help="复制 ok 规则到 dest")
    parser.add_argument("--prune", action="store_true", help="删除 dest 中不再存在的规则文件")
    parser.add_argument("--report", default="", help="把分类 JSON 报告写入该路径")
    args = parser.parse_args(argv)

    result = classify(args.source)
    report = result.to_dict()
    if args.copy:
        report["copy"] = copy_rules(result, args.dest, prune=args.prune)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        target = Path(args.report)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
