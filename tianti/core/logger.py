"""结构化 JSONL 日志（并发安全，可静音）。"""

from __future__ import annotations

import json
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

_LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}
_lock = threading.Lock()


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class JsonlLogger:
    def __init__(
        self,
        name: str = "tianti",
        path: str | Path | None = None,
        level: str = "info",
        run_id: str | None = None,
        console: bool = False,
    ) -> None:
        self.name = name
        self.path = Path(path) if path else None
        self.level = _LEVELS.get(level.lower(), 20)
        self.run_id = run_id
        self.console = console

    def _emit(self, level: str, message: str, fields: dict[str, Any]) -> None:
        if _LEVELS[level] < self.level:
            return
        record: dict[str, Any] = {"ts": _now(), "level": level, "logger": self.name, "msg": message}
        if self.run_id:
            record["run_id"] = self.run_id
        record.update(fields)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with _lock:
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            if self.console and _LEVELS[level] >= 30:
                sys.stderr.write(line + "\n")

    def debug(self, message: str, **fields: Any) -> None:
        self._emit("debug", message, fields)

    def info(self, message: str, **fields: Any) -> None:
        self._emit("info", message, fields)

    def warning(self, message: str, **fields: Any) -> None:
        self._emit("warning", message, fields)

    def error(self, message: str, **fields: Any) -> None:
        self._emit("error", message, fields)


_current: dict[str, Any] = {"path": None, "level": "info", "run_id": None, "console": False}


def configure(
    log_dir: str | Path | None = None,
    *,
    level: str = "info",
    run_id: str | None = None,
    console: bool = False,
) -> None:
    """全局日志配置；CLI 启动时调用一次。"""
    if log_dir is not None:
        _current["path"] = Path(log_dir) / "tianti.log.jsonl"
    _current["level"] = level
    _current["run_id"] = run_id
    _current["console"] = console


def get_logger(name: str = "tianti") -> JsonlLogger:
    return JsonlLogger(
        name=name,
        path=_current["path"],
        level=_current["level"],
        run_id=_current["run_id"],
        console=_current["console"],
    )
