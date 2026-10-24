"""统一异常体系：CLI/API 统一把 TiantiError 渲染成结构化错误。"""

from __future__ import annotations

from typing import Any


class TiantiError(Exception):
    """引擎所有异常的基类。"""

    code: str = "tianti.error"

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = dict(context)

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.code, "message": self.message, "context": self.context}


class ConfigError(TiantiError):
    code = "tianti.config"


class SampleError(TiantiError):
    code = "tianti.sample"


class TraceError(TiantiError):
    code = "tianti.trace"


class SandboxError(TiantiError):
    code = "tianti.sandbox"


class SandboxUnavailable(SandboxError):
    code = "tianti.sandbox.unavailable"


class RuleError(TiantiError):
    code = "tianti.rule"

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        line: int | None = None,
        rule: str | None = None,
        **context: Any,
    ) -> None:
        super().__init__(message, path=path, line=line, rule=rule, **context)
        self.path = path
        self.line = line
        self.rule = rule


class DetectorError(TiantiError):
    code = "tianti.detector"


class ReportError(TiantiError):
    code = "tianti.report"
