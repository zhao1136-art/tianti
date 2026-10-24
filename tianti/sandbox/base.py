"""沙箱后端契约（L1）。

职责边界：只负责“隔离 + 限时 + 观测 + 产出事件”，不做语义判断。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from ..core.config import PolicyConfig
from ..core.errors import SandboxUnavailable
from ..core.model import Sample
from ..trace.schema import Event, SandboxInfo, SandboxLimits, Trace


@dataclass
class SandboxPolicy:
    name: str = "deep"
    timeout_s: int = 20
    mem_mb: int = 512
    cpu_s: int = 10
    network: str = "blocked"
    max_events: int = 20000
    backend: str = "containment"
    workdir_root: Path | None = None
    follow_children: bool = True
    registry_snapshot: bool = True

    @classmethod
    def from_config(cls, policy: PolicyConfig, *, workdir_root: str | Path | None = None) -> "SandboxPolicy":
        return cls(
            name=policy.name,
            timeout_s=policy.timeout_s,
            mem_mb=policy.mem_mb,
            cpu_s=policy.cpu_s,
            network=policy.network,
            max_events=policy.max_events,
            backend=policy.backend,
            workdir_root=Path(workdir_root) if workdir_root is not None else None,
            follow_children=policy.follow_children,
            registry_snapshot=policy.registry_snapshot,
        )

    def limits(self) -> SandboxLimits:
        return SandboxLimits(
            timeout_s=self.timeout_s,
            mem_mb=self.mem_mb,
            cpu_s=self.cpu_s,
            network=self.network,
        )


class SandboxBackend(Protocol):
    name: str

    def available(self) -> tuple[bool, str]:
        """返回 (是否可用, 原因)。"""
        ...

    def run(
        self,
        sample: Sample,
        policy: SandboxPolicy,
        *,
        on_event: Callable[[Event], None] | None = None,
    ) -> Trace:
        ...


class BaseSandboxBackend:
    """后端公共基类：子类覆盖 run()。"""

    name = "base"

    def available(self) -> tuple[bool, str]:
        return False, "未实现"

    def run(
        self,
        sample: Sample,
        policy: SandboxPolicy,
        *,
        on_event: Callable[[Event], None] | None = None,
    ) -> Trace:
        raise SandboxUnavailable(f"沙箱后端 {self.name} 不可用", backend=self.name)

    def sandbox_info(self, policy: SandboxPolicy, *, started_at: str = "", ended_at: str = "", terminated_by: str = "unknown", isolation: list[str] | None = None) -> SandboxInfo:
        return SandboxInfo(
            host="",
            isolation=list(isolation or []),
            limits=policy.limits(),
            started_at=started_at,
            ended_at=ended_at,
            terminated_by=terminated_by,
        )
