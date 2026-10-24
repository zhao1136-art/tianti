"""引擎配置：默认值 + config/engine.json 深合并。"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError

DEFAULT_TACTIC_WEIGHTS: dict[str, float] = {
    "TA0001": 6.0,
    "TA0002": 8.0,
    "TA0003": 10.0,
    "TA0004": 15.0,
    "TA0005": 8.0,
    "TA0006": 15.0,
    "TA0007": 5.0,
    "TA0008": 15.0,
    "TA0009": 8.0,
    "TA0011": 15.0,
    "TA0040": 20.0,
}


@dataclass
class PathsConfig:
    root: Path
    rules: Path
    detectors: Path
    samples: Path
    work: Path
    out: Path
    logs: Path
    config: Path

    @classmethod
    def from_root(cls, root: str | Path) -> "PathsConfig":
        base = Path(root).resolve()
        return cls(
            root=base,
            rules=base / "rules",
            detectors=base / "detectors",
            samples=base / "samples",
            work=base / "work",
            out=base / "out",
            logs=base / "logs",
            config=base / "config" / "engine.json",
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "root": str(self.root),
            "rules": str(self.rules),
            "detectors": str(self.detectors),
            "samples": str(self.samples),
            "work": str(self.work),
            "out": str(self.out),
            "logs": str(self.logs),
            "config": str(self.config),
        }


@dataclass
class PolicyConfig:
    name: str = "deep"
    timeout_s: int = 20
    mem_mb: int = 512
    cpu_s: int = 10
    network: str = "blocked"
    max_events: int = 20000
    backend: str = "containment"
    follow_children: bool = True
    registry_snapshot: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "timeout_s": self.timeout_s,
            "mem_mb": self.mem_mb,
            "cpu_s": self.cpu_s,
            "network": self.network,
            "max_events": self.max_events,
            "backend": self.backend,
            "follow_children": self.follow_children,
            "registry_snapshot": self.registry_snapshot,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any], *, name: str | None = None) -> "PolicyConfig":
        data = dict(payload)
        if name:
            data["name"] = name
        return cls(
            name=str(data.get("name", "deep")),
            timeout_s=int(data.get("timeout_s", 20)),
            mem_mb=int(data.get("mem_mb", 512)),
            cpu_s=int(data.get("cpu_s", 10)),
            network=str(data.get("network", "blocked")),
            max_events=int(data.get("max_events", 20000)),
            backend=str(data.get("backend", "containment")),
            follow_children=bool(data.get("follow_children", True)),
            registry_snapshot=bool(data.get("registry_snapshot", True)),
        )


@dataclass
class ScoringConfig:
    clean_below: float = 10.0
    malicious_at: float = 40.0
    critical_escalation: bool = True
    signed_downgrade: float = 0.5
    tactic_weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_TACTIC_WEIGHTS))
    whitelist_paths: list[str] = field(default_factory=list)
    whitelist_sha256: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "clean_below": self.clean_below,
            "malicious_at": self.malicious_at,
            "critical_escalation": self.critical_escalation,
            "signed_downgrade": self.signed_downgrade,
            "tactic_weights": dict(self.tactic_weights),
            "whitelist_paths": list(self.whitelist_paths),
            "whitelist_sha256": list(self.whitelist_sha256),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScoringConfig":
        weights = dict(DEFAULT_TACTIC_WEIGHTS)
        weights.update({str(k): float(v) for k, v in dict(payload.get("tactic_weights") or {}).items()})
        return cls(
            clean_below=float(payload.get("clean_below", 10.0)),
            malicious_at=float(payload.get("malicious_at", 40.0)),
            critical_escalation=bool(payload.get("critical_escalation", True)),
            signed_downgrade=float(payload.get("signed_downgrade", 0.5)),
            tactic_weights=weights,
            whitelist_paths=[str(x) for x in (payload.get("whitelist_paths") or [])],
            whitelist_sha256=[str(x).lower() for x in (payload.get("whitelist_sha256") or [])],
        )


def default_root() -> Path:
    """仓库根目录；PyInstaller 冻结后向上找包含 rules/ 与 config/engine.json 的目录。"""
    import sys

    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        for candidate in (exe_dir, exe_dir.parent, exe_dir.parent.parent):
            if (candidate / "config" / "engine.json").is_file() and (candidate / "rules").is_dir():
                return candidate
        return exe_dir
    return Path(__file__).resolve().parents[2]


DEFAULT_POLICIES: dict[str, dict[str, Any]] = {
    "fast": {
        "timeout_s": 10,
        "mem_mb": 256,
        "cpu_s": 5,
        "network": "blocked",
        "max_events": 5000,
        "backend": "replay",
        "registry_snapshot": False,
    },
    "deep": {
        "timeout_s": 20,
        "mem_mb": 512,
        "cpu_s": 10,
        "network": "blocked",
        "max_events": 20000,
        "backend": "containment",
    },
    "paranoid": {
        "timeout_s": 60,
        "mem_mb": 768,
        "cpu_s": 30,
        "network": "blocked",
        "max_events": 50000,
        "backend": "containment",
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


@dataclass
class Config:
    paths: PathsConfig
    policies: dict[str, PolicyConfig]
    default_policy: str = "deep"
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def default(cls, root: str | Path | None = None) -> "Config":
        if root is None:
            root = default_root()
        paths = PathsConfig.from_root(root)
        policies = {name: PolicyConfig.from_dict(data, name=name) for name, data in DEFAULT_POLICIES.items()}
        return cls(paths=paths, policies=policies, default_policy="deep", scoring=ScoringConfig())

    @classmethod
    def load(cls, path: str | Path | None = None, root: str | Path | None = None) -> "Config":
        cfg = cls.default(root)
        target = Path(path) if path is not None else cfg.paths.config
        if not target.exists():
            return cfg
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"配置文件读取失败: {target}: {exc}", path=str(target)) from exc
        if not isinstance(payload, dict):
            raise ConfigError(f"配置文件顶层必须是对象: {target}", path=str(target))
        return cfg.merged(payload)

    def merged(self, payload: dict[str, Any]) -> "Config":
        data = _deep_merge(
            {
                "default_policy": self.default_policy,
                "policies": {name: policy.to_dict() for name, policy in self.policies.items()},
                "scoring": self.scoring.to_dict(),
            },
            payload,
        )
        policies = {
            name: PolicyConfig.from_dict(value, name=name)
            for name, value in dict(data.get("policies") or {}).items()
            if isinstance(value, dict)
        }
        if not policies:
            policies = dict(self.policies)
        return Config(
            paths=self.paths,
            policies=policies,
            default_policy=str(data.get("default_policy", self.default_policy)),
            scoring=ScoringConfig.from_dict(dict(data.get("scoring") or {})),
            extra={k: v for k, v in data.items() if k not in {"policies", "scoring", "default_policy"}},
        )

    def policy(self, name: str | None = None) -> PolicyConfig:
        key = name or self.default_policy
        if key not in self.policies:
            raise ConfigError(f"未知策略: {key}（可用: {', '.join(sorted(self.policies))})")
        return self.policies[key]

    def ensure_dirs(self) -> None:
        for path in (self.paths.work, self.paths.out, self.paths.logs):
            path.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_policy": self.default_policy,
            "policies": {name: policy.to_dict() for name, policy in self.policies.items()},
            "scoring": self.scoring.to_dict(),
            "paths": self.paths.to_dict(),
        }

    def save(self, path: str | Path | None = None) -> Path:
        target = Path(path) if path is not None else self.paths.config
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return target
