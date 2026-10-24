"""检测器引擎：加载 detectors/*.yml + 运行（含 Python 状态机检测器注册）。

对外契约（与 delivery 约定）：
    run_detectors(trace, detectors_dir=None, *, errors=None, ...) -> list[DetectorHit]
    run_detectors_detailed(...) -> DetectorRunResult   # 带 errors / suppressed 明细 / 降权系数

异常隔离：任一检测器（YAML 编译期或运行期）失败只记入 errors，不影响其它检测器。
Python 检测器用 register_python_detector 装饰器注册，输出统一归一化为 DetectorHit。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable

from ..core.errors import DetectorError
from ..trace.schema import Event, Trace
from .base import SEVERITY_RANK, DetectorHit, DetectorSpec
from .dsl import CompiledDetector, compile_detector, root_process_event_ids
from .suppress import Suppressor, TrustStore, sample_image_for_trace
from . import yamlmini

__all__ = [
    "DEFAULT_DETECTORS_DIR",
    "DetectorRunResult",
    "DetectorSet",
    "PythonDetector",
    "clear_detector_cache",
    "clear_python_detectors",
    "list_detectors",
    "load_detectors",
    "python_detector",
    "register_python_detector",
    "run_detectors",
    "run_detectors_detailed",
]

#: tianti/detect/detectors.py -> 仓库根目录 -> detectors/
DEFAULT_DETECTORS_DIR = Path(__file__).resolve().parents[2] / "detectors"

_PYTHON_REGISTRY: dict[str, "PythonDetector"] = {}
_PYTHON_REGISTRY_VERSION = 0

#: 检测器加载缓存（按目录 mtime/size 签名 + Python 注册表版本失效）。
#: 第二次 load_detectors() 只做目录 stat，通常 <1ms；目录/文件变化会自动重载。
_LOAD_CACHE: dict[tuple[Any, ...], "DetectorSet"] = {}
_MAX_LOAD_CACHE = 16


@dataclass
class PythonDetector:
    """Python 检测器（复杂状态机）：fn(trace) -> DetectorHit | list[DetectorHit] | bool | None。"""

    spec: DetectorSpec
    fn: Callable[[Trace], Any]

    @property
    def id(self) -> str:
        return self.spec.id


def register_python_detector(
    *,
    id: str,
    name: str = "",
    tactic: str = "",
    technique: str = "",
    severity: str = "medium",
    score: float | None = None,
    window_s: float = 0.0,
    fn: Callable[[Trace], Any] | None = None,
) -> Any:
    """注册 Python 检测器。可直接调用，也可作为装饰器：@python_detector(id=...)。

    重复注册同一 id 会覆盖（测试可反复注册）；生产加载时 YAML 与 Python 同名会记 error。
    """

    def _decorator(func: Callable[[Trace], Any]) -> Callable[[Trace], Any]:
        global _PYTHON_REGISTRY_VERSION
        from .dsl import SEVERITY_DEFAULT_SCORE

        spec = DetectorSpec(
            id=id,
            name=name or id,
            tactic=tactic,
            technique=technique,
            severity=severity,
            score=float(score if score is not None else SEVERITY_DEFAULT_SCORE.get(severity, 8.0)),
            window_s=float(window_s),
        )
        _PYTHON_REGISTRY[id] = PythonDetector(spec=spec, fn=func)
        _PYTHON_REGISTRY_VERSION += 1
        return func

    if fn is not None:
        return _decorator(fn)
    return _decorator


python_detector = register_python_detector


def clear_python_detectors() -> None:
    global _PYTHON_REGISTRY_VERSION
    _PYTHON_REGISTRY.clear()
    _PYTHON_REGISTRY_VERSION += 1


def clear_detector_cache() -> None:
    """清空加载缓存（测试/热更新用）。"""
    _LOAD_CACHE.clear()


@dataclass
class DetectorSet:
    """一个目录加载出来的全部检测器。"""

    detectors: list[CompiledDetector] = field(default_factory=list)
    python: list[PythonDetector] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source_dir: str = ""

    def __len__(self) -> int:
        return len(self.detectors) + len(self.python)

    def by_id(self) -> dict[str, CompiledDetector]:
        return {detector.id: detector for detector in self.detectors}

    def specs(self) -> list[DetectorSpec]:
        return [detector.spec for detector in self.detectors] + [detector.spec for detector in self.python]


@dataclass
class DetectorRunResult:
    """一次检测运行结果（完整信息，供 CLI / 评分 / 报告使用）。"""

    hits: list[DetectorHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    load_errors: list[str] = field(default_factory=list)
    evaluated: int = 0
    suppressed: list[dict[str, Any]] = field(default_factory=list)
    suppress_factors: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": [hit.to_dict() for hit in self.hits],
            "errors": list(self.errors),
            "load_errors": list(self.load_errors),
            "evaluated": self.evaluated,
            "suppressed": list(self.suppressed),
            "suppress_factors": dict(self.suppress_factors),
        }


def _directory_signature(directory: Path) -> tuple[Any, ...]:
    """目录签名：(文件名, size, mtime_ns) 元组；用于缓存失效。"""
    if not directory.exists():
        return ("missing",)
    try:
        entries = sorted(directory.iterdir(), key=lambda path: path.name)
    except OSError:
        return ("unreadable",)
    signature: list[tuple[str, int, int]] = []
    for path in entries:
        if not path.is_file() or path.suffix.lower() not in (".yml", ".yaml"):
            continue
        try:
            info = path.stat()
        except OSError:
            continue
        signature.append((path.name, info.st_size, info.st_mtime_ns))
    return tuple(signature)


def load_detectors(
    detectors_dir: str | Path | None = None,
    *,
    include_python: bool = True,
) -> DetectorSet:
    """加载目录下全部 *.yml / *.yaml 检测器；单个文件失败只汇总错误。

    带模块级缓存：同一目录（mtime/size 未变）第二次调用 <1ms，避免每次 scan 重付解析/编译成本。
    """
    directory = Path(detectors_dir) if detectors_dir is not None else DEFAULT_DETECTORS_DIR
    key = (
        str(directory.resolve()) if directory.exists() else str(directory),
        bool(include_python),
        _directory_signature(directory),
        _PYTHON_REGISTRY_VERSION,
    )
    cached = _LOAD_CACHE.get(key)
    if cached is not None:
        return cached
    result = _load_detectors_uncached(directory, include_python=include_python)
    if len(_LOAD_CACHE) >= _MAX_LOAD_CACHE:
        _LOAD_CACHE.clear()
    _LOAD_CACHE[key] = result
    return result


def _load_detectors_uncached(directory: Path, *, include_python: bool) -> DetectorSet:
    result = DetectorSet(source_dir=str(directory))
    if not directory.exists():
        result.errors.append(f"检测器目录不存在: {directory}")
        if include_python:
            result.python = list(_PYTHON_REGISTRY.values())
        return result

    files = sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() in (".yml", ".yaml")
    )
    seen: set[str] = set()
    for path in files:
        try:
            payload = yamlmini.load(str(path))
            compiled = compile_detector(payload, source_path=str(path))
        except (yamlmini.YamlError, DetectorError, OSError) as exc:
            result.errors.append(f"{path.name}: {exc}")
            continue
        except Exception as exc:  # 单文件异常隔离，绝不影响其它检测器
            result.errors.append(f"{path.name}: 未预期错误 {type(exc).__name__}: {exc}")
            continue
        if compiled.id in seen:
            result.errors.append(f"{path.name}: 检测器 id 重复: {compiled.id}")
            continue
        seen.add(compiled.id)
        result.detectors.append(compiled)

    if include_python:
        for python_detector_item in _PYTHON_REGISTRY.values():
            if python_detector_item.id in seen:
                result.errors.append(f"python 检测器 id 与 YAML 重复: {python_detector_item.id}")
                continue
            result.python.append(python_detector_item)
    result.detectors.sort(key=lambda detector: detector.id)
    result.python.sort(key=lambda detector: detector.id)
    return result


def list_detectors(detectors_dir: str | Path | None = None) -> dict[str, Any]:
    """CLI 用：列出检测器元数据。"""
    loaded = load_detectors(detectors_dir)
    return {
        "count": len(loaded),
        "detectors": [spec.to_dict() for spec in loaded.specs()],
        "errors": list(loaded.errors),
        "source_dir": loaded.source_dir,
    }


def _default_hit(detector: PythonDetector, **overrides: Any) -> DetectorHit:
    spec = detector.spec
    payload: dict[str, Any] = {
        "detector_id": spec.id,
        "name": spec.name,
        "severity": spec.severity,
        "tactic": spec.tactic,
        "technique": spec.technique,
        "score": spec.score,
    }
    payload.update(overrides)
    return DetectorHit(**payload)


def _normalize_python_output(detector: PythonDetector, output: Any) -> list[DetectorHit]:
    if output is None or output is False:
        return []
    if output is True:
        return [_default_hit(detector)]
    if isinstance(output, DetectorHit):
        output.detector_id = output.detector_id or detector.spec.id
        output.name = output.name or detector.spec.name
        output.severity = output.severity or detector.spec.severity
        output.tactic = output.tactic or detector.spec.tactic
        output.technique = output.technique or detector.spec.technique
        if not output.score:
            output.score = detector.spec.score
        return [output]
    if isinstance(output, dict):
        payload = dict(output)
        payload.setdefault("detector_id", detector.spec.id)
        return _normalize_python_output(detector, DetectorHit.from_dict(payload))
    if isinstance(output, (list, tuple)):
        hits: list[DetectorHit] = []
        for item in output:
            hits.extend(_normalize_python_output(detector, item))
        return hits
    raise TypeError(
        f"Python 检测器 {detector.spec.id} 返回类型不支持: {type(output).__name__}"
    )


def _sort_hits(hits: list[DetectorHit]) -> None:
    hits.sort(key=lambda hit: (-SEVERITY_RANK.get(hit.severity, 0), -float(hit.score), hit.detector_id))


def run_detectors_detailed(
    trace: Trace,
    detector_set: DetectorSet | None = None,
    *,
    detectors_dir: str | Path | None = None,
    include_python: bool = True,
    suppressor: Suppressor | None = None,
    sample_sha256: str = "",
) -> DetectorRunResult:
    """运行全部检测器，失败隔离并汇总；对命中应用抑制并记录降权系数。"""
    loaded = detector_set if detector_set is not None else load_detectors(detectors_dir, include_python=include_python)
    events_by_id = {event.id: event for event in trace.events}
    sha = sample_sha256 or trace.sample.sha256
    sample_name = trace.sample.name
    # “样本自身”的进程镜像：仅当进程名与 sample.name 一致时才算（Lead 决策）
    sample_image = sample_image_for_trace(trace)
    active_suppressor = suppressor or Suppressor()
    # Python 检测器同样看不到根进程的宿主启动命令行（Lead 决策）
    root_ids = root_process_event_ids(trace)
    python_trace = trace
    if root_ids:
        python_trace = replace(trace, events=[event for event in trace.events if event.id not in root_ids])
    result = DetectorRunResult(load_errors=list(loaded.errors), errors=list(loaded.errors))

    for detector in loaded.detectors:
        result.evaluated += 1
        try:
            evidence = detector.evaluate(trace)
        except Exception as exc:  # 单检测器异常隔离
            result.errors.append(f"{detector.id}: 运行异常 {type(exc).__name__}: {exc}")
            continue
        if evidence is None:
            continue
        result.hits.append(
            DetectorHit(
                detector_id=detector.id,
                name=detector.spec.name,
                severity=detector.spec.severity,
                tactic=detector.spec.tactic,
                technique=detector.spec.technique,
                score=float(detector.spec.score),
                evidence=detector.event_ids(evidence),
                detail=detector.detail(evidence),
            )
        )

    for python_detector_item in loaded.python:
        result.evaluated += 1
        try:
            output = python_detector_item.fn(python_trace)
            python_hits = _normalize_python_output(python_detector_item, output)
        except Exception as exc:  # 单检测器异常隔离
            result.errors.append(
                f"{python_detector_item.id}: 运行异常 {type(exc).__name__}: {exc}"
            )
            continue
        result.hits.extend(python_hits)

    detectors_by_id = loaded.by_id()
    for hit in result.hits:
        detector = detectors_by_id.get(hit.detector_id)
        rules = detector.suppress_rules if detector is not None else ()
        try:
            decision = active_suppressor.check_hit(
                hit,
                events_by_id,
                rules,
                sample_sha256=sha,
                sample_name=sample_name,
                sample_image=sample_image,
            )
        except Exception as exc:
            result.errors.append(f"{hit.detector_id}: 抑制判定异常 {type(exc).__name__}: {exc}")
            decision = None
        if decision is None or not decision.suppressed:
            result.suppress_factors[hit.detector_id] = 1.0
            continue
        hit.suppressed = True
        hit.suppress_reason = decision.reason
        result.suppress_factors[hit.detector_id] = float(decision.factor)
        result.suppressed.append(
            {
                "detector_id": hit.detector_id,
                "reason": decision.reason,
                "factor": round(float(decision.factor), 3),
                "evidence": list(hit.evidence),
            }
        )

    _sort_hits(result.hits)
    return result


def run_detectors(
    trace: Trace,
    detectors_dir: str | Path | None = None,
    *,
    errors: list[str] | None = None,
    detector_set: DetectorSet | None = None,
    include_python: bool = True,
    suppressor: Suppressor | None = None,
    trust: TrustStore | None = None,
) -> list[DetectorHit]:
    """交付契约：返回 list[DetectorHit]。传 errors 列表可收集隔离的错误（汇总）。"""
    active_suppressor = suppressor
    if active_suppressor is None and trust is not None:
        active_suppressor = Suppressor(trust)
    result = run_detectors_detailed(
        trace,
        detector_set,
        detectors_dir=detectors_dir,
        include_python=include_python,
        suppressor=active_suppressor,
    )
    if errors is not None:
        errors.extend(result.errors)
    return result.hits
