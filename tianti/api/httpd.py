"""本地 HTTP API（stdlib ThreadingHTTPServer，仅监听 127.0.0.1）。

端点：
    GET  /health          健康检查
    POST /scan            {"path": ..., "policy": ...} -> 202 {"task_id": ...}
    GET  /result/{id}     queued/running -> 202；done -> 200 ScanResult JSON
    GET  /rules           规则包摘要（规则引擎未就绪时 available=false + reason）
    GET  /metrics         进程内计数指标
    GET  /                端点索引

所有错误均返回 JSON；边界只接受回环地址，避免把本地扫描能力暴露到局域网。
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .. import __version__
from ..core.config import Config
from ..core.errors import SampleError, TiantiError
from ..report.base import RESULT_SCHEMA
from . import pipeline

MAX_BODY_BYTES = 1 << 20  # 1 MiB
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


@dataclass
class TaskRecord:
    task_id: str
    path: str
    policy: str | None = None
    status: str = "queued"  # queued | running | done | error
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    def summary(self, *, include_result: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "task_id": self.task_id,
            "status": self.status,
            "path": self.path,
            "policy": self.policy,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
        if self.finished_at is not None:
            payload["elapsed_s"] = round(self.finished_at - (self.started_at or self.created_at), 3)
        if self.error is not None:
            payload["error"] = self.error
        if include_result and self.result is not None:
            payload["result"] = self.result
        return payload


class ScanService:
    """内存任务表 + 单样本后台线程执行（并发受本机资源限制，默认串行）。"""

    def __init__(
        self,
        *,
        config: Config | None = None,
        scan_func: Callable[[str, str | None], Any] | None = None,
        max_tasks: int = 100,
    ) -> None:
        self.config = config or Config.load()
        self._scan_func = scan_func or self._default_scan
        self._max_tasks = max(1, int(max_tasks))
        self._lock = threading.Lock()
        self._tasks: dict[str, TaskRecord] = {}
        self.started_at = time.time()
        self._metrics = {
            "requests_total": 0,
            "scan_submitted": 0,
            "scan_completed": 0,
            "scan_failed": 0,
        }

    def _default_scan(self, path: str, policy: str | None) -> Any:
        return pipeline.scan_path(path, policy=policy, config=self.config)

    # ------------------------------------------------------------- 任务
    def submit(self, path: str, policy: str | None = None) -> TaskRecord:
        target = Path(str(path)).expanduser()
        if not target.exists():
            raise SampleError(f"路径不存在: {target}", path=str(target))
        if not target.is_file():
            raise SampleError(f"仅支持文件扫描: {target}", path=str(target))
        record = TaskRecord(task_id=uuid.uuid4().hex[:16], path=str(target), policy=policy)
        with self._lock:
            self._tasks[record.task_id] = record
            self._metrics["scan_submitted"] += 1
            self._prune_locked()
        thread = threading.Thread(
            target=self._run_task,
            args=(record.task_id,),
            name=f"tianti-scan-{record.task_id}",
            daemon=True,
        )
        thread.start()
        return record

    def _run_task(self, task_id: str) -> None:
        with self._lock:
            record = self._tasks.get(task_id)
            if record is None:
                return
            record.status = "running"
            record.started_at = time.time()
        try:
            result = self._scan_func(record.path, record.policy)
            payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        except TiantiError as exc:
            self._finish(task_id, error=exc.to_dict())
            return
        except Exception as exc:  # API 边界兜底：任何异常都转 JSON，不打印 traceback 给客户端
            self._finish(
                task_id,
                error={"error": "tianti.api.internal", "message": str(exc), "context": {"type": type(exc).__name__}},
            )
            return
        self._finish(task_id, result=payload)

    def _finish(self, task_id: str, *, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> None:
        with self._lock:
            record = self._tasks.get(task_id)
            if record is None:
                return
            record.finished_at = time.time()
            if error is not None:
                record.status = "error"
                record.error = error
                self._metrics["scan_failed"] += 1
            else:
                record.status = "done"
                record.result = result
                self._metrics["scan_completed"] += 1

    def _prune_locked(self) -> None:
        if len(self._tasks) <= self._max_tasks:
            return
        finished = sorted(
            (record for record in self._tasks.values() if record.status in ("done", "error")),
            key=lambda record: record.finished_at or record.created_at,
        )
        for record in finished[: max(0, len(self._tasks) - self._max_tasks)]:
            self._tasks.pop(record.task_id, None)

    def get(self, task_id: str) -> TaskRecord | None:
        with self._lock:
            return self._tasks.get(task_id)

    def task_payload(self, task_id: str) -> dict[str, Any] | None:
        record = self.get(task_id)
        if record is None:
            return None
        return record.summary(include_result=False)

    # ------------------------------------------------------------- 指标 / 规则
    def note_request(self) -> None:
        with self._lock:
            self._metrics["requests_total"] += 1

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            tasks = list(self._tasks.values())
            counters = dict(self._metrics)
        counts = {"total": len(tasks), "queued": 0, "running": 0, "done": 0, "error": 0}
        for record in tasks:
            counts[record.status] = counts.get(record.status, 0) + 1
        return {
            "service": "tianti-api",
            "version": __version__,
            "uptime_s": round(time.time() - self.started_at, 3),
            "requests": counters,
            "tasks": counts,
            "result_schema": RESULT_SCHEMA,
        }

    def rules(self) -> dict[str, Any]:
        try:
            return pipeline.describe_rules(self.config)
        except Exception as exc:
            return {"available": False, "count": 0, "reason": f"规则摘要生成失败: {exc}"}


class ApiHandler(BaseHTTPRequestHandler):
    """API 请求处理器；service 由 create_server 注入到子类上。"""

    server_version = "TianTiAPI/" + __version__
    service: ScanService

    # 安静日志：避免把每次探测写到 stderr；异常由 JSON 响应表达
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    # ------------------------------------------------------------- 工具
    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, code: str, message: str, **context: Any) -> None:
        self._json(status, {"error": code, "message": message, "context": context})

    def _route_path(self) -> str:
        return urlsplit(self.path).path.rstrip("/") or "/"

    def _read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        length = int(raw_length or 0)
        if length <= 0:
            raise ValueError("请求体为空，需要 JSON 对象")
        if length > MAX_BODY_BYTES:
            raise ValueError(f"请求体过大（上限 {MAX_BODY_BYTES} 字节）")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"JSON 解析失败: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return payload

    # ------------------------------------------------------------- GET
    def do_GET(self) -> None:  # noqa: N802
        self.service.note_request()
        path = self._route_path()
        try:
            if path == "/health":
                self._json(200, {
                    "status": "ok",
                    "service": "tianti-api",
                    "version": __version__,
                    "result_schema": RESULT_SCHEMA,
                    "time": _iso_now(),
                })
                return
            if path == "/metrics":
                self._json(200, self.service.metrics())
                return
            if path == "/rules":
                self._json(200, self.service.rules())
                return
            if path == "/":
                self._json(200, {
                    "service": "tianti-api",
                    "version": __version__,
                    "endpoints": ["GET /health", "POST /scan", "GET /result/{id}", "GET /rules", "GET /metrics"],
                })
                return
            if path.startswith("/result/"):
                task_id = path[len("/result/"):]
                record = self.service.get(task_id)
                if record is None:
                    self._error(404, "tianti.api.task_not_found", f"任务不存在: {task_id}", task_id=task_id)
                    return
                if record.status in ("queued", "running"):
                    self._json(202, record.summary())
                    return
                if record.status == "error":
                    self._json(422, record.summary())
                    return
                self._json(200, record.summary(include_result=True))
                return
            self._error(404, "tianti.api.not_found", f"未知端点: {path}")
        except Exception as exc:
            self._error(500, "tianti.api.internal", f"服务内部错误: {exc}")

    # ------------------------------------------------------------- POST
    def do_POST(self) -> None:  # noqa: N802
        self.service.note_request()
        path = self._route_path()
        try:
            if path != "/scan":
                self._error(404, "tianti.api.not_found", f"未知端点: {path}")
                return
            try:
                payload = self._read_json()
            except ValueError as exc:
                self._error(400, "tianti.api.bad_request", str(exc))
                return
            raw_path = payload.get("path")
            if not isinstance(raw_path, str) or not raw_path.strip():
                self._error(400, "tianti.api.bad_request", "缺少字段 path（样本或 trace JSON 的路径）")
                return
            policy = payload.get("policy")
            if policy is not None and not isinstance(policy, str):
                self._error(400, "tianti.api.bad_request", "policy 必须是字符串")
                return
            try:
                record = self.service.submit(raw_path.strip(), policy)
            except SampleError as exc:
                self._error(404, "tianti.api.sample_not_found", exc.message, **exc.context)
                return
            self._json(202, {"task_id": record.task_id, "status": record.status, "path": record.path})
        except Exception as exc:
            self._error(500, "tianti.api.internal", f"服务内部错误: {exc}")


def create_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    service: ScanService | None = None,
    config: Config | None = None,
) -> ThreadingHTTPServer:
    """创建仅回环监听的 HTTP 服务（port=0 时由系统分配）。"""
    if host not in LOOPBACK_HOSTS:
        raise ValueError(f"出于安全考虑，API 只允许监听回环地址，拒绝: {host}")
    active_service = service or ScanService(config=config)
    handler_cls = type("BoundApiHandler", (ApiHandler,), {"service": active_service})
    server = ThreadingHTTPServer((host, port), handler_cls)
    server.daemon_threads = True
    server.service = active_service  # type: ignore[attr-defined]
    return server


def serve(host: str = "127.0.0.1", port: int = 8765, *, service: ScanService | None = None) -> None:
    """阻塞运行 API 服务（CLI serve 使用）。"""
    server = create_server(host, port, service=service)
    actual_host, actual_port = server.server_address[0], server.server_address[1]
    sys.stdout.write(f"天体引擎 API 监听 http://{actual_host}:{actual_port}（仅回环，Ctrl+C 停止）\n")
    sys.stdout.flush()
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
