"""天体引擎 Tk 桌面前端。

设计目标：
- 纯标准库（tkinter/ttk），零第三方依赖；
- 复用现有 L5 pipeline（扫描/回放/规则/检测/评分），不在 UI 里重复分析逻辑；
- 扫描在工作线程执行，UI 通过队列刷新，不卡界面；
- 默认「自动」模式：trace JSON 走离线回放（不执行样本），其他文件走沙箱执行。
"""

from __future__ import annotations

import argparse
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterable

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .. import __version__
from ..api import pipeline
from ..core.config import Config
from ..core.errors import TiantiError
from ..report import ScanResult, load_result, save_html, save_result
from ..trace import schema
from . import format as fmt

MAX_DIR_FILES = 100
APP_NAME = "御天分析"
APP_SUBTITLE = "沙箱执行 · capa 规则 · 危险行为检测"
TITLE = f"{APP_NAME} — 沙箱行为分析"


class _Cancelled(Exception):
    """用户停止导致当前文件分析被强杀。"""
COLORS = {
    "bg": "#f2f4f7",
    "panel": "#ffffff",
    "header": "#1f3a5f",
    "accent": "#2d6cdf",
    "malicious": "#c0392b",
    "suspicious": "#b9770e",
    "clean": "#1e8449",
    "muted": "#6b7280",
}


class TiantiApp:
    """主窗口。root 由外部创建，便于 smoke test / 截图脚本复用。"""

    def __init__(self, root: tk.Tk, *, config: Config | None = None, initial_path: str | None = None) -> None:
        self.root = root
        self.config = config or Config.load()
        self.queue: "queue.Queue[tuple[str, Any]]" = queue.Queue()
        self.results: dict[str, ScanResult] = {}
        self._row_seq = 0
        self.scanning = False
        self.cancel_requested = threading.Event()
        self._cap_rows: list[dict[str, Any]] = []
        self._det_rows: list[dict[str, Any]] = []
        self._sig_rows: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []
        self._matrix_map: dict[str, ScanResult] = {}
        self.current_proc: "subprocess.Popen[str] | None" = None
        self._proc_lock = threading.Lock()
        self._batch_started = 0.0

        self.root.title(TITLE)
        self.root.geometry("1460x860")
        self.root.minsize(1200, 720)
        self.root.configure(bg=COLORS["bg"])

        self._configure_style()
        self._build_menu()
        self._build_layout()
        if initial_path:
            self.path_var.set(initial_path)
        self.root.after(120, self._poll_queue)

    # ------------------------------------------------------------------ 样式
    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=("Microsoft YaHei UI", 10))
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Panel.TFrame", background=COLORS["panel"])
        style.configure("TLabel", background=COLORS["bg"])
        style.configure("Panel.TLabel", background=COLORS["panel"])
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 16, "bold"), foreground="white")
        style.configure("Sub.TLabel", font=("Microsoft YaHei UI", 9), foreground="#c9d6e8")
        style.configure("TButton", padding=(10, 5))
        style.configure("Accent.TButton", font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("Treeview", rowheight=26, font=("Microsoft YaHei UI", 10))
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("TLabelframe.Label", font=("Microsoft YaHei UI", 10, "bold"))
        self.root.option_add("*Font", ("Microsoft YaHei UI", 10))

    # ------------------------------------------------------------------ 菜单
    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="选择样本文件…", command=self.browse_sample)
        file_menu.add_command(label="选择行为轨迹 JSON…", command=self.browse_trace)
        file_menu.add_separator()
        file_menu.add_command(label="打开输出目录", command=self.open_output_dir)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.destroy)
        menubar.add_cascade(label="文件", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="关于 / 使用说明", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)
        self.root.config(menu=menubar)

    # ------------------------------------------------------------------ 布局
    def _build_layout(self) -> None:
        header = tk.Frame(self.root, bg=COLORS["header"], height=64)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(
            header, text=APP_NAME, bg=COLORS["header"], fg="white",
            font=("Microsoft YaHei UI", 16, "bold"),
        ).pack(side="left", padx=16, pady=10)
        tk.Label(
            header,
            text=APP_SUBTITLE,
            bg=COLORS["header"], fg="#c9d6e8", font=("Microsoft YaHei UI", 9),
        ).pack(side="left", pady=18)
        tk.Label(
            header, text=f"v{__version__}   引擎 TianTi   schema: tianti.trace/1",
            bg=COLORS["header"], fg="#c9d6e8", font=("Microsoft YaHei UI", 9),
        ).pack(side="right", padx=16)

        body = ttk.Frame(self.root, padding=(10, 8))
        body.pack(fill="both", expand=True)

        self._build_inputs(body)
        self._build_results(body)
        self._build_status(body)

    def _build_inputs(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="扫描目标", padding=10)
        frame.pack(fill="x")

        row1 = ttk.Frame(frame)
        row1.pack(fill="x")
        ttk.Label(row1, text="路径：").pack(side="left")
        self.path_var = tk.StringVar()
        entry = ttk.Entry(row1, textvariable=self.path_var)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row1, text="选择文件", command=self.browse_sample).pack(side="left", padx=2)
        ttk.Button(row1, text="选择目录", command=self.browse_directory).pack(side="left", padx=2)

        row2 = ttk.Frame(frame)
        row2.pack(fill="x", pady=(10, 0))
        ttk.Label(row2, text="模式：").pack(side="left")
        self.mode_var = tk.StringVar(value="auto")
        for text, value in (
            ("自动（trace 回放 / 其他沙箱执行）", "auto"),
            ("强制沙箱执行", "sandbox"),
            ("强制离线回放", "replay"),
        ):
            ttk.Radiobutton(row2, text=text, value=value, variable=self.mode_var).pack(side="left", padx=(0, 12))

        ttk.Separator(row2, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Label(row2, text="策略：").pack(side="left")
        self.policy_var = tk.StringVar(value=self.config.default_policy)
        ttk.Combobox(
            row2, textvariable=self.policy_var, values=sorted(self.config.policies),
            width=8, state="readonly",
        ).pack(side="left", padx=(0, 16))
        self.upstream_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="加载上游 capa 规则（rules/upstream）", variable=self.upstream_var).pack(side="left")

        row3 = ttk.Frame(frame)
        row3.pack(fill="x", pady=(10, 0))
        self.start_button = ttk.Button(row3, text="开始扫描", style="Accent.TButton", command=self.start_scan)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(row3, text="停止", command=self.request_stop, state="disabled")
        self.stop_button.pack(side="left", padx=6)
        self.html_button = ttk.Button(row3, text="打开 HTML 报告", command=self.open_html, state="disabled")
        self.html_button.pack(side="left", padx=6)
        ttk.Button(row3, text="打开输出目录", command=self.open_output_dir).pack(side="left", padx=6)
        self.clear_button = ttk.Button(row3, text="清空结果", command=self.clear_results)
        self.clear_button.pack(side="left", padx=6)
        ttk.Label(
            row3, text="提示：离线回放不会执行样本，适合反复调规则；沙箱执行受火绒 HIPS 监控可能弹窗。",
            foreground=COLORS["muted"],
        ).pack(side="left", padx=12)

    def _build_results(self, parent: ttk.Frame) -> None:
        paned = ttk.PanedWindow(parent, orient="horizontal")
        paned.pack(fill="both", expand=True, pady=(10, 0))

        left = ttk.Frame(paned, padding=(0, 0, 6, 0))
        paned.add(left, weight=5)
        columns = ("name", "verdict", "score", "confidence", "matches", "hits")
        headings = ("文件", "判定", "分数", "置信度", "能力", "危险行为")
        widths = (230, 64, 62, 66, 52, 78)
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        for column, heading, width in zip(columns, headings, widths):
            self.tree.heading(column, text=heading)
            self.tree.column(column, width=width, anchor="center" if column != "name" else "w", stretch=(column == "name"))
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")
        self.tree.tag_configure("malicious", foreground=COLORS["malicious"])
        self.tree.tag_configure("suspicious", foreground=COLORS["suspicious"])
        self.tree.tag_configure("clean", foreground=COLORS["clean"])
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        right = ttk.Frame(paned, padding=(6, 0, 0, 0))
        paned.add(right, weight=6)
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)

        self._build_summary_tab()

        self.summary_text = self._add_text_tab("摘要")
        self.cap_tree, self.cap_frame = self._add_tree_tab("能力", ("name", "namespace", "attck", "techniques", "evidence"), ("规则", "命名空间", "ATT&CK", "技术", "证据数"), (190, 170, 260, 90, 60))
        self.det_tree, self.det_frame = self._add_tree_tab("危险行为", ("name", "severity", "score", "tactic", "technique", "evidence"), ("检测器", "严重度", "分数", "战术", "技术", "证据数"), (200, 70, 70, 80, 90, 60))
        self.timeline_text = self._add_text_tab("事件时间线")
        self.signal_tree, self.signal_frame = self._add_tree_tab("静态信号", ("id", "severity", "score", "detail"), ("信号", "严重度", "分数", "说明"), (220, 70, 60, 420))
        self.raw_text = self._add_text_tab("原始 JSON")
        self.notes_text = self._add_text_tab("备注")

        self.cap_tree.bind("<<TreeviewSelect>>", self._on_cap_select)
        self.det_tree.bind("<<TreeviewSelect>>", self._on_det_select)

        placeholder = "在左侧选择一条扫描结果查看详情。\n\n" \
                      "· 自动模式：选中的是 tianti.trace/1 轨迹 JSON 时走离线回放，不会执行样本；\n" \
                      "· 其他文件走 containment 沙箱（受限令牌 + 低完整性 + 断网 + 超时强杀）；\n" \
                      "· 需要上游 capa 规则时勾选「加载上游规则」。"
        self._set_text(self.summary_text, placeholder)


    # ------------------------------------------------------------------ 汇总
    def _build_summary_tab(self) -> None:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="汇总")
        top = ttk.Frame(frame)
        top.pack(fill="x", pady=(4, 6))
        self.matrix_summary_var = tk.StringVar(value="尚无结果：扫描后这里显示批量结果矩阵与统计。")
        ttk.Label(top, textvariable=self.matrix_summary_var, justify="left").pack(side="left")
        ttk.Button(top, text="导出汇总 CSV", command=self.export_summary_csv).pack(side="right")
        columns = ("name", "verdict", "score", "confidence", "matches", "hits", "tactics")
        headings = ("文件", "判定", "分数", "置信度", "能力", "危险行为", "战术")
        widths = (250, 70, 70, 70, 60, 70, 260)
        self.matrix_tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for column, heading, width in zip(columns, headings, widths):
            self.matrix_tree.heading(column, text=heading)
            self.matrix_tree.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.matrix_tree.yview)
        self.matrix_tree.configure(yscrollcommand=scroll.set)
        self.matrix_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")
        self.matrix_tree.tag_configure("malicious", foreground=COLORS["malicious"])
        self.matrix_tree.tag_configure("suspicious", foreground=COLORS["suspicious"])
        self.matrix_tree.tag_configure("clean", foreground=COLORS["clean"])
        self.matrix_tree.bind("<<TreeviewSelect>>", self._on_matrix_select)

    def _refresh_summary(self, *, elapsed_s: float = 0.0) -> None:
        ordered = sorted(
            self.results.items(), key=lambda item: (-float(item[1].verdict.score), item[1].sample_name)
        )
        for item in self.matrix_tree.get_children():
            self.matrix_tree.delete(item)
        self._matrix_map = {}
        for index, (_iid, result) in enumerate(ordered):
            iid = f"m{index}"
            self._matrix_map[iid] = result
            self.matrix_tree.insert(
                "", "end", iid=iid,
                values=(
                    result.sample_name,
                    fmt.verdict_label(result.verdict_name),
                    f"{float(result.verdict.score):.2f}",
                    f"{float(result.verdict.confidence) * 100:.0f}%",
                    len(result.matches),
                    len(result.hits),
                    ", ".join(result.verdict.tactics) or "-",
                ),
                tags=(result.verdict_name,),
            )
        elapsed = elapsed_s or (time.monotonic() - self._batch_started if self._batch_started else 0.0)
        stats = fmt.summary_stats(
            [result for _, result in ordered], errors=len(self.errors), elapsed_s=elapsed
        )
        if stats["total"]:
            self.matrix_summary_var.set(fmt.stats_line(stats))
        else:
            self.matrix_summary_var.set("尚无结果：扫描后这里显示批量结果矩阵与统计。")

    def _on_matrix_select(self, _event: Any = None) -> None:
        selection = self.matrix_tree.selection()
        if not selection:
            return
        result = self._matrix_map.get(selection[0])
        if result is None:
            return
        for iid, candidate in self.results.items():
            if candidate is result:
                self.tree.selection_set(iid)
                self.tree.see(iid)
                break
        self._show_result(result)

    def _finish_batch(self) -> None:
        elapsed = time.monotonic() - self._batch_started if self._batch_started else 0.0
        self._refresh_summary(elapsed_s=elapsed)
        stats = fmt.summary_stats(list(self.results.values()), errors=len(self.errors), elapsed_s=elapsed)
        summary = (
            f"完成：{stats['total']} 个结果，恶意 {stats['malicious']} / 可疑 {stats['suspicious']} / 干净 {stats['clean']}"
        )
        if self.errors:
            summary += f"，失败 {len(self.errors)} 个文件"
        self.status_var.set(summary)
        if stats["total"]:
            self.notebook.select(0)
        self.count_var.set(f"结果：{stats['total']}    失败：{len(self.errors)}")

    def clear_results(self) -> None:
        if self.scanning:
            return
        self.results.clear()
        self.errors.clear()
        self._matrix_map.clear()
        self._batch_started = 0.0
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for iid in self.matrix_tree.get_children():
            self.matrix_tree.delete(iid)
        for tree in (self.cap_tree, self.det_tree, self.signal_tree):
            for iid in tree.get_children():
                tree.delete(iid)
        for widget in (self.timeline_text, self.raw_text, self.notes_text):
            self._set_text(widget, "")
        self._set_text(self.summary_text, "在左侧选择一条扫描结果查看详情。")
        self.matrix_summary_var.set("尚无结果：扫描后这里显示批量结果矩阵与统计。")
        self.count_var.set("结果：0    失败：0")
        self.status_var.set("已清空结果")

    def export_summary_csv(self) -> None:
        if not self.results:
            messagebox.showinfo("没有结果", "先扫描出结果再导出汇总。")
            return
        out_dir = self.config.paths.out / "gui"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = filedialog.asksaveasfilename(
            title="导出汇总 CSV",
            defaultextension=".csv",
            initialdir=str(out_dir),
            initialfile="summary.csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not path:
            return
        try:
            Path(path).write_text("\ufeff" + fmt.matrix_csv(fmt.matrix_rows(self.results.values())), encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        self.status_var.set(f"汇总已导出：{path}")

    def _add_text_tab(self, title: str) -> scrolledtext.ScrolledText:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        widget = scrolledtext.ScrolledText(frame, wrap="word", font=("Consolas", 9), bg=COLORS["panel"], relief="flat")
        widget.pack(fill="both", expand=True)
        widget.configure(state="disabled")
        return widget

    def _add_tree_tab(
        self, title: str, columns: tuple[str, ...], headings: tuple[str, ...], widths: tuple[int, ...]
    ) -> tuple[ttk.Treeview, ttk.Frame]:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")
        return tree, frame

    def _build_status(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=(8, 0))
        self.progress = ttk.Progressbar(frame, mode="indeterminate", length=220)
        self.progress.pack(side="left")
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(frame, textvariable=self.status_var).pack(side="left", padx=10)
        self.count_var = tk.StringVar(value="结果：0")
        ttk.Label(frame, textvariable=self.count_var, foreground=COLORS["muted"]).pack(side="right")

    # ------------------------------------------------------------------ 交互
    def browse_sample(self) -> None:
        path = filedialog.askopenfilename(title="选择待检样本")
        if path:
            self.path_var.set(path)

    def browse_directory(self) -> None:
        path = filedialog.askdirectory(title="选择待检目录")
        if path:
            self.path_var.set(path)

    def browse_trace(self) -> None:
        path = filedialog.askopenfilename(title="选择行为轨迹 JSON", filetypes=[("Trace JSON", "*.json"), ("所有文件", "*.*")])
        if path:
            self.mode_var.set("replay")
            self.path_var.set(path)

    def start_scan(self) -> None:
        if self.scanning:
            return
        raw = self.path_var.get().strip()
        if not raw:
            messagebox.showwarning("没有输入", "请先选择文件或目录。")
            return
        target = Path(raw)
        if not target.exists():
            messagebox.showerror("路径不存在", f"{target}")
            return
        try:
            files = self._collect_targets(target)
        except TiantiError as exc:
            messagebox.showerror("无法扫描", exc.message)
            return
        if not files:
            messagebox.showwarning("没有文件", "目标下没有可扫描文件。")
            return

        self.cancel_requested.clear()
        self.errors.clear()
        self._batch_started = time.monotonic()
        self._set_scanning(True)
        self.status_var.set(f"准备扫描 {len(files)} 个文件…")
        thread = threading.Thread(
            target=self._worker,
            args=(files, self.mode_var.get(), self.policy_var.get(), bool(self.upstream_var.get())),
            daemon=True,
        )
        thread.start()

    def request_stop(self) -> None:
        self.cancel_requested.set()
        killed = self._force_kill_current()
        if killed:
            self.status_var.set("已强杀当前沙箱进程，等待收尾…")
        else:
            self.status_var.set("已请求停止（当前没有正在运行的沙箱进程）…")

    def _collect_targets(self, target: Path) -> list[Path]:
        if target.is_file():
            return [target]
        files = sorted(path for path in target.rglob("*") if path.is_file())
        return files[:MAX_DIR_FILES]

    def _worker(self, files: list[Path], mode: str, policy: str, include_upstream: bool) -> None:
        for index, path in enumerate(files, start=1):
            if self.cancel_requested.is_set():
                self.queue.put(("stopped", None))
                break
            self.queue.put(("status", f"[{index}/{len(files)}] 正在分析 {path.name} …"))
            try:
                result = self._analyze_one(
                    path, mode, policy, include_upstream, index=index, total=len(files)
                )
                self.queue.put(("row", result))
            except _Cancelled:
                self.queue.put(("stopped", None))
                break
            except Exception as exc:  # 单文件失败不中断整批
                self.queue.put(("error", (path.name, str(exc))))
        self.queue.put(("done", None))

    def _analyze_one(
        self,
        path: Path,
        mode: str,
        policy: str,
        include_upstream: bool,
        *,
        index: int = 1,
        total: int = 1,
    ) -> ScanResult:
        is_trace = path.suffix.lower() == ".json" and _looks_like_trace(path)
        replay = mode == "replay" or (mode == "auto" and is_trace)
        if replay:
            trace = schema.load(path)
            result = pipeline.analyze_trace(trace, config=self.config, include_upstream=include_upstream)
            result.notes.insert(0, "输入为 trace JSON：离线重放分析，未执行样本。")
            result.extra["input"] = "replay"
            result.extra["source_path"] = str(path)
            return result
        return self._run_cli_scan(path, policy, include_upstream, index=index, total=total)

    def _run_cli_scan(
        self, path: Path, policy: str, include_upstream: bool, *, index: int, total: int
    ) -> ScanResult:
        """沙箱扫描放到子进程执行，便于「停止」时整棵进程树强杀。"""
        tmp = Path(tempfile.mkdtemp(prefix="tianti_gui_"))
        command = [
            sys.executable, "-m", "tianti", "scan", str(path),
            "--policy", policy, "--format", "json", "--out", str(tmp),
        ]
        if include_upstream:
            command.append("--include-upstream")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            command,
            cwd=str(self.config.paths.root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
        with self._proc_lock:
            self.current_proc = proc
        started = time.monotonic()
        try:
            while proc.poll() is None:
                if self.cancel_requested.is_set():
                    self._kill_process_tree(proc)
                    raise _Cancelled()
                elapsed = time.monotonic() - started
                self.queue.put(("status", f"[{index}/{total}] 沙箱执行 {path.name} … {elapsed:.1f}s"))
                time.sleep(0.2)
            stdout, stderr = proc.communicate()
        finally:
            with self._proc_lock:
                self.current_proc = None
        if proc.returncode != 0:
            lines = (stderr or stdout or "").strip().splitlines()
            raise RuntimeError("CLI 扫描失败: " + (lines[-1] if lines else f"退出码 {proc.returncode}"))
        candidates = sorted(tmp.glob("*.result.json"))
        if not candidates:
            raise RuntimeError("CLI 未产出结果文件")
        result = load_result(candidates[0])
        shutil.rmtree(tmp, ignore_errors=True)
        return result

    def _kill_process_tree(self, proc: "subprocess.Popen[str]") -> None:
        if proc.poll() is not None:
            return
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True, text=True, timeout=15, creationflags=creationflags,
            )
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    def _force_kill_current(self) -> bool:
        with self._proc_lock:
            proc = self.current_proc
        if proc is None or proc.poll() is not None:
            return False
        self._kill_process_tree(proc)
        return True

    # ------------------------------------------------------------------ 队列
    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "status":
                    self.status_var.set(str(payload))
                elif kind == "row":
                    self._add_row(payload)
                elif kind == "error":
                    name, message = payload
                    self.errors.append({"file": str(name), "error": str(message)})
                    self.status_var.set(f"错误：{name}: {message}")
                    self._refresh_summary()
                elif kind == "stopped":
                    self.status_var.set("已停止：当前沙箱进程已强杀")
                elif kind == "done":
                    self._set_scanning(False)
                    self._finish_batch()
        except queue.Empty:
            pass
        self.root.after(120, self._poll_queue)

    def _add_row(self, result: ScanResult) -> None:
        self._row_seq += 1
        iid = f"r{self._row_seq}"
        self.results[iid] = result
        self.tree.insert(
            "", "end", iid=iid,
            values=(
                result.sample_name,
                fmt.verdict_label(result.verdict_name),
                fmt.score_text(result),
                fmt.confidence_text(result),
                len(result.matches),
                len(result.hits),
            ),
            tags=(result.verdict_name,),
        )
        self.tree.selection_set(iid)
        self._show_result(result)
        self._refresh_summary()
        self.count_var.set(f"结果：{len(self.results)}")

    def _set_scanning(self, scanning: bool) -> None:
        self.scanning = scanning
        self.start_button.configure(state="disabled" if scanning else "normal")
        self.stop_button.configure(state="normal" if scanning else "disabled")
        self.html_button.configure(state="disabled" if scanning else "normal")
        self.clear_button.configure(state="disabled" if scanning else "normal")
        if scanning:
            self.progress.start(12)
        else:
            self.progress.stop()

    # ------------------------------------------------------------------ 详情
    def _on_select(self, _event: Any = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        result = self.results.get(selection[0])
        if result is not None:
            self._show_result(result)

    def _show_result(self, result: ScanResult) -> None:
        self._set_text(self.summary_text, fmt.summary_text(result))
        self._fill_tree(
            self.cap_tree,
            [
                (row["name"], row["namespace"], row["attck"] or "-", row["techniques"] or "-", row["evidence_count"])
                for row in fmt.capability_rows(result)
            ],
        )
        self._cap_rows = fmt.capability_rows(result)
        self._fill_tree(
            self.det_tree,
            [
                (row["name"] or row["id"], row["severity_label"], f"{row['score']:.1f}",
                 row["tactic"], row["technique"], row["evidence_count"])
                for row in fmt.detector_rows(result)
            ],
        )
        self._det_rows = fmt.detector_rows(result)
        self._fill_tree(
            self.signal_tree,
            [(row["id"], row["severity"], f"{row['score']:.1f}", row["detail"]) for row in fmt.static_signal_rows(result)],
        )
        self._sig_rows = fmt.static_signal_rows(result)
        timeline = [fmt.event_line(row) for row in fmt.event_rows(result)]
        if len(result.events) > 3000:
            timeline.append(f"...（共 {len(result.events)} 条事件，仅显示前 3000 条；完整事件见原始 JSON）")
        self._set_text(self.timeline_text, "\n".join(timeline) or "（没有事件）")
        self._set_text(self.raw_text, fmt.json_text(result))
        self._set_text(self.notes_text, fmt.notes_text(result))

    def _on_cap_select(self, _event: Any = None) -> None:
        selection = self.cap_tree.selection()
        if not selection or not self._cap_rows:
            return
        index = self.cap_tree.index(selection[0])
        if index >= len(self._cap_rows):
            return
        row = self._cap_rows[index]
        text = (
            f"{row['name']}\n"
            f"命名空间: {row['namespace']}    作用域: {row['scope']}    置信度: {row['confidence']}\n"
            f"ATT&CK: {row['attck'] or '-'}\n"
            f"证据事件: {row['evidence'] or '-'}\n"
            f"来源: {row['source']}\n"
        )
        self._set_text(self.notes_text, text)

    def _on_det_select(self, _event: Any = None) -> None:
        selection = self.det_tree.selection()
        if not selection or not self._det_rows:
            return
        index = self.det_tree.index(selection[0])
        if index >= len(self._det_rows):
            return
        row = self._det_rows[index]
        text = (
            f"{row['name']} ({row['id']})\n"
            f"严重度: {row['severity_label']}    分数: {row['score']:.1f}    抑制: {row['suppressed']}\n"
            f"战术/技术: {row['tactic']} / {row['technique']}\n"
            f"证据事件: {row['evidence'] or '-'}\n"
            f"说明: {row['detail'] or '-'}\n"
        )
        self._set_text(self.notes_text, text)

    def _fill_tree(self, tree: ttk.Treeview, rows: Iterable[tuple[Any, ...]]) -> None:
        for item in tree.get_children():
            tree.delete(item)
        for row in rows:
            tree.insert("", "end", values=row)

    def _set_text(self, widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # ------------------------------------------------------------------ 动作
    def open_html(self) -> None:
        selection = self.tree.selection()
        result = self.results.get(selection[0]) if selection else None
        if result is None:
            return
        out_dir = self.config.paths.out / "gui"
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = _safe_stem(result.sample_name)
        json_path = save_result(result, out_dir / f"{stem}.result.json")
        html_path = save_html(result, out_dir / f"{stem}.report.html", title=f"天体引擎报告 - {result.sample_name}")
        self.status_var.set(f"已生成报告：{html_path}")
        try:
            os.startfile(str(html_path))  # type: ignore[attr-defined]
        except Exception:
            messagebox.showinfo("报告已生成", f"{html_path}\n{json_path}")

    def open_output_dir(self) -> None:
        self.config.paths.out.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(self.config.paths.out))  # type: ignore[attr-defined]
        except Exception as exc:
            messagebox.showinfo("输出目录", f"{self.config.paths.out}\n({exc})")

    def show_about(self) -> None:
        messagebox.showinfo(
            f"关于{APP_NAME}",
            f"{APP_NAME}（Yutian Analysis）\n"
            "沙箱 + capa 规则能力识别 + 危险行为检测\n"
            f"引擎内核：TianTi v{__version__}\n\n"
            "· 自动模式：trace JSON 离线回放；其他文件走 containment 沙箱\n"
            "· 离线回放不会执行样本，适合反复调规则\n"
            "· 沙箱执行受本机火绒 HIPS 监控可能弹窗（受限令牌/低完整性/断网）\n\n"
            f"版本 {__version__}    schema: tianti.trace/1",
        )

    # ------------------------------------------------------------------ 演示
    def load_demo_trace(self, trace_path: str | Path) -> None:
        trace = schema.load(trace_path)
        result = pipeline.analyze_trace(trace, config=self.config)
        result.notes.insert(0, "演示数据：离线回放，未执行样本。")
        self._add_row(result)

    def capture(self, path: str | Path, *, delay_ms: int = 1200) -> None:
        """截图当前窗口（需要 Pillow；失败只打印原因，不影响主流程）。"""

        def grab() -> None:
            try:
                import ctypes
                import time
                from ctypes import wintypes

                from PIL import ImageGrab  # type: ignore

                # 先置顶并强制刷新，避免被其他窗口遮挡导致截到空白
                self.root.lift()
                self.root.attributes("-topmost", True)
                self.root.focus_force()
                self.root.update_idletasks()
                self.root.update()
                time.sleep(0.8)
                self.root.update_idletasks()
                self.root.update()

                image = None
                # 优先用窗口真实物理坐标（处理 DPI 缩放）
                try:
                    hwnd = int(self.root.wm_frame(), 16)
                    rect = wintypes.RECT()
                    if ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                        bbox = (rect.left, rect.top, rect.right, rect.bottom)
                        image = ImageGrab.grab(bbox=bbox)
                except Exception:
                    image = None
                if image is None:
                    image = ImageGrab.grab()
                image.save(str(path))
                print(f"screenshot saved: {path} {image.size}")
            except Exception as exc:  # pragma: no cover - 环境相关
                print(f"screenshot failed: {exc}")
            finally:
                self.root.after(200, self.root.destroy)

        self.root.after(delay_ms, grab)


def _looks_like_trace(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False
    return "tianti.trace/1" in head


def _safe_stem(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in str(name))
    return cleaned[:80] or "sample"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tianti gui", description="御天分析（Tk 桌面前端）")
    parser.add_argument("--path", default=None, help="启动时填入的样本/轨迹路径")
    parser.add_argument("--demo", action="store_true", help="加载 golden trace 演示数据")
    parser.add_argument("--trace", default=None, help="配合 --demo 指定 trace 文件")
    parser.add_argument("--screenshot", default=None, help="渲染后截图保存到指定 PNG（需要 Pillow）")
    parser.add_argument("--smoke", action="store_true", help="自检：创建窗口后立即退出（CI 用）")
    args = parser.parse_args(argv)

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"无法创建 Tk 窗口（没有可用显示器？）: {exc}")
        return 2

    try:
        app = TiantiApp(root, initial_path=args.path)
        if args.demo:
            fixtures = app.config.paths.root / "tests" / "fixtures" / "traces"
            if args.trace:
                paths = [Path(args.trace)]
            else:
                paths = [
                    fixtures / "golden_ransom_sim.json",
                    fixtures / "golden_injection.json",
                    fixtures / "golden_benign_installer.json",
                ]
            for trace_path in paths:
                app.load_demo_trace(trace_path)
            app.notebook.select(0)
        if args.smoke:
            root.withdraw()
            root.update_idletasks()
            root.update()
            root.after(120, root.destroy)
            root.mainloop()
            print("gui smoke ok")
            return 0
        if args.screenshot:
            app.capture(args.screenshot)
        root.mainloop()
        return 0
    except Exception as exc:  # pragma: no cover - 启动期异常给用户可读信息
        messagebox.showerror("启动失败", f"{type(exc).__name__}: {exc}")
        raise
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
