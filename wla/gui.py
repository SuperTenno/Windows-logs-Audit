"""轻量级 Tkinter 图形界面：选择模式、配置参数、后台审计、查看结果。"""

from __future__ import annotations

import datetime as dt
import os
import queue
import sys
import threading
import tkinter as tk
import traceback
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText

from . import __version__, knowledge
from .collectors import (
    CollectOptions,
    CollectionError,
    LocalCollector,
    OfflineCollector,
    WinRMCollector,
    collect,
)
from .demo import build_demo
from .diagnostics import format_diagnostics, run_diagnostics
from .elevation import is_admin, relaunch_as_admin
from .engine import analyze
from .iis import parse_iis_text
from .parser import parse_events
from .report import DOCX_AVAILABLE, summarize, write_report
from .rules_base import RuleOptions
from .tomcat import parse_tomcat_text

FONT = "Microsoft YaHei UI"


class AuditApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"Windows 日志安全审计 v{__version__}")
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        width = min(1040, max(900, screen_width - 80))
        height = min(820, max(680, screen_height - 100))
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(900, 640)
        self.queue: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.running = False
        self.report_paths: list[str] = []
        self.is_elevated = is_admin()
        self._build_style()
        self._apply_icon()
        self._build_ui()
        self._update_mode()
        self.root.after(120, self._poll)

    # ---- 样式 ----
    def _build_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=(FONT, 9))
        style.configure("Title.TLabel", font=(FONT, 16, "bold"), foreground="#0B3D6B")
        style.configure("Sub.TLabel", foreground="#6B7280")
        style.configure("Accent.TButton", font=(FONT, 10, "bold"))
        style.configure("Treeview", rowheight=24, font=(FONT, 9))
        style.configure("Treeview.Heading", font=(FONT, 9, "bold"))

    # ---- 界面 ----
    def _apply_icon(self) -> None:
        base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
        icon = base / "assets" / "app.ico"
        if icon.exists():
            try:
                self.root.iconbitmap(default=str(icon))
            except tk.TclError:
                pass

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Windows 主机日志安全审计", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="事件日志 + IIS + Tomcat 中间件 · 入侵痕迹检测 · Word/Markdown/JSON/HTML 报告",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(2, 10))

        if not self.is_elevated:
            banner = ttk.Frame(outer)
            banner.pack(fill="x", pady=(0, 8))
            ttk.Label(
                banner,
                text="⚠ 当前未以管理员身份运行：本机模式读取 Security 日志会失败",
                foreground="#B91C1C",
            ).pack(side="left")
            ttk.Button(
                banner, text="以管理员身份重启", command=self._elevate
            ).pack(side="left", padx=8)

        mode_frame = ttk.LabelFrame(outer, text="审计模式", padding=8)
        mode_frame.pack(fill="x")
        self.mode = tk.StringVar(value="remote")
        for value, label in (
            ("remote", "远程主机（WinRM）"),
            ("local", "本机日志"),
            ("offline", "离线日志目录"),
            ("demo", "演示数据"),
        ):
            ttk.Radiobutton(
                mode_frame, text=label, value=value, variable=self.mode,
                command=self._update_mode,
            ).pack(side="left", padx=(0, 18))

        # 连接参数
        conn = ttk.LabelFrame(outer, text="连接与路径", padding=8)
        conn.pack(fill="x", pady=8)
        self.host = tk.StringVar()
        self.port = tk.StringVar(value="5985")
        self.user = tk.StringVar()
        self.password = tk.StringVar()
        self.ssl = tk.BooleanVar(value=False)
        self.offline_dir = tk.StringVar()

        self.host_entry = self._labeled_entry(conn, "目标主机", self.host, 0, 0, 24)
        self.port_entry = self._labeled_entry(conn, "WinRM 端口", self.port, 0, 2, 8)
        self.user_entry = self._labeled_entry(conn, "用户名", self.user, 1, 0, 24)
        self.pass_entry = self._labeled_entry(conn, "密码", self.password, 1, 2, 20, show="*")
        ttk.Checkbutton(conn, text="使用 HTTPS(SSL)", variable=self.ssl).grid(
            row=2, column=0, sticky="w", pady=(6, 0)
        )

        self.offline_row = ttk.Frame(conn)
        self.offline_row.grid(row=3, column=0, columnspan=5, sticky="ew", pady=(6, 0))
        ttk.Label(self.offline_row, text="离线日志目录").pack(side="left")
        self.offline_entry = ttk.Entry(self.offline_row, textvariable=self.offline_dir, width=62)
        self.offline_entry.pack(side="left", padx=8)
        ttk.Button(self.offline_row, text="浏览...", command=self._choose_dir).pack(side="left")

        # 分析选项
        opts = ttk.LabelFrame(outer, text="分析选项", padding=8)
        opts.pack(fill="x")
        self.since = tk.StringVar(value="168")
        self.max_events = tk.StringVar(value="0")
        self.format_var = tk.StringVar(value="docx")
        self.no_iis = tk.BooleanVar(value=False)
        self.no_tomcat = tk.BooleanVar(value=False)
        self.no_posture = tk.BooleanVar(value=False)
        self.no_charts = tk.BooleanVar(value=False)

        self._labeled_entry(opts, "最近 N 小时", self.since, 0, 0, 8)
        self._labeled_entry(opts, "每日志最大条数(0=默认)", self.max_events, 0, 2, 10)
        ttk.Label(opts, text="报告格式").grid(row=0, column=4, sticky="e", padx=(12, 4))
        ttk.Combobox(
            opts, textvariable=self.format_var, width=8, state="readonly",
            values=["docx", "md", "json", "html", "all"],
        ).grid(row=0, column=5, sticky="w")

        checks = ttk.Frame(opts)
        checks.grid(row=1, column=0, columnspan=6, sticky="w", pady=(6, 0))
        ttk.Checkbutton(checks, text="跳过 IIS", variable=self.no_iis).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="跳过 Tomcat", variable=self.no_tomcat).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="跳过主机基线", variable=self.no_posture).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="不生成图表", variable=self.no_charts).pack(side="left")

        out_row = ttk.Frame(opts)
        out_row.grid(row=2, column=0, columnspan=6, sticky="ew", pady=(6, 0))
        ttk.Label(out_row, text="报告路径").pack(side="left")
        self.out_path = tk.StringVar()
        ttk.Entry(out_row, textvariable=self.out_path, width=70).pack(side="left", padx=8, fill="x", expand=True)
        ttk.Button(out_row, text="另存为...", command=self._choose_output).pack(side="left")

        # 操作按钮
        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=6)
        self.start_button = ttk.Button(
            buttons, text="开始审计", style="Accent.TButton", command=self._start
        )
        self.start_button.pack(side="left")
        self.open_button = ttk.Button(
            buttons, text="打开报告", command=self._open_report, state="disabled"
        )
        self.open_button.pack(side="left", padx=8)
        ttk.Button(buttons, text="打开输出目录", command=self._open_folder).pack(side="left")
        ttk.Button(buttons, text="清空日志", command=self._clear_log).pack(side="left", padx=8)
        ttk.Button(buttons, text="环境诊断", command=self._diagnose).pack(side="left")

        self.progress = ttk.Progressbar(buttons, mode="indeterminate", length=180)
        self.progress.pack(side="right")
        self.status = tk.StringVar(value="就绪")
        ttk.Label(buttons, textvariable=self.status).pack(side="right", padx=10)

        # 日志
        log_frame = ttk.LabelFrame(outer, text="运行日志", padding=6)
        log_frame.pack(fill="both", expand=True)
        self.log = ScrolledText(
            log_frame, height=16, wrap="word", font=(FONT, 9),
            background="#0F172A", foreground="#E5E7EB", insertbackground="#E5E7EB",
        )
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")
        self._append("提示：选择“演示数据”可直接体验完整审计流程；远程模式需目标启用 WinRM。")
        if not DOCX_AVAILABLE:
            self._append("警告：未安装 python-docx，将无法生成 Word 报告。")

    def _labeled_entry(self, parent, label, variable, row, column, width, show=None):
        ttk.Label(parent, text=label).grid(
            row=row, column=column, sticky="e", padx=(0, 6), pady=4
        )
        entry = ttk.Entry(parent, textvariable=variable, width=width, show=show)
        entry.grid(row=row, column=column + 1, sticky="w", padx=(0, 16), pady=4)
        return entry

    def _update_mode(self) -> None:
        mode = self.mode.get()
        previous = getattr(self, "_last_mode", None)
        if mode == "offline" and previous != "offline" and self.since.get().strip() == "168":
            self.since.set("0")
        elif previous == "offline" and mode != "offline" and self.since.get().strip() == "0":
            self.since.set("168")
        self._last_mode = mode
        remote = mode == "remote"
        for widget in (self.host_entry, self.port_entry, self.user_entry, self.pass_entry):
            widget.configure(state="normal" if remote else "disabled")
        if mode == "offline":
            self.offline_row.grid()
            self.offline_entry.configure(state="normal")
        else:
            self.offline_row.grid_remove()
        if mode == "demo":
            self.status.set("演示模式：无需目标主机")
        elif mode == "offline":
            self.status.set("离线模式：分析已导出的日志目录")
        else:
            self.status.set("就绪")

    def _choose_dir(self) -> None:
        path = filedialog.askdirectory(title="选择离线日志目录")
        if path:
            self.offline_dir.set(path)

    def _choose_output(self) -> None:
        fmt = self.format_var.get()
        extension = "docx" if fmt == "all" else fmt
        path = filedialog.asksaveasfilename(
            title="保存报告",
            defaultextension=f".{extension}",
            filetypes=[("Word 文档", "*.docx"), ("Markdown", "*.md"), ("JSON", "*.json"), ("HTML", "*.html")],
        )
        if path:
            self.out_path.set(path)

    # ---- 日志 ----
    def _append(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _log_threadsafe(self, text: str) -> None:
        self.queue.put(("log", text))

    def _elevate(self) -> None:
        if is_admin():
            self.is_elevated = True
            return
        if relaunch_as_admin(["--gui"]):
            self.root.destroy()
            return
        messagebox.showwarning(
            "提权失败",
            "未能启动管理员实例（UAC 被取消或系统策略禁止）。\n"
            "请右键程序选择“以管理员身份运行”，或运行 --diagnose 查看原因。",
            parent=self.root,
        )

    def _diagnose(self) -> None:
        self._append("")
        self._append("[*] 正在执行本机环境诊断（管理员权限 / Security 日志 / 审核策略）...")
        self.status.set("诊断中...")

        def work():
            collector = None
            try:
                collector = LocalCollector()
                data = run_diagnostics(collector)
                self.queue.put(("diag", data))
            except Exception as error:  # noqa: BLE001
                self.queue.put(("diag_error", str(error)))
            finally:
                if collector is not None:
                    try:
                        collector.close()
                    except Exception:  # noqa: BLE001
                        pass

        threading.Thread(target=work, daemon=True).start()

    def _show_diagnostics(self, data: dict) -> None:
        text = format_diagnostics(data)
        self._append(text)
        ok = bool(data.get("security_access")) and bool(data.get("security_read"))
        self.status.set("诊断完成：Security 日志可读" if ok else "诊断完成：Security 日志不可读")
        summary = "\n".join(text.splitlines()[:16])
        messagebox.showinfo("环境诊断", summary, parent=self.root)

    # ---- 启动 ----
    def _start(self) -> None:
        if self.running:
            return
        mode = self.mode.get()
        if mode == "remote":
            if not self.host.get().strip():
                messagebox.showwarning("缺少参数", "请输入目标主机地址")
                return
            if not self.user.get().strip():
                messagebox.showwarning("缺少参数", "请输入用户名")
                return
            if not self.password.get():
                value = simpledialog.askstring("密码", "请输入密码：", show="*", parent=self.root)
                if not value:
                    return
                self.password.set(value)
        if mode == "offline" and not self.offline_dir.get().strip():
            messagebox.showwarning("缺少参数", "请选择离线日志目录")
            return
        if mode == "local" and not is_admin():
            answer = messagebox.askyesno(
                "需要管理员权限",
                "读取 Security 日志需要完整管理员权限。\n\n"
                "当前进程未提升（UAC 过滤令牌）。是否以管理员身份重启？\n\n"
                "选择“否”将继续以普通权限采集，Security 日志将不可用。",
                parent=self.root,
            )
            if answer:
                self._elevate()
                return
            self._append("[!] 未提升权限：Security 日志将不可用，其他日志仍可分析。")

        self.report_paths = []
        self.open_button.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.progress.start(12)
        self.status.set("审计中...")
        self._append("")
        self._append("=" * 72)
        self._append(f"[{dt.datetime.now():%H:%M:%S}] 开始 {self.mode.get()} 审计")

        self.running = True
        self.worker = threading.Thread(target=self._run, daemon=True)
        self.worker.start()

    def _run(self) -> None:
        try:
            report, paths = self._execute()
            self.queue.put(("done", (report, paths)))
        except CollectionError as error:
            self.queue.put(("error", str(error)))
        except Exception as error:  # noqa: BLE001
            self.queue.put(("error", f"{error}\n{traceback.format_exc()}"))

    def _execute(self):
        mode = self.mode.get()
        output = self.out_path.get().strip()
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M")
        fmt = self.format_var.get()
        extension = "docx" if fmt == "all" else fmt

        if mode == "demo":
            data = build_demo()
            target = data.target
            stats = {"parsed": 0, "errors": 0}
            events = []
            collection = []
            for key in ("security", "system", "powershell", "defender", "rdp_lsm"):
                parsed = parse_events(getattr(data, key), key, stats)
                events.extend(parsed)
                collection.append(
                    {"log": key, "label": knowledge.LOG_LABELS.get(key, key),
                     "count": len(parsed), "status": "ok", "error": ""}
                )
            iis_records = parse_iis_text(data.iis, "demo")
            collection.append({"log": "iis", "label": "IIS Web 日志", "count": len(iis_records), "status": "ok", "error": ""})
            tomcat_access, tomcat_catalina = parse_tomcat_text(data.tomcat)
            collection.append({"log": "tomcat", "label": "Tomcat 中间件日志",
                               "count": len(tomcat_access) + len(tomcat_catalina), "status": "ok", "error": ""})
            report = analyze(
                events, iis_records=iis_records,
                tomcat_access=tomcat_access, tomcat_catalina=tomcat_catalina,
                posture=data.posture, options=self._rule_options(mode),
                target=target, mode="demo", collection=collection,
                parse_errors=stats["errors"],
            )
        else:
            target = self.host.get().strip() or os.environ.get("COMPUTERNAME", "local")
            if mode == "remote":
                port = int(self.port.get() or 5985)
                if self.ssl.get() and port == 5985:
                    port = 5986
                collector = WinRMCollector(
                    target, self.user.get().strip(), self.password.get(),
                    port=port, use_ssl=self.ssl.get(),
                )
            elif mode == "local":
                collector = LocalCollector()
                target = os.environ.get("COMPUTERNAME", "local")
            else:
                collector = OfflineCollector(self.offline_dir.get().strip())
                target = Path(self.offline_dir.get().strip()).name
            options = CollectOptions(
                since_hours=self._since_hours(mode),
                max_events=int(self.max_events.get() or 0),
                iis=not self.no_iis.get(),
                tomcat=not self.no_tomcat.get(),
                posture=not self.no_posture.get(),
                progress=self._log_threadsafe,
            )
            try:
                result = collect(collector, options)
            finally:
                try:
                    collector.close()
                except Exception:  # noqa: BLE001
                    pass
            self._log_threadsafe(
                f"采集完成：{len(result.events)} 条事件，"
                f"{len(result.iis_records)} 条 IIS 请求，"
                f"{len(parse_tomcat_text(result.tomcat_text)[0])} 条 Tomcat 请求"
            )
            tomcat_access, tomcat_catalina = parse_tomcat_text(result.tomcat_text)
            report = analyze(
                result.events,
                iis_records=result.iis_records,
                tomcat_access=tomcat_access,
                tomcat_catalina=tomcat_catalina,
                posture=result.posture,
                options=self._rule_options(mode),
                target=target, mode=mode,
                collection=result.collection,
                parse_errors=result.parse_errors,
            )

        if not output:
            safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in target)
            output = str(Path.cwd() / f"windows_security_audit_{safe}_{stamp}.{extension}")
        self._log_threadsafe(f"正在生成报告：{output}")
        paths = write_report(report, output, fmt, with_charts=not self.no_charts.get())
        return report, paths

    def _since_hours(self, mode: str) -> int:
        value = self.since.get().strip()
        if not value:
            return 0 if mode == "offline" else 168
        try:
            return max(0, int(value))
        except ValueError:
            return 168

    def _rule_options(self, mode: str) -> RuleOptions:
        hours = self._since_hours(mode)
        since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours) if hours > 0 else None
        return RuleOptions(since=since)

    # ---- 队列 ----
    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._append(payload)
                elif kind == "done":
                    report, paths = payload
                    self._finish(report, paths)
                elif kind == "error":
                    self._fail(payload)
                elif kind == "diag":
                    self._show_diagnostics(payload)
                elif kind == "diag_error":
                    self.status.set("诊断失败")
                    self._append(f"[-] 诊断失败：{payload}")
                    messagebox.showerror("诊断失败", payload, parent=self.root)
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _finish(self, report, paths) -> None:
        self.running = False
        self.progress.stop()
        self.start_button.configure(state="normal")
        self.report_paths = list(paths)
        if paths:
            self.open_button.configure(state="normal")
        self.status.set(f"完成 · {report.verdict}")
        self._append("")
        self._append(summarize(report, paths))
        if report.findings:
            self._append("主要发现：")
            for finding in report.sorted_findings()[:12]:
                self._append(f"  [{finding.severity.label}] {finding.title}")
        messagebox.showinfo(
            "审计完成",
            f"结论：{report.verdict}\n风险评分：{report.risk_score:.1f}\n"
            f"发现：{len(report.findings)} 项\n\n报告：{paths[0] if paths else '-'}",
            parent=self.root,
        )

    def _fail(self, message: str) -> None:
        self.running = False
        self.progress.stop()
        self.start_button.configure(state="normal")
        self.status.set("失败")
        self._append("[-] 审计失败：")
        self._append(message)
        messagebox.showerror("审计失败", message.splitlines()[0][:500], parent=self.root)

    def _open_report(self) -> None:
        if not self.report_paths:
            return
        path = self.report_paths[0]
        try:
            os.startfile(path)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            messagebox.showinfo("报告路径", path, parent=self.root)

    def _open_folder(self) -> None:
        folder = Path(self.report_paths[0]).parent if self.report_paths else Path.cwd()
        try:
            os.startfile(str(folder))  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            messagebox.showinfo("输出目录", str(folder), parent=self.root)


def main() -> int:
    try:
        root = tk.Tk()
    except tk.TclError as error:
        print(f"无法启动图形界面：{error}")
        return 1
    AuditApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
