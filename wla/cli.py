"""命令行入口与交互式向导。"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import re
import sys
import traceback
from pathlib import Path
from typing import Optional

from . import __version__, knowledge
from .collectors import (
    WINRM_AVAILABLE,
    CollectOptions,
    CollectionError,
    LocalCollector,
    OfflineCollector,
    WinRMCollector,
    collect,
)
from .demo import build_demo
from .diagnostics import format_diagnostics, run_diagnostics, security_usable
from .elevation import is_admin, relaunch_as_admin
from .engine import analyze
from .iis import parse_iis_text
from .models import Severity
from .parser import decode_text, parse_events
from .report import DOCX_AVAILABLE, summarize, write_report
from .rules_base import RuleOptions
from .tomcat import parse_tomcat_text

_SEVERITY_CHOICES = ["info", "low", "medium", "high", "critical"]


def _configure_stdio() -> None:
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:  # noqa: BLE001
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="WindowsLogAudit" if getattr(sys, "frozen", False) else "windows_log_audit.py",
        description=(
            "Windows 主机日志深度安全审计：采集/解析事件日志与 IIS 日志，"
            "检测暴力破解、后门账户、持久化、凭据窃取、WebShell、反取证等入侵痕迹，"
            "输出 Word/Markdown/JSON/HTML 报告。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python windows_log_audit.py --host 10.0.0.5 -u Administrator --ssl\n"
            "  python windows_log_audit.py --local --out audit.docx\n"
            "  python windows_log_audit.py --offline .\\exported_logs --format all\n"
            "  python windows_log_audit.py --demo\n"
        ),
    )
    mode = parser.add_argument_group("采集模式")
    mode.add_argument("--host", help="远程 Windows 主机 IP/名称（WinRM）")
    mode.add_argument("--port", type=int, default=5985, help="WinRM 端口，默认 5985（SSL 通常为 5986）")
    mode.add_argument("-u", "--user", help="用户名（域\\用户 或 本地用户）")
    mode.add_argument("-p", "--password", help="密码（不推荐，会留在命令历史中）")
    mode.add_argument("--password-file", help="从文件读取密码")
    mode.add_argument("--ssl", action="store_true", help="WinRM 使用 HTTPS")
    mode.add_argument("--local", action="store_true", help="采集本机日志（需管理员权限读取安全日志）")
    mode.add_argument("--offline", metavar="DIR", help="离线分析导出的日志目录")
    mode.add_argument("--demo", action="store_true", help="使用内置演示数据生成报告")
    mode.add_argument("--diagnose", action="store_true", help="诊断管理员权限与 Security 日志可读性")
    mode.add_argument("--no-elevate", action="store_true", help="本机模式不自动请求管理员权限")

    collect_group = parser.add_argument_group("采集选项")
    collect_group.add_argument("--since-hours", type=int, default=None, help="只采集最近 N 小时，默认 168；0 表示不限制（离线模式默认不限制）")
    collect_group.add_argument("--max-events", type=int, default=0, help="每个日志最多采集条数，0 使用内置默认值")
    collect_group.add_argument("--logs", help="仅采集指定日志，逗号分隔：security,system,application,powershell,rdp_lsm,rdp_rcm,defender,sysmon,wmi,bits,taskscheduler")
    collect_group.add_argument("--iis-path", action="append", default=[], help="自定义 IIS 日志根目录（可重复）")
    collect_group.add_argument("--iis-files", type=int, default=5, help="每个 IIS 站点最多读取的日志文件数，默认 5")
    collect_group.add_argument("--no-iis", action="store_true", help="跳过 IIS 日志")
    collect_group.add_argument("--tomcat-path", action="append", default=[], help="自定义 Tomcat 日志目录（可重复）")
    collect_group.add_argument("--no-tomcat", action="store_true", help="跳过 Tomcat 日志")
    collect_group.add_argument("--no-posture", action="store_true", help="跳过主机安全配置采集")
    collect_group.add_argument("--export-dir", help="把采集到的原始日志保存到目录，便于离线复现")

    analysis = parser.add_argument_group("分析选项")
    analysis.add_argument("--brute-threshold", type=int, default=5, help="同一来源登录失败多少次视为暴力破解，默认 5")
    analysis.add_argument("--brute-window", type=int, default=10, help="暴力破解滑动窗口（分钟），默认 10")
    analysis.add_argument("--min-severity", choices=_SEVERITY_CHOICES, default="info", help="报告中保留的最低级别，默认 info")
    analysis.add_argument("--geoip", metavar="MMDB", help="GeoLite2-City.mmdb 路径（可选，用于 IP 归属地）")
    analysis.add_argument("--no-charts", action="store_true", help="报告中不生成图表")

    output = parser.add_argument_group("输出")
    output.add_argument("--gui", action="store_true", help="启动图形界面")
    output.add_argument("--out", default="", help="报告文件路径，默认 windows_security_audit_<主机>_<时间>.docx")
    output.add_argument("--format", choices=["docx", "md", "json", "html", "all"], default="docx", help="报告格式，默认 docx")
    output.add_argument("--fail-on", choices=["none"] + _SEVERITY_CHOICES, default="none", help="发现达到该级别时以退出码 3 结束（便于自动化）")
    output.add_argument("--quiet", action="store_true", help="只输出最终摘要")
    output.add_argument("--debug", action="store_true", help="异常时打印堆栈")
    output.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.gui:
        try:
            from .gui import main as gui_main
        except ImportError as error:
            print(f"[-] 无法启动图形界面（缺少 tkinter）: {error}", file=sys.stderr)
            return 1
        return gui_main()

    if args.diagnose:
        return _run_diagnose(args)

    if args.demo:
        return _run_demo(args)
    if args.offline:
        return _run_offline(args)
    if args.local:
        return _run_local(args)
    if args.host:
        return _run_remote(args)

    return _interactive(args)


# ---------------------------------------------------------------------------
# 各模式
# ---------------------------------------------------------------------------
def _progress(args) -> callable:
    if args.quiet:
        return lambda message: None
    return lambda message: print(f"[*] {message}", flush=True)


def _run_diagnose(args) -> int:
    collector = None
    try:
        if args.host:
            if not WINRM_AVAILABLE:
                print("[-] 未安装 pywinrm", file=sys.stderr)
                return 1
            if not args.user:
                print("[-] 远程诊断需要 --user", file=sys.stderr)
                return 1
            password = _resolve_password(args)
            if password is None:
                return 1
            port = args.port
            if args.ssl and port == 5985:
                port = 5986
            collector = WinRMCollector(
                args.host, args.user, password, port=port, use_ssl=args.ssl
            )
            print(f"[*] 远程环境诊断：{args.host}:{port}", flush=True)
        else:
            collector = LocalCollector()
            print("[*] 本机环境诊断...", flush=True)
        data = run_diagnostics(collector)
        print(format_diagnostics(data))
        return 0 if security_usable(data) else 2
    except CollectionError as error:
        print(f"[-] 诊断失败：{error}", file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001
        print(f"[-] 诊断失败：{error}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return 1
    finally:
        if collector is not None:
            try:
                collector.close()
            except Exception:  # noqa: BLE001
                pass


def _run_remote(args) -> int:
    if args.since_hours is None:
        args.since_hours = 168
    if not WINRM_AVAILABLE:
        print("[-] 未安装 pywinrm，请执行: pip install pywinrm", file=sys.stderr)
        return 1
    if not args.user:
        print("[-] 远程模式需要 --user", file=sys.stderr)
        return 1
    password = _resolve_password(args)
    if password is None:
        return 1
    port = args.port
    if args.ssl and port == 5985:
        port = 5986
    try:
        collector = WinRMCollector(
            args.host, args.user, password, port=port, use_ssl=args.ssl
        )
    except CollectionError as error:
        print(f"[-] {error}", file=sys.stderr)
        return 1

    print(f"[*] 连接 {args.host}:{port}（{'HTTPS' if args.ssl else 'HTTP'}）...", flush=True)
    try:
        probe = collector.run_ps("$env:COMPUTERNAME", timeout=60).strip()
        print(f"[+] 连接成功，远程主机名：{probe or '未知'}", flush=True)
    except CollectionError as error:
        print(f"[-] WinRM 连接失败：{error}", file=sys.stderr)
        print("    请确认目标已启用 WinRM、账号具备管理员权限，且端口/SSL 配置正确。", file=sys.stderr)
        return 1

    target = args.host
    return _execute(args, collector, target, "remote")


def _run_local(args) -> int:
    if args.since_hours is None:
        args.since_hours = 168
    if not is_admin():
        print(
            "[!] 当前进程未以管理员身份运行（UAC 过滤令牌），无法读取 Security 日志。",
            flush=True,
        )
        if not args.no_elevate:
            print("[*] 正在请求管理员权限...", flush=True)
            if relaunch_as_admin():
                print("[+] 已启动管理员实例，请在新窗口继续。", flush=True)
                return 0
            print("[!] 提权被取消或失败。", file=sys.stderr)
        print("[!] 继续以普通权限采集：Security 日志将不可用，其他日志仍可分析。", file=sys.stderr)
        print("[!] 可运行 --diagnose 查看详细原因。", file=sys.stderr)
    try:
        collector = LocalCollector()
    except CollectionError as error:
        print(f"[-] {error}", file=sys.stderr)
        return 1
    print("[*] 本机采集：需要管理员权限才能读取安全日志。", flush=True)
    return _execute(args, collector, os.environ.get("COMPUTERNAME", "local"), "local")


def _run_offline(args) -> int:
    if args.since_hours is None:
        args.since_hours = 0
    try:
        collector = OfflineCollector(args.offline)
    except CollectionError as error:
        print(f"[-] {error}", file=sys.stderr)
        return 1
    print(f"[*] 离线分析目录：{collector.directory}（{len(collector.files)} 个文件）", flush=True)
    return _execute(args, collector, str(collector.directory.name), "offline")


def _run_demo(args) -> int:
    print("[*] 正在加载内置演示数据（模拟一条完整入侵链）...", flush=True)
    data = build_demo()
    stats = {"parsed": 0, "errors": 0}
    events = []
    collection = []
    for key in ("security", "system", "powershell", "defender", "rdp_lsm"):
        text = getattr(data, key)
        parsed = parse_events(text, key, stats)
        events.extend(parsed)
        collection.append(
            {
                "log": key,
                "label": knowledge.LOG_LABELS.get(key, key),
                "count": len(parsed),
                "status": "ok" if parsed else "empty",
                "error": "",
            }
        )
    iis_records = parse_iis_text(data.iis, "demo")
    collection.append(
        {
            "log": "iis",
            "label": "IIS Web 日志",
            "count": len(iis_records),
            "status": "ok",
            "error": "",
        }
    )

    tomcat_access, tomcat_catalina = parse_tomcat_text(data.tomcat)
    collection.append(
        {
            "log": "tomcat",
            "label": "Tomcat 中间件日志",
            "count": len(tomcat_access) + len(tomcat_catalina),
            "status": "ok",
            "error": "",
        }
    )

    rule_options = _rule_options(args)
    report = analyze(
        events,
        iis_records=iis_records,
        tomcat_access=tomcat_access,
        tomcat_catalina=tomcat_catalina,
        posture=data.posture,
        options=rule_options,
        target=data.target,
        mode="demo",
        collection=collection,
        parse_errors=stats["errors"],
    )
    return _finish(args, report, data.target)


def _execute(args, collector, target: str, mode: str) -> int:
    if args.since_hours is None:
        args.since_hours = 168
    logs = _parse_logs(args.logs)
    options = CollectOptions(
        since_hours=args.since_hours,
        max_events=args.max_events,
        logs=logs,
        iis=not args.no_iis,
        iis_paths=args.iis_path,
        iis_max_files=args.iis_files,
        tomcat=not args.no_tomcat,
        tomcat_paths=args.tomcat_path,
        posture=not args.no_posture,
        keep_raw=bool(args.export_dir),
        progress=_progress(args),
    )
    print("[*] 开始采集日志...", flush=True)
    try:
        result = collect(collector, options)
    except CollectionError as error:
        print(f"[-] 采集失败：{error}", file=sys.stderr)
        return 1
    finally:
        try:
            collector.close()
        except Exception:  # noqa: BLE001
            pass

    tomcat_access, tomcat_catalina = parse_tomcat_text(result.tomcat_text)
    print(
        f"[+] 采集完成：{len(result.events)} 条事件，{len(result.iis_records)} 条 IIS 请求，"
        f"{len(tomcat_access) + len(tomcat_catalina)} 条 Tomcat 日志",
        flush=True,
    )
    for entry in result.collection:
        if entry.get("status") not in {"ok", None}:
            print(f"    - {entry.get('label')}: {entry.get('status')} {entry.get('error', '')}", flush=True)

    if args.export_dir:
        _export_raw(result, args.export_dir, target, mode)
        print(f"[+] 原始日志已导出：{args.export_dir}", flush=True)

    rule_options = _rule_options(args)
    geo_lookup = _geo_lookup(args)
    report = analyze(
        result.events,
        iis_records=result.iis_records,
        tomcat_access=tomcat_access,
        tomcat_catalina=tomcat_catalina,
        posture=result.posture,
        options=rule_options,
        target=target,
        mode=mode,
        collection=result.collection,
        parse_errors=result.parse_errors,
        geo_lookup=geo_lookup,
    )
    return _finish(args, report, target)


def _finish(args, report, target: str) -> int:
    fmt = args.format
    if not DOCX_AVAILABLE and fmt in {"docx", "all"}:
        print("[!] 未安装 python-docx，跳过 Word 报告（pip install python-docx）", file=sys.stderr)
        if fmt == "docx":
            fmt = "md"

    output = args.out or _default_output(target, fmt)
    print("[*] 正在生成报告...", flush=True)
    try:
        paths = write_report(report, output, fmt, with_charts=not args.no_charts)
    except Exception as error:  # noqa: BLE001
        print(f"[-] 报告生成失败：{error}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return 1

    print(summarize(report, paths))
    threshold = Severity.parse(args.fail_on) if args.fail_on != "none" else None
    if threshold is not None and report.findings and report.max_severity >= threshold:
        return 3
    return 0


def _rule_options(args) -> RuleOptions:
    since = None
    if args.since_hours and args.since_hours > 0:
        since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=args.since_hours)
    return RuleOptions(
        brute_threshold=max(1, args.brute_threshold),
        brute_window_minutes=max(1, args.brute_window),
        since=since,
        min_severity=Severity.parse(args.min_severity),
    )


# ---------------------------------------------------------------------------
# 交互模式（保持旧版使用习惯）
# ---------------------------------------------------------------------------
def _interactive(args) -> int:
    print("=" * 62)
    print(" Windows 主机日志远程安全审计")
    print(f" 版本 {__version__}  |  支持 WinRM / 本机 / 离线 / 演示")
    print("=" * 62)
    print("  [1] 远程主机（WinRM）")
    print("  [2] 本机日志")
    print("  [3] 离线日志目录")
    print("  [4] 演示数据（无需目标主机）")
    choice = input("请选择审计模式 [1]: ").strip() or "1"
    if choice == "4":
        args.demo = True
        return _run_demo(args)
    if choice == "3":
        directory = input("日志目录路径: ").strip().strip('"')
        if not directory:
            print("[-] 未提供目录。", file=sys.stderr)
            return 1
        args.offline = directory
        return _run_offline(args)
    if choice == "2":
        args.local = True
        return _run_local(args)

    # 远程模式
    args.host = input("目标 Windows 主机 IP/名称: ").strip()
    if not args.host:
        print("[-] 必须输入目标主机。", file=sys.stderr)
        return 1
    port = input("WinRM 端口 [5985]: ").strip()
    args.port = int(port) if port.isdigit() else 5985
    args.user = input("用户名 (域\\用户 或 本地用户): ").strip()
    if not args.user:
        print("[-] 必须输入用户名。", file=sys.stderr)
        return 1
    args.password = getpass.getpass("密码: ")
    args.ssl = input("使用 SSL (HTTPS)? [y/N]: ").strip().lower() == "y"
    if args.ssl and args.port == 5985:
        args.port = 5986
    geo = input("启用 IP 地理定位 (需要 GeoLite2-City.mmdb)? [y/N]: ").strip().lower()
    if geo == "y":
        path = input("GeoIP 数据库路径 [GeoLite2-City.mmdb]: ").strip() or "GeoLite2-City.mmdb"
        args.geoip = path
    if not args.logs:
        keep = input("仅采集核心日志（安全/系统/应用/PowerShell/RDP）? [Y/n]: ").strip().lower()
        if keep in {"", "y", "yes"}:
            args.logs = "security,system,application,powershell,rdp_lsm,rdp_rcm"
    default_out = _default_output(args.host, args.format)
    out = input(f"报告文件名 [{default_out}]: ").strip()
    args.out = out or default_out
    return _run_remote(args)


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
def _parse_logs(value: Optional[str]) -> list[str]:
    if not value:
        return list(knowledge.CHANNELS)
    logs = []
    for item in value.split(","):
        key = item.strip()
        if not key:
            continue
        if key not in knowledge.CHANNELS:
            print(f"[!] 忽略未知日志：{key}", file=sys.stderr)
            continue
        logs.append(key)
    return logs or list(knowledge.CHANNELS)


def _resolve_password(args) -> Optional[str]:
    if args.password:
        return args.password
    env_password = os.environ.get("WLA_PASSWORD")
    if env_password:
        return env_password
    if args.password_file:
        try:
            return decode_text(Path(args.password_file).read_bytes()).strip()
        except OSError as error:
            print(f"[-] 读取密码文件失败：{error}", file=sys.stderr)
            return None
    try:
        return getpass.getpass("密码: ")
    except (EOFError, KeyboardInterrupt):
        print("\n[-] 已取消。", file=sys.stderr)
        return None


def _default_output(target: str, fmt: str) -> str:
    safe = re.sub(r"[^\w.\-]+", "_", target or "local")
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M")
    extension = "docx" if fmt == "all" else fmt
    return f"windows_security_audit_{safe}_{stamp}.{extension}"


def _export_raw(result, directory: str, target: str, mode: str) -> None:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    for key, text in (result.raw or {}).items():
        if not text:
            continue
        filename = {
            "iis": "iis.log",
            "tomcat": "tomcat.log",
        }.get(key, f"{key}.xml")
        (root / filename).write_text(text, encoding="utf-8")
    if result.posture:
        (root / "posture.json").write_text(
            json.dumps(result.posture, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    manifest = {
        "tool": f"windows_log_audit {__version__}",
        "target": target,
        "mode": mode,
        "exported_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "events": len(result.events),
        "iis_records": len(result.iis_records),
        "collection": result.collection,
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _geo_lookup(args):
    if not args.geoip:
        return None
    try:
        import geoip2.database
    except ImportError:
        print("[!] 未安装 geoip2，跳过 IP 地理定位（pip install geoip2）", file=sys.stderr)
        return None
    if not Path(args.geoip).exists():
        print(f"[!] GeoIP 数据库不存在：{args.geoip}", file=sys.stderr)
        return None
    try:
        reader = geoip2.database.Reader(args.geoip)
    except Exception as error:  # noqa: BLE001
        print(f"[!] 无法加载 GeoIP 数据库：{error}", file=sys.stderr)
        return None

    def lookup(ip: str) -> str:
        try:
            response = reader.city(ip)
        except Exception:  # noqa: BLE001
            return ""
        parts = [response.country.name or "", response.city.name or ""]
        return ", ".join(part for part in parts if part)

    # 进程退出时由 reader 自行回收；显式保留引用避免被 GC
    lookup.reader = reader  # type: ignore[attr-defined]
    return lookup


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
