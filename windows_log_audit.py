#!/usr/bin/env python3
"""
Windows 主机日志深度安全审计工具。

相对 1.x 版本的主要变化：
  * 修复 WinRM 端口/SSL 被忽略、RDP 事件解析（UserData）、IIS 方法名不一致、
    时间戳解析、IIS 字段索引等缺陷；
  * 支持远程（WinRM）、本机、离线导出文件三种采集方式；
  * 覆盖登录/账户/持久化/执行/凭据/防御规避/Web/Tomcat 等 100+ 事件与行为规则，
    并给出 ATT&CK 映射、证据、处置建议；
  * 输出 Word / Markdown / JSON / HTML 报告，附时间线、IOC 与风险评分；
  * 提供 Tkinter 图形界面与内置演示数据。

用法示例：
    python windows_log_audit.py --host 10.0.0.5 -u Administrator --ssl
    python windows_log_audit.py --local --out audit.docx
    python windows_log_audit.py --offline .\\exported_logs --format all
    python windows_log_audit.py --demo
    python windows_log_audit.py --gui

打包后的 exe 不带参数双击时直接打开图形界面。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wla.cli import main  # noqa: E402


def _hide_console() -> None:
    try:
        import ctypes

        handle = ctypes.windll.kernel32.GetConsoleWindow()
        if handle:
            ctypes.windll.user32.ShowWindow(handle, 0)
    except Exception:  # noqa: BLE001
        pass


def _run() -> int:
    # 单文件 exe 双击（无参数）或 --gui 时直接进入图形界面
    if getattr(sys, "frozen", False) and sys.argv[1:] in ([], ["--gui"]):
        _hide_console()
        try:
            from wla.gui import main as gui_main

            return gui_main()
        except Exception as error:  # noqa: BLE001
            try:
                import ctypes

                ctypes.windll.user32.MessageBoxW(0, str(error), "图形界面启动失败", 0x10)
            except Exception:  # noqa: BLE001
                pass
            return 1
    return main()


if __name__ == "__main__":
    try:
        sys.exit(_run())
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        sys.exit(130)
