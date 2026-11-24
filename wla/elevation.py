"""Windows 管理员权限检测与自提升。"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path


def is_windows() -> bool:
    return sys.platform == "win32"


def is_admin() -> bool:
    """当前进程是否拥有完整管理员令牌（而非仅管理员账户的过滤令牌）。"""
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def relaunch_as_admin(extra_args: list[str] | None = None) -> bool:
    """以管理员身份重启当前程序，成功发起 UAC 请求返回 True。

    - 打包后的 exe：直接重启 exe，保留原命令行参数；
    - 源码运行：重启 python.exe 并附带原脚本与参数。
    """
    if not is_windows():
        return False
    args = list(sys.argv[1:]) if extra_args is None else list(extra_args)
    if getattr(sys, "frozen", False):
        executable = sys.executable
    else:
        script = Path(sys.argv[0])
        if not script.exists():
            return False
        executable = sys.executable
        args = [str(script.resolve())] + args

    params = subprocess.list2cmdline(args)
    try:
        shell32 = ctypes.windll.shell32
        shell32.ShellExecuteW.restype = ctypes.c_void_p
        result = shell32.ShellExecuteW(
            None, "runas", executable, params, os.getcwd(), 1
        )
    except Exception:  # noqa: BLE001
        return False
    return int(result or 0) > 32
