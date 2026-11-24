#!/usr/bin/env python3
"""Windows 日志审计工具图形界面入口。

也可以使用：python windows_log_audit.py --gui
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wla.gui import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
