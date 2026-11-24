# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 单文件打包配置（完整功能：图表 / Word / WinRM / Tomcat / GeoIP）。

构建：pyinstaller --clean --noconfirm build_exe.spec
产物：dist/WindowsLogAudit.exe
"""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# python-docx 的默认模板、matplotlib 的字体/样式数据必须随包携带
datas = (
    collect_data_files("docx")
    + collect_data_files("matplotlib")
    + [("assets/app.ico", "assets")]
)

hiddenimports = (
    collect_submodules("winrm")
    + collect_submodules("docx")
    + collect_submodules("geoip2")
    + [
        "matplotlib.backends.backend_agg",
        "matplotlib.backends.backend_tkagg",
        "tkinter",
        "tkinter.ttk",
        "tkinter.scrolledtext",
        "tkinter.filedialog",
        "tkinter.messagebox",
        "tkinter.simpledialog",
        "wla.gui",
    ]
)

# 仅排除与功能无关的 GUI/科学计算/开发依赖，避免拖入 Qt、IPython 等体积大户
excludes = [
    "PyQt5",
    "PyQt6",
    "PySide2",
    "PySide6",
    "IPython",
    "jupyter",
    "notebook",
    "pytest",
    "ruff",
    "pandas",
    "scipy",
    "tkinter.test",
    "test",
]

a = Analysis(
    ["windows_log_audit.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WindowsLogAudit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/app.ico",
)
